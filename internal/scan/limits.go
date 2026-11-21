package scan

import (
	"context"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// Limits are the effective intensity limits of a run: for every value the
// stricter of the profile and the global safety policy.
type Limits struct {
	PPS            int           // probe packets per second, all nmap processes together
	ParallelChunks int           // nmap worker count
	ParallelHosts  int           // hosts in the HTTP stage at one time
	HTTPRPS        float64       // HTTP requests per second, all hosts together
	PerHostRPS     float64       // HTTP requests per second to one host
	PerHostConc    int           // parallel HTTP services on one host
	PerHostDelay   time.Duration // pause between requests to one host
	MaxPaths       int           // extra signature paths per HTTP service
}

// Defaults used when neither the profile nor the policy sets a value.
const (
	defaultPPS            = 300
	defaultParallelChunks = 2
	defaultParallelHosts  = 8
	defaultHTTPRPS        = 10
	defaultPerHostRPS     = 5
	defaultPerHostConc    = 2
)

func minPositive(a, b int) int {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	}
	return b
}

func minPositiveF(a, b float64) float64 {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	}
	return b
}

// EffectiveLimits computes min(profile, policy) for every limit.
func EffectiveLimits(p model.ScanProfile, pol model.SafetyPolicy) Limits {
	l := Limits{
		PPS:            minPositive(p.Rate.MaxPPS, pol.MaxPPS),
		ParallelChunks: p.Rate.MaxParallelChunks,
		ParallelHosts:  p.Rate.MaxParallelHosts,
		HTTPRPS:        minPositiveF(p.Rate.HTTPRPS, pol.MaxHTTPRPS),
		PerHostRPS:     pol.MaxPerHostRPS,
		PerHostConc:    p.Rate.PerHostConcurrency,
		PerHostDelay:   time.Duration(p.Rate.PerHostDelayMs) * time.Millisecond,
		MaxPaths:       pol.MaxPathsPerHost,
	}
	if l.PPS <= 0 {
		l.PPS = defaultPPS
	}
	if l.ParallelChunks <= 0 {
		l.ParallelChunks = defaultParallelChunks
	}
	if l.ParallelChunks > 32 {
		l.ParallelChunks = 32
	}
	if l.ParallelChunks > l.PPS {
		l.ParallelChunks = l.PPS // every nmap process needs at least 1 packet per second
	}
	if l.ParallelHosts <= 0 {
		l.ParallelHosts = defaultParallelHosts
	}
	if l.HTTPRPS <= 0 {
		l.HTTPRPS = defaultHTTPRPS
	}
	if l.PerHostRPS <= 0 {
		l.PerHostRPS = defaultPerHostRPS
	}
	if l.PerHostRPS > l.HTTPRPS {
		l.PerHostRPS = l.HTTPRPS
	}
	if l.PerHostConc <= 0 {
		l.PerHostConc = defaultPerHostConc
	}
	if l.MaxPaths < 0 {
		l.MaxPaths = 0
	}
	return l
}

// httpPacketsPerRequest is the kernel TCP traffic of one HTTP request
// (handshake, request, ACKs, close), with version-detection connects
// included. Measured on the lab /16: 9 238 kernel TCP packets for 1 183
// HTTP requests.
const httpPacketsPerRequest = 8

// HTTPReserve is the part of the packet cap kept for the traffic that does
// not go through nmap's pacing: HTTP fingerprinting and the TCP connects of
// version detection. At most a quarter of the cap.
func (l Limits) HTTPReserve() int {
	r := int(l.HTTPRPS*httpPacketsPerRequest + 0.5)
	return min(r, l.PPS/4)
}

// ProbePPS is the budget of the nmap processes together: the cap minus the
// HTTP reserve. With it, everything the scanner sends stays under the cap
// in every second (measured with e2e/ppsbins; before the reserve the nmap
// packets held 1 000 pps and the kernel's TCP added up to 103 more).
func (l Limits) ProbePPS() int {
	return max(1, l.PPS-l.HTTPReserve())
}

// Budget is the global packet budget of a run. Every nmap process takes a
// share before it starts and passes it to nmap as --max-rate. The shares in
// use never add up to more than the total.
type Budget struct {
	mu     sync.Mutex
	total  int
	inUse  int
	waiter chan struct{}
}

// NewBudget makes a budget of total packets per second.
func NewBudget(total int) *Budget {
	if total < 1 {
		total = 1
	}
	return &Budget{total: total, waiter: make(chan struct{})}
}

// Share is the equal share of one of n parallel processes (at least 1).
func (b *Budget) Share(n int) int {
	if n < 1 {
		n = 1
	}
	s := b.total / n
	if s < 1 {
		s = 1
	}
	return s
}

// Acquire grants min(want, free) packets per second. It waits while nothing is free.
func (b *Budget) Acquire(ctx context.Context, want int) (int, error) {
	if want < 1 {
		want = 1
	}
	for {
		b.mu.Lock()
		free := b.total - b.inUse
		if free >= 1 {
			if want > free {
				want = free
			}
			b.inUse += want
			b.mu.Unlock()
			return want, nil
		}
		ch := b.waiter
		b.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		}
	}
}

// Release gives a share back.
func (b *Budget) Release(n int) {
	b.mu.Lock()
	b.inUse -= n
	if b.inUse < 0 {
		b.inUse = 0
	}
	close(b.waiter)
	b.waiter = make(chan struct{})
	b.mu.Unlock()
}

// InUse returns the packets per second that are handed out now.
func (b *Budget) InUse() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inUse
}
