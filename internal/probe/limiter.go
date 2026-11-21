package probe

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token bucket. Wait blocks until the caller may send. A nil
// Limiter and a Limiter with a rate of 0 or less do not limit.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

// NewLimiter makes a bucket that refills at perSecond and holds at most burst tokens.
func NewLimiter(perSecond float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: perSecond, burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

// Wait takes one token.
func (l *Limiter) Wait(ctx context.Context) error { return l.WaitN(ctx, 1) }

// WaitN takes n tokens. It reserves them at once and then sleeps for the
// debt, so the long-run rate holds even when n is larger than the burst.
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	if l == nil || l.rate <= 0 || n <= 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.last = now
	l.tokens -= float64(n)
	var wait time.Duration
	if l.tokens < 0 {
		wait = time.Duration(-l.tokens / l.rate * float64(time.Second))
	}
	l.mu.Unlock()
	if wait <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		// give the tokens back: nothing was sent
		l.mu.Lock()
		l.tokens += float64(n)
		l.mu.Unlock()
		return ctx.Err()
	}
}
