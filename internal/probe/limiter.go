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

// WaitAll blocks until every limiter has a token at the same moment, then
// takes one from each. Nothing is reserved ahead: a token is taken when the
// caller may send, so each limiter sees the real send times and its rate
// holds even when another limiter of the set is the slower one.
// Callers must pass the limiters in the same order everywhere.
func WaitAll(ctx context.Context, ls ...*Limiter) error {
	var act []*Limiter
	for _, l := range ls {
		if l != nil && l.rate > 0 {
			act = append(act, l)
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, l := range act {
			l.mu.Lock()
		}
		now := time.Now()
		var wait time.Duration
		for _, l := range act {
			l.tokens += now.Sub(l.last).Seconds() * l.rate
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
			l.last = now
			if l.tokens < 1 {
				wait = max(wait, time.Duration((1-l.tokens)/l.rate*float64(time.Second))+time.Microsecond)
			}
		}
		if wait == 0 {
			for _, l := range act {
				l.tokens--
			}
		}
		for i := len(act) - 1; i >= 0; i-- {
			act[i].mu.Unlock()
		}
		if wait == 0 {
			return nil
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
}

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
