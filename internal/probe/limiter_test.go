package probe

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"
)

// Two hosts share one global limiter. Each limiter must hold its own rate,
// measured on the moments the callers were let through.
func TestWaitAllHoldsEveryLimit(t *testing.T) {
	global := NewLimiter(40, 1)
	hosts := []*Limiter{NewLimiter(30, 1), NewLimiter(30, 1)}
	var mu sync.Mutex
	stamps := map[int][]time.Time{}
	var all []time.Time
	var wg sync.WaitGroup
	for h := range hosts {
		for w := 0; w < 3; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 8; i++ {
					if err := WaitAll(context.Background(), hosts[h], global); err != nil {
						t.Error(err)
						return
					}
					now := time.Now()
					mu.Lock()
					stamps[h] = append(stamps[h], now)
					all = append(all, now)
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	gap := func(ts []time.Time) time.Duration {
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		best := time.Hour
		for i := 1; i < len(ts); i++ {
			best = min(best, ts[i].Sub(ts[i-1]))
		}
		return best
	}
	// 2 ms of slack for the scheduler
	if g := gap(all); g < time.Second/40-2*time.Millisecond {
		t.Errorf("global limiter: smallest gap %s, want about %s", g, time.Second/40)
	}
	for h, ts := range stamps {
		if g := gap(ts); g < time.Second/30-2*time.Millisecond {
			t.Errorf("host %d limiter: smallest gap %s, want about %s", h, g, time.Second/30)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if WaitAll(ctx, global) == nil {
		t.Error("a cancelled context must end the wait")
	}
	if WaitAll(context.Background(), nil, NewLimiter(0, 1)) != nil {
		t.Error("nil and unlimited limiters must not block")
	}
}
