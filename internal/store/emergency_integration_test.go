package store_test

import (
	"context"
	"sync"
	"testing"

	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// M3 of the security review: a PUT of the safety policy that read the policy
// before an emergency stop must not clear the stop.
func TestSafetyPutNeverClearsTheEmergencyStop(t *testing.T) {
	ctx := context.Background()
	st := storetest.New(t)
	for _, seeded := range []bool{false, true} {
		if seeded {
			// A stored policy row (the usual case after the first edit).
			p, _ := st.GetSafetyPolicy(ctx)
			p.MaxPPS = 900
			if _, err := st.PutSafetyPolicy(ctx, p); err != nil {
				t.Fatal(err)
			}
		}
		stale, err := st.GetSafetyPolicy(ctx) // read by PUT /settings/safety: flag off
		if err != nil || stale.EmergencyStop {
			t.Fatalf("start: %+v %v", stale, err)
		}
		if p, err := st.SetEmergencyStop(ctx, true); err != nil || !p.EmergencyStop {
			t.Fatalf("stop: %+v %v", p, err)
		}
		stale.MaxPPS = 700
		got, err := st.PutSafetyPolicy(ctx, stale) // written after the stop with the stale flag
		if err != nil {
			t.Fatal(err)
		}
		if !got.EmergencyStop || got.MaxPPS != 700 {
			t.Fatalf("seeded=%v: a stale policy write cleared the emergency stop (or lost the edit): %+v", seeded, got)
		}
		// A PUT with the flag set does not set it either: only SetEmergencyStop does.
		if p, err := st.SetEmergencyStop(ctx, false); err != nil || p.EmergencyStop {
			t.Fatalf("release: %+v %v", p, err)
		}
		stale.EmergencyStop = true
		if got, _ := st.PutSafetyPolicy(ctx, stale); got.EmergencyStop {
			t.Fatalf("a policy write set the emergency stop: %+v", got)
		}
	}

	// Concurrent: stops and policy writes interleave; every stop survives.
	for i := 0; i < 20; i++ {
		if _, err := st.SetEmergencyStop(ctx, false); err != nil {
			t.Fatal(err)
		}
		stale, _ := st.GetSafetyPolicy(ctx)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = st.SetEmergencyStop(ctx, true) }()
		go func() { defer wg.Done(); _, _ = st.PutSafetyPolicy(ctx, stale) }()
		wg.Wait()
		if p, _ := st.GetSafetyPolicy(ctx); !p.EmergencyStop {
			t.Fatalf("round %d: the emergency stop was lost", i)
		}
	}
}
