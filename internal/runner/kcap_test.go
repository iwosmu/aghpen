package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// fakeCap plays the kernel packet cap (internal/kcap).
type fakeCap struct {
	mu      sync.Mutex
	ready   error
	dropped int64
	synced  []int
}

func (f *fakeCap) Sync(_ context.Context, pps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced = append(f.synced, pps)
}

func (f *fakeCap) Ready() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ready
}

func (f *fakeCap) Dropped(context.Context) (int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped, true
}

func (f *fakeCap) set(ready error, dropped int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ready, f.dropped = ready, dropped
}

// A required cap that is not installed refuses the run; an installed one
// follows the policy cap, and the packets the kernel dropped during the run
// become one note of the run.
func TestKernelCapRefusesAndNotes(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	kc := &fakeCap{ready: errors.New("CZUJKA_KERNEL_CAP=require, but the kernel packet cap is not installed: nft not found")}
	e.m.opt.KernelCap = kc
	if _, err := e.m.Start(ctx, e.p.ID, nil, "manual"); !errors.Is(err, ErrKernelCap) || !strings.Contains(err.Error(), "nft not found") {
		t.Fatalf("start without the required cap: %v", err)
	}
	policy, err := e.st.GetSafetyPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kc.set(nil, 100)
	e.eng.blockAt = 1
	run, err := e.m.Start(ctx, e.p.ID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	<-e.eng.blocked
	kc.set(nil, 140) // a freeze: the kernel drops 40 packets during the run
	close(e.eng.release)
	done := waitStatus(t, e.st, run.ID, model.RunCompleted)
	if len(done.Stats.Notes) != 1 || done.Stats.Notes[0] != "jądro odrzuciło 40 pakietów ponad limit" {
		t.Fatalf("notes: %q", done.Stats.Notes)
	}
	kc.mu.Lock()
	synced := append([]int{}, kc.synced...)
	kc.mu.Unlock()
	if len(synced) < 2 || synced[len(synced)-1] != policy.MaxPPS {
		t.Fatalf("the cap must follow the policy cap %d: %v", policy.MaxPPS, synced)
	}

	// No drops, no note.
	e.eng.mu.Lock()
	e.eng.blockAt = -1
	e.eng.mu.Unlock()
	run2, err := e.m.Start(ctx, e.p.ID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if got := waitStatus(t, e.st, run2.ID, model.RunCompleted); len(got.Stats.Notes) != 0 {
		t.Fatalf("notes without drops: %q", got.Stats.Notes)
	}
}
