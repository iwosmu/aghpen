package scan

import (
	"testing"
	"time"
)

// CurrentPPS must show the speed of a stage while it runs, not only after
// it has ended.
func TestCurrentPPSDuringALongStage(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	k := newStatsKeeper(nil, func() time.Time { return now })
	end := k.begin(250)
	now = now.Add(2 * time.Second)
	if s := k.snapshot(); s.CurrentPPS != 250 || s.PacketsSent != 0 {
		t.Errorf("after 2 s of a running stage: %+v", s)
	}
	end2 := k.begin(250) // a second worker starts
	now = now.Add(10 * time.Second)
	if s := k.snapshot(); s.CurrentPPS != 500 {
		t.Errorf("two running stages: current = %v, want 500", s.CurrentPPS)
	}
	// the first stage ends: its exact count replaces the estimate
	end()
	k.addStage(2880, true, now.Add(-12*time.Second), now) // 240 per second, measured
	if s := k.snapshot(); s.CurrentPPS != 490 || s.PacketsSent != 2880 {
		t.Errorf("one ended, one running: %+v", s)
	}
	end2()
	now = now.Add(6 * time.Second)
	if s := k.snapshot(); s.CurrentPPS != 0 {
		t.Errorf("idle for longer than the window: current = %v", s.CurrentPPS)
	}
}
