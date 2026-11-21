package enginewire

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/httpfp"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/sched"
)

func TestWindow(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	all := []int{0, 1, 2, 3, 4, 5, 6}
	p := model.ScanProfile{Schedule: model.Schedule{Timezone: "Europe/Warsaw", Windows: []model.Window{{Days: all, Start: "22:00", End: "06:00"}}}}
	at := func(day, h, m int) time.Time { return time.Date(2026, 11, day, h, m, 0, 0, loc) }

	if end, next := Window(model.ScanProfile{}, at(17, 12, 0)); end != nil || next != nil {
		t.Errorf("no windows: got %v %v, want no limit", end, next)
	}
	// inside the night window, after midnight
	end, next := Window(p, at(17, 1, 30))
	if end == nil || !end.Equal(at(17, 6, 0)) || next == nil || !next.Equal(at(17, 22, 0)) {
		t.Errorf("inside: end %v next %v", end, next)
	}
	// outside: the run may not scan now and waits for 22:00
	now := at(17, 12, 0)
	end, next = Window(p, now)
	if end == nil || !end.Equal(now) || next == nil || !next.Equal(at(17, 22, 0)) {
		t.Errorf("outside: end %v next %v", end, next)
	}
	// a wrong timezone name must not open the window for the whole day
	p.Schedule.Timezone = "Mars/Olympus"
	if end, _ := Window(p, now); end == nil {
		t.Error("a bad timezone removed the window limit")
	}
}

func TestTargetParser(t *testing.T) {
	var tp TargetParser
	valid, invalid := tp.ParseText("10.0.0.0/30\n999.1.1.1\nexample.com\n10.0.1.5-10.0.1.9")
	if len(valid) != 3 || len(invalid) != 1 || invalid[0].Line != 2 || invalid[0].Reason == "" {
		t.Fatalf("valid %+v invalid %+v", valid, invalid)
	}
	if valid[0].Kind != model.TargetCIDR || valid[0].Addresses != 4 || valid[2].Addresses != 5 {
		t.Errorf("targets = %+v", valid)
	}
	if n := tp.Excluded([]model.Target{{Value: "10.9.0.0/24", Enabled: true}, {Value: "10.9.0.0/25", Enabled: true}}, []string{"10.9.0.0/26", "10.9.0.200"}); n != 65 {
		t.Errorf("excluded = %d, want 65 (overlapping targets count once)", n)
	}
	valid, invalid, err := tp.ParseFile("targets.csv", []byte("value,note\n192.0.2.0/29,lab\n999.1.1.1,bad\n"))
	if err != nil || len(valid) != 1 || len(invalid) != 1 {
		t.Errorf("csv: %v %+v %+v", err, valid, invalid)
	}
	if v, inv := tp.ParseText(""); v == nil || inv == nil {
		t.Error("empty input must give empty slices, not nil (JSON arrays)")
	}
}

func TestNewPlugsTheRequestLimiterIntoTheCollector(t *testing.T) {
	c := httpfp.New()
	if New(Deps{Fingerprinter: c}) == nil || c.Wait == nil {
		t.Fatal("the collector did not get the per-request hook")
	}
	called := false
	own := httpfp.New()
	own.Wait = func(context.Context, string) error { called = true; return nil }
	New(Deps{Fingerprinter: own})
	_ = own.Wait(context.Background(), "")
	if !called {
		t.Error("an existing Wait hook must be kept")
	}
	if New(Deps{}) == nil {
		t.Error("the default collector")
	}
}

func TestBusyMapping(t *testing.T) {
	for _, err := range []error{runner.ErrActiveRun, runner.ErrEmergencyStop, runner.ErrBadState} {
		if got := busy(err); !errors.Is(got, sched.ErrBusy) || !errors.Is(got, err) {
			t.Errorf("busy(%v) = %v", err, got)
		}
	}
	other := errors.New("database down")
	if got := busy(other); errors.Is(got, sched.ErrBusy) || !reflect.DeepEqual(got, other) {
		t.Errorf("busy(other) = %v", got)
	}
	if busy(nil) != nil {
		t.Error("nil")
	}
	if !errors.Is(PauseCause(model.PauseManual), context.Canceled) && PauseCause(model.PauseManual) == nil {
		t.Error("pause cause")
	}
}
