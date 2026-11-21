package runner

import (
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestEstimateWindowOutsideAndInside(t *testing.T) {
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	open := now.Add(12 * time.Hour) // 22:00
	close := open.Add(8 * time.Hour)
	// The shape of enginewire.Window: outside a window the end is "now" and next is the next start.
	win := func(_ model.ScanProfile, t time.Time) (*time.Time, *time.Time) {
		if !t.Before(open) && t.Before(close) {
			e := close
			n := open.Add(24 * time.Hour)
			return &e, &n
		}
		e, n := t, open
		return &e, &n
	}
	m := &Manager{opt: Options{Window: win}}
	p := model.ScanProfile{Schedule: model.Schedule{Windows: []model.Window{{Start: "22:00", End: "06:00"}}}}

	est := model.ScanEstimate{EstDurationSec: 3600, WindowSec: 0, FitsWindow: false}
	m.estimateWindow(&est, p, now)
	if est.InWindow || est.NextWindowAt == nil || !est.NextWindowAt.Equal(open) || est.WindowSec != 8*3600 || !est.FitsWindow {
		t.Fatalf("outside the window: %+v", est)
	}
	long := model.ScanEstimate{EstDurationSec: 9 * 3600}
	m.estimateWindow(&long, p, now)
	if long.FitsWindow {
		t.Fatalf("a 9 h scan does not fit an 8 h window: %+v", long)
	}
	in := model.ScanEstimate{EstDurationSec: 60, WindowSec: 100, FitsWindow: true}
	m.estimateWindow(&in, p, open.Add(time.Hour))
	if !in.InWindow || in.NextWindowAt != nil || in.WindowSec != 100 {
		t.Fatalf("inside the window the engine numbers stay: %+v", in)
	}
	none := model.ScanEstimate{FitsWindow: true}
	m.estimateWindow(&none, model.ScanProfile{}, now)
	if !none.InWindow || !none.FitsWindow {
		t.Fatalf("no windows: %+v", none)
	}
}
