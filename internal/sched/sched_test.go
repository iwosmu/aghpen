package sched

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func waw(t *testing.T) *time.Location {
	t.Helper()
	loc, err := Location("")
	if err != nil {
		t.Skip("no timezone database:", err)
	}
	if loc.String() != "Europe/Warsaw" {
		t.Fatalf("default timezone = %s", loc)
	}
	return loc
}

func at(loc *time.Location, s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
	if err != nil {
		panic(err)
	}
	return t
}

func TestInWindowSimpleAndMidnight(t *testing.T) {
	loc := waw(t)
	day := []model.Window{{Start: "08:00", End: "16:00"}}
	if !InWindow(at(loc, "2026-11-23 08:00"), day, loc) || !InWindow(at(loc, "2026-11-23 15:59"), day, loc) {
		t.Error("inside the day window")
	}
	if InWindow(at(loc, "2026-11-23 16:00"), day, loc) || InWindow(at(loc, "2026-11-23 07:59"), day, loc) {
		t.Error("the end is exclusive, the start inclusive")
	}
	if !InWindow(time.Now(), nil, loc) {
		t.Error("no windows means any time")
	}

	// 22:00–06:00 that starts on Friday (5) only. 2026-11-20 is a Friday.
	night := []model.Window{{Days: []int{5}, Start: "22:00", End: "06:00"}}
	for s, want := range map[string]bool{
		"2026-11-20 21:59": false,
		"2026-11-20 22:00": true,
		"2026-11-20 23:59": true,
		"2026-11-21 00:00": true, // Saturday morning belongs to Friday's window
		"2026-11-21 05:59": true,
		"2026-11-21 06:00": false,
		"2026-11-21 22:30": false, // Saturday evening: no window starts on Saturday
		"2026-11-22 03:00": false,
		"2026-11-20 03:00": false, // Friday morning would belong to Thursday's window
	} {
		if got := InWindow(at(loc, s), night, loc); got != want {
			t.Errorf("InWindow(%s) = %v, want %v", s, got, want)
		}
	}
	// the same instant given in UTC
	if !InWindow(at(loc, "2026-11-21 01:00").UTC(), night, loc) {
		t.Error("UTC input must be converted to the schedule timezone")
	}
	// Start == End is a full day
	full := []model.Window{{Days: []int{1}, Start: "00:00", End: "00:00"}}
	if !InWindow(at(loc, "2026-11-23 13:00"), full, loc) || InWindow(at(loc, "2026-11-24 00:00"), full, loc) {
		t.Error("24-hour window on Monday")
	}
	// malformed windows never match
	bad := []model.Window{{Start: "25:00", End: "06:00"}}
	if InWindow(at(loc, "2026-11-23 03:00"), bad, loc) || ValidateWindows(bad) == nil {
		t.Error("a malformed window must be rejected")
	}
	if ValidateWindows([]model.Window{{Days: []int{7}, Start: "01:00", End: "02:00"}}) == nil {
		t.Error("day 7 is invalid")
	}
	if err := ValidateWindows(night); err != nil {
		t.Error(err)
	}
}

func TestWindowEndAndNextStart(t *testing.T) {
	loc := waw(t)
	night := []model.Window{{Days: []int{1, 2, 3, 4, 5}, Start: "22:00", End: "06:00"}}
	end, ok := WindowEnd(at(loc, "2026-11-20 23:30"), night, loc) // Friday night
	if !ok || !end.Equal(at(loc, "2026-11-21 06:00")) {
		t.Errorf("end = %v %v", end, ok)
	}
	end, ok = WindowEnd(at(loc, "2026-11-21 02:00"), night, loc)
	if !ok || !end.Equal(at(loc, "2026-11-21 06:00")) {
		t.Errorf("end after midnight = %v %v", end, ok)
	}
	if _, ok := WindowEnd(at(loc, "2026-11-21 12:00"), night, loc); ok {
		t.Error("outside a window there is no end")
	}
	if _, ok := WindowEnd(time.Now(), nil, loc); ok {
		t.Error("no windows: no limit")
	}
	// Saturday 12:00 → next start is Monday 22:00 (no window starts on Sat or Sun)
	next, ok := NextWindowStart(at(loc, "2026-11-21 12:00"), night, loc)
	if !ok || !next.Equal(at(loc, "2026-11-23 22:00")) {
		t.Errorf("next start = %v", next)
	}
	// inside a window: the next start is the following evening
	next, _ = NextWindowStart(at(loc, "2026-11-23 23:00"), night, loc)
	if !next.Equal(at(loc, "2026-11-24 22:00")) {
		t.Errorf("next start from inside = %v", next)
	}
	if got, _ := NextAllowed(at(loc, "2026-11-23 23:00"), night, loc); !got.Equal(at(loc, "2026-11-23 23:00")) {
		t.Errorf("NextAllowed inside = %v", got)
	}
	if got, _ := NextAllowed(at(loc, "2026-11-23 12:00"), night, loc); !got.Equal(at(loc, "2026-11-23 22:00")) {
		t.Errorf("NextAllowed outside = %v", got)
	}
	// touching windows are one window: 20:00–00:00 and 00:00–04:00
	chain := []model.Window{{Start: "20:00", End: "00:00"}, {Start: "00:00", End: "04:00"}}
	end, _ = WindowEnd(at(loc, "2026-11-23 21:00"), chain, loc)
	if !end.Equal(at(loc, "2026-11-24 04:00")) {
		t.Errorf("chained end = %v", end)
	}
	if _, ok := NextWindowStart(time.Now(), []model.Window{{Start: "x", End: "y"}}, loc); ok {
		t.Error("only malformed windows: no start")
	}
}

func TestWindowsAcrossDaylightSaving(t *testing.T) {
	loc := waw(t)
	w := []model.Window{{Start: "01:00", End: "05:00"}}
	// 2026-03-29: clocks jump 02:00 → 03:00. The window keeps its clock times and lasts 3 hours.
	start := at(loc, "2026-03-29 01:00")
	end, ok := WindowEnd(start, w, loc)
	if !ok || end.Sub(start) != 3*time.Hour || end.In(loc).Hour() != 5 {
		t.Errorf("spring: end %v, length %v", end.In(loc), end.Sub(start))
	}
	if !InWindow(time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC), w, loc) { // 03:30 CEST
		t.Error("03:30 local on the spring day is inside")
	}
	// 2026-10-25: clocks go back 03:00 → 02:00. The window lasts 5 hours.
	start = at(loc, "2026-10-25 01:00")
	end, ok = WindowEnd(start, w, loc)
	if !ok || end.Sub(start) != 5*time.Hour || end.In(loc).Hour() != 5 {
		t.Errorf("autumn: end %v, length %v", end.In(loc), end.Sub(start))
	}
	// both 02:30 instants of the repeated hour are inside
	first := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC)  // 02:30 CEST
	second := time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC) // 02:30 CET
	if !InWindow(first, w, loc) || !InWindow(second, w, loc) {
		t.Error("the repeated hour is inside the window")
	}
	// a night window across the spring change: 22:00 Sat → 06:00 Sun is 7 hours
	night := []model.Window{{Start: "22:00", End: "06:00"}}
	start = at(loc, "2026-03-28 22:00")
	end, _ = WindowEnd(start, night, loc)
	if end.Sub(start) != 7*time.Hour {
		t.Errorf("night window across spring change = %v", end.Sub(start))
	}
	next, _ := NextWindowStart(at(loc, "2026-03-29 12:00"), night, loc)
	if !next.Equal(at(loc, "2026-03-29 22:00")) || next.UTC().Hour() != 20 {
		t.Errorf("next start after the change = %v", next.UTC())
	}
}

func TestCron(t *testing.T) {
	loc := waw(t)
	cases := []struct{ expr, after, want string }{
		{"0 2 * * *", "2026-11-21 12:00", "2026-11-22 02:00"},
		{"0 2 * * *", "2026-11-22 02:00", "2026-11-23 02:00"}, // strictly after
		{"*/15 * * * *", "2026-11-21 12:07", "2026-11-21 12:15"},
		{"30 1 * * 1-5", "2026-11-20 02:00", "2026-11-23 01:30"}, // Friday 02:00 → Monday
		{"0 0 1 * *", "2026-11-21 12:00", "2026-12-01 00:00"},
		{"0 8 * * mon", "2026-11-21 12:00", "2026-11-23 08:00"},
		{"0 8 * * 7", "2026-11-21 12:00", "2026-11-22 08:00"}, // 7 = Sunday
		{"15,45 9-10 * * *", "2026-11-21 09:50", "2026-11-21 10:15"},
		{"0 12 29 feb *", "2026-11-21 12:00", "2028-02-29 12:00"},
		{"0 6 13 * fri", "2026-11-21 12:00", "2026-11-27 06:00"}, // day of month OR weekday
		{"5/20 * * * *", "2026-11-21 12:26", "2026-11-21 12:45"},
	}
	for _, c := range cases {
		cr, err := ParseCron(c.expr)
		if err != nil {
			t.Errorf("%q: %v", c.expr, err)
			continue
		}
		if got := cr.Next(at(loc, c.after), loc); !got.Equal(at(loc, c.want)) {
			t.Errorf("%q after %s = %s, want %s", c.expr, c.after, got.In(loc).Format("2006-01-02 15:04"), c.want)
		}
	}
	// 02:30 does not exist on 2026-03-29: the job runs at 03:30, once
	cr, _ := ParseCron("30 2 * * *")
	got := cr.Next(at(loc, "2026-03-28 12:00"), loc)
	if got.UTC() != time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC) {
		t.Errorf("skipped hour: %v", got.UTC())
	}
	if n := cr.Next(got, loc); !n.Equal(at(loc, "2026-03-30 02:30")) {
		t.Errorf("day after the change: %v", n.In(loc))
	}
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "a * * * *", "5-1 * * * *", "0 0 * * * *"} {
		if _, err := ParseCron(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if c, _ := ParseCron("0 0 31 2 *"); !c.Next(at(loc, "2026-01-01 00:00"), loc).IsZero() {
		t.Error("31 February never fires")
	}
}

func TestNextRunAndNextStart(t *testing.T) {
	loc := waw(t)
	now := at(loc, "2026-11-23 10:00") // Monday
	night := []model.Window{{Start: "22:00", End: "06:00"}}

	iv := model.Schedule{Enabled: true, IntervalMinutes: 90}
	if got, _ := NextRun(iv, time.Time{}, now); !got.Equal(now) {
		t.Errorf("an interval schedule that never ran is due now: %v", got)
	}
	last := at(loc, "2026-11-23 09:00")
	if got, _ := NextRun(iv, last, now); !got.Equal(at(loc, "2026-11-23 10:30")) {
		t.Errorf("interval next = %v", got)
	}
	cr := model.Schedule{Enabled: true, Cron: "0 12 * * *", Windows: night}
	if got, _ := NextRun(cr, time.Time{}, now); !got.Equal(at(loc, "2026-11-23 12:00")) {
		t.Errorf("cron next = %v", got)
	}
	// due at 12:00 but the window opens at 22:00
	if got, _ := NextStart(cr, time.Time{}, now); !got.Equal(at(loc, "2026-11-23 22:00")) {
		t.Errorf("cron start in window = %v", got)
	}
	// overdue interval inside a window: now
	iv.Windows = []model.Window{{Start: "08:00", End: "18:00"}}
	if got, _ := NextStart(iv, at(loc, "2026-11-22 09:00"), now); !got.Equal(now) {
		t.Errorf("overdue start = %v", got)
	}
	if _, err := NextRun(model.Schedule{Enabled: true}, time.Time{}, now); err != ErrNoSchedule {
		t.Errorf("empty schedule: %v", err)
	}
	if _, err := NextRun(model.Schedule{Cron: "bogus"}, time.Time{}, now); err == nil {
		t.Error("bad cron must fail")
	}
	if _, err := NextRun(model.Schedule{IntervalMinutes: 5, Timezone: "Mars/Olympus"}, time.Time{}, now); err == nil {
		t.Error("bad timezone must fail")
	}
	// timezone of the schedule decides the cron time
	utc := model.Schedule{Cron: "0 12 * * *", Timezone: "UTC"}
	if got, _ := NextRun(utc, time.Time{}, now); got.UTC().Hour() != 12 {
		t.Errorf("UTC cron = %v", got.UTC())
	}
}

type fakeBackend struct {
	profiles []model.ScanProfile
	last     map[int64]time.Time
	active   map[int64]bool
	paused   []model.ScanRun
	started  []int64
	resumed  []int64
	ends     map[int64]*time.Time
	startErr error
}

func (f *fakeBackend) ScheduledProfiles(context.Context) ([]model.ScanProfile, error) {
	return f.profiles, nil
}
func (f *fakeBackend) LastRun(_ context.Context, id int64) (time.Time, bool, error) {
	return f.last[id], f.active[id], nil
}
func (f *fakeBackend) StartRun(_ context.Context, id int64, end *time.Time) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.started = append(f.started, id)
	f.ends[id] = end
	return nil
}
func (f *fakeBackend) WindowPausedRuns(context.Context) ([]model.ScanRun, error) {
	return f.paused, nil
}
func (f *fakeBackend) ResumeRun(_ context.Context, id int64, end *time.Time) error {
	f.resumed = append(f.resumed, id)
	f.ends[-id] = end
	return nil
}

func TestSchedulerTick(t *testing.T) {
	loc := waw(t)
	night := []model.Window{{Start: "22:00", End: "06:00"}}
	prof := func(id int64, s model.Schedule) model.ScanProfile {
		s.Enabled = true
		return model.ScanProfile{ID: id, Enabled: true, Schedule: s}
	}
	boot := at(loc, "2026-11-23 09:00")
	clock := boot
	b := &fakeBackend{
		profiles: []model.ScanProfile{
			prof(1, model.Schedule{IntervalMinutes: 60}),                  // no windows: due at once
			prof(2, model.Schedule{IntervalMinutes: 60, Windows: night}),  // due, but must wait for 22:00
			prof(3, model.Schedule{Cron: "0 12 * * *"}),                   // due at 12:00
			prof(4, model.Schedule{IntervalMinutes: 30}),                  // a run is active
			prof(5, model.Schedule{IntervalMinutes: 600, Windows: night}), // has a window-paused run
			{ID: 6, Enabled: false, Schedule: model.Schedule{Enabled: true, IntervalMinutes: 1}},
		},
		last:   map[int64]time.Time{4: boot.Add(-2 * time.Hour), 5: boot.Add(-10 * time.Hour)},
		active: map[int64]bool{4: true},
		ends:   map[int64]*time.Time{},
	}
	p5 := int64(5)
	resumeAt := at(loc, "2026-11-23 22:00")
	b.paused = []model.ScanRun{{ID: 77, ProfileID: &p5, Status: model.RunPaused, PauseReason: model.PauseWindowClosed, ResumeAt: &resumeAt}}

	s := New(b, Options{Now: func() time.Time { return clock }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	d := s.Tick(context.Background(), clock) // 09:00
	if !reflect.DeepEqual(d.Started, []int64{1}) || len(d.Resumed) != 0 || !reflect.DeepEqual(d.Waiting, []int64{2}) {
		t.Fatalf("09:00 decision = %+v", d)
	}
	if b.ends[1] != nil {
		t.Error("no windows: no window end")
	}
	b.last[1] = clock

	clock = at(loc, "2026-11-23 12:00")
	d = s.Tick(context.Background(), clock)
	if !reflect.DeepEqual(d.Started, []int64{1, 3}) { // profile 1 is due again (60 min), cron fires
		t.Fatalf("12:00 decision = %+v", d)
	}
	b.last[1], b.last[3] = clock, clock

	clock = at(loc, "2026-11-23 12:01")
	if d = s.Tick(context.Background(), clock); len(d.Started) != 0 {
		t.Fatalf("12:01: nothing is due, got %+v", d)
	}

	// 22:00: the window opens. Profile 2 starts, run 77 resumes, both with the window end.
	clock = at(loc, "2026-11-23 22:00")
	b.last[1] = clock // keep profile 1 quiet
	d = s.Tick(context.Background(), clock)
	if !reflect.DeepEqual(d.Started, []int64{2}) || !reflect.DeepEqual(d.Resumed, []int64{77}) {
		t.Fatalf("22:00 decision = %+v", d)
	}
	want := at(loc, "2026-11-24 06:00")
	if b.ends[2] == nil || !b.ends[2].Equal(want) || b.ends[-77] == nil || !b.ends[-77].Equal(want) {
		t.Errorf("window ends = %v %v", b.ends[2], b.ends[-77])
	}
	for _, id := range b.started {
		if id == 4 || id == 5 || id == 6 {
			t.Errorf("profile %d must not start (active, paused or disabled)", id)
		}
	}

	// ErrBusy from the backend is not a start
	b2 := &fakeBackend{profiles: []model.ScanProfile{prof(1, model.Schedule{IntervalMinutes: 5})}, last: map[int64]time.Time{}, active: map[int64]bool{}, ends: map[int64]*time.Time{}, startErr: ErrBusy}
	if d := New(b2, Options{Now: func() time.Time { return clock }}).Tick(context.Background(), clock); len(d.Started) != 0 {
		t.Errorf("busy start counted: %+v", d)
	}
}

func TestSchedulerRunStopsOnCancel(t *testing.T) {
	b := &fakeBackend{last: map[int64]time.Time{}, active: map[int64]bool{}, ends: map[int64]*time.Time{}}
	s := New(b, Options{Interval: 5 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}
