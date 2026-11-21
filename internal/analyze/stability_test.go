package analyze

import (
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

var warsaw = mustLoc("Europe/Warsaw")

func mustLoc(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

// history builds a profile from scans at a fixed interval. upAt decides if
// the host answers at a given local time.
func history(start time.Time, n int, every time.Duration, upAt func(time.Time) bool) (Profile, time.Time) {
	var p Profile
	t := start
	for i := 0; i < n; i++ {
		p.Add(model.HostObservation{RunID: int64(i + 1), At: t, Up: upAt(t.In(warsaw))}, warsaw)
		t = t.Add(every)
	}
	return p, t
}

func officeHours(t time.Time) bool {
	wd := t.Weekday()
	return wd >= time.Monday && wd <= time.Friday && t.Hour() >= 8 && t.Hour() < 16
}

// missRun adds misses one by one and returns the assessment after each.
func missRun(t *testing.T, name string, p *Profile, next time.Time, every time.Duration, n int) []Assessment {
	t.Helper()
	out := make([]Assessment, 0, n)
	for i := 0; i < n; i++ {
		p.Add(model.HostObservation{At: next, Up: false}, warsaw)
		a := Assess(*p, warsaw)
		out = append(out, a)
		last := a.Steps[len(a.Steps)-1]
		t.Logf("%-34s miss %2d at %s  up_rate=%.2f  p_alive=%.3f  status=%-16s down_after=%d",
			name, i+1, next.In(warsaw).Format("Mon 15:04"), last.UpRate, a.PAlive, a.Status, a.DownAfterMisses)
		next = next.Add(every)
	}
	return out
}

func firstDown(as []Assessment) int {
	for i, a := range as {
		if a.Status == model.HostDown {
			return i + 1
		}
	}
	return 0
}

// The named scenarios of docs/ARCHITECTURE.md §4.3. Run with -v to print the
// p_alive after each miss; the documentation quotes these numbers.
func TestStabilityScenarios(t *testing.T) {
	// Monday 2026-10-26 00:00 Europe/Warsaw (after the DST change, so a
	// fixed interval keeps the same local hours).
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, warsaw)

	t.Run("stable server disappears", func(t *testing.T) {
		p, next := history(start, 56, 6*time.Hour, func(time.Time) bool { return true }) // 14 days, 4 scans a day
		if a := Assess(p, warsaw); a.Status != model.HostUp || a.PAlive != 1 || a.DownAfterMisses != 2 {
			t.Fatalf("before the misses: %+v", a)
		}
		as := missRun(t, "stable server", &p, next, 6*time.Hour, 3)
		if as[0].Status != model.HostUnstable {
			t.Errorf("after 1 miss want unstable, got %s (p=%.3f)", as[0].Status, as[0].PAlive)
		}
		if got := firstDown(as); got != 2 {
			t.Errorf("stable server must be reported after 2 misses, got %d", got)
		}
		if as[0].DownAfterMisses != 1 {
			t.Errorf("after 1 miss one more miss reports it, got %d", as[0].DownAfterMisses)
		}
	})

	t.Run("workstation off every night", func(t *testing.T) {
		// 4 weeks, a scan every 4 hours (02, 06, 10, 14, 18, 22).
		p, next := history(start.Add(2*time.Hour), 4*7*6, 4*time.Hour, officeHours)
		a := Assess(p, warsaw)
		t.Logf("workstation pattern: %q stability=%.2f", a.Pattern, a.Stability)
		if a.Pattern != "zwykle aktywny pn–pt 10–15" {
			t.Errorf("pattern = %q", a.Pattern)
		}
		if a.Status != model.HostExpectedOffline {
			t.Errorf("Sunday 22:00 after a normal weekend: want expected-offline, got %s (p=%.3f)", a.Status, a.PAlive)
		}
		// History ends Sunday 22:00 (a miss). Next scans: Mon 02, 06 (off hours), then Mon 10, 14 (usual hours) ...
		as := missRun(t, "workstation", &p, next, 4*time.Hour, 12)
		// Index 0 = Mon 02:00, 1 = Mon 06:00: night, explained.
		for i := 0; i < 2; i++ {
			if as[i].Status != model.HostExpectedOffline || !as[i].Expected {
				t.Errorf("night miss %d: want expected-offline, got %s", i+1, as[i].Status)
			}
			if as[i].PAlive < 0.6 {
				t.Errorf("night miss %d: p_alive = %.3f, want it to stay high", i+1, as[i].PAlive)
			}
		}
		if drop := as[0].PAlive - as[1].PAlive; drop > 0.01 {
			t.Errorf("one night miss lowered p_alive by %.3f", drop)
		}
		// Index 2 = Mon 10:00: it misses its usual hour.
		if as[2].Status != model.HostUnstable {
			t.Errorf("first miss in usual hours: want unstable, got %s", as[2].Status)
		}
		down := firstDown(as)
		if down == 0 {
			t.Fatalf("workstation that misses its usual hours must be reported")
		}
		// Count misses in usual hours until the report.
		usual := 0
		for _, s := range as[down-1].Steps {
			if !s.Explained {
				usual++
			}
		}
		t.Logf("workstation reported inactive after %d misses, %d of them in usual hours", down, usual)
		if usual < 2 || usual > 3 {
			t.Errorf("want 2-3 misses in usual hours before the report, got %d", usual)
		}
	})

	t.Run("workstation is not reported over a weekend", func(t *testing.T) {
		p, _ := history(start.Add(2*time.Hour), 4*7*6, 4*time.Hour, officeHours)
		// Trim to Friday 14:00 of the last week (the last answer), then miss until Monday 06:00.
		var q Profile
		cut := time.Date(2026, 11, 20, 14, 0, 0, 0, warsaw)
		for _, o := range p.Recent {
			if !o.At.After(cut) {
				q.Add(o, warsaw)
			}
		}
		as := missRun(t, "workstation weekend", &q, cut.Add(4*time.Hour), 4*time.Hour, 16) // Fri 18:00 .. Mon 06:00
		for i, a := range as {
			if a.Status != model.HostExpectedOffline {
				t.Errorf("weekend miss %d: want expected-offline, got %s (p=%.3f)", i+1, a.Status, a.PAlive)
			}
		}
	})

	t.Run("host up half of the time at random", func(t *testing.T) {
		rng := rand.New(rand.NewSource(7))
		p, next := history(start, 120, 6*time.Hour, func(time.Time) bool { return rng.Intn(2) == 0 })
		// Make sure the history ends with an answer.
		p.Add(model.HostObservation{At: next, Up: true}, warsaw)
		a := Assess(p, warsaw)
		t.Logf("random host pattern: %q stability=%.2f down_after=%d", a.Pattern, a.Stability, a.DownAfterMisses)
		if !strings.Contains(a.Pattern, "bez wzorca dobowego") {
			t.Errorf("pattern = %q", a.Pattern)
		}
		as := missRun(t, "random 50% host", &p, next.Add(6*time.Hour), 6*time.Hour, 8)
		down := firstDown(as)
		if down < 4 || down > 6 {
			t.Errorf("random host must tolerate about 5 misses, reported after %d", down)
		}
		for i := 0; i < down-1; i++ {
			if as[i].Status != model.HostUnstable {
				t.Errorf("miss %d: want unstable, got %s", i+1, as[i].Status)
			}
		}
	})

	t.Run("new host seen once", func(t *testing.T) {
		var p Profile
		p.Add(model.HostObservation{At: start.Add(10 * time.Hour), Up: true}, warsaw)
		a := Assess(p, warsaw)
		if a.Status != model.HostUp || a.Pattern != "" {
			t.Fatalf("seen once: %+v", a)
		}
		as := missRun(t, "new host seen once", &p, start.Add(34*time.Hour), 24*time.Hour, 3)
		if as[0].Status != model.HostUnstable {
			t.Errorf("after 1 miss want unstable, got %s", as[0].Status)
		}
		if got := firstDown(as); got < 2 || got > 3 {
			t.Errorf("new host: reported after %d misses, want 2 or 3", got)
		}
		if as[0].Pattern != "" {
			t.Errorf("no pattern with so little data, got %q", as[0].Pattern)
		}
	})

	t.Run("host that comes back", func(t *testing.T) {
		p, next := history(start, 56, 6*time.Hour, func(time.Time) bool { return true })
		as := missRun(t, "host that comes back", &p, next, 6*time.Hour, 3)
		if as[2].Status != model.HostDown {
			t.Fatalf("want down after 3 misses, got %s", as[2].Status)
		}
		if as[2].DownAfterMisses != 0 {
			t.Errorf("down host: DownAfterMisses = %d", as[2].DownAfterMisses)
		}
		p.Add(model.HostObservation{At: next.Add(18 * time.Hour), Up: true}, warsaw)
		a := Assess(p, warsaw)
		t.Logf("host that comes back: status=%s p_alive=%.3f misses=%d stability=%.2f down_after=%d", a.Status, a.PAlive, a.ConsecutiveMisses, a.Stability, a.DownAfterMisses)
		if a.Status != model.HostUp || a.PAlive != 1 || a.ConsecutiveMisses != 0 {
			t.Errorf("after the answer: %+v", a)
		}
	})

	t.Run("never answered", func(t *testing.T) {
		var p Profile
		p.Add(model.HostObservation{At: start, Up: false}, warsaw)
		if a := Assess(p, warsaw); a.Status != model.HostUnknown {
			t.Errorf("want unknown, got %s", a.Status)
		}
		if a := Assess(Profile{}, warsaw); a.Status != model.HostUnknown {
			t.Errorf("empty profile: want unknown, got %s", a.Status)
		}
	})
}

func TestBucketIndexIsTimezoneAware(t *testing.T) {
	// 2026-10-05 is a Monday. 23:30 UTC is Tuesday 01:30 in Warsaw (CEST, UTC+2).
	at := time.Date(2026, 10, 5, 23, 30, 0, 0, time.UTC)
	if got, want := BucketIndex(at, time.UTC), 1*24+23; got != want {
		t.Errorf("UTC bucket = %d, want %d", got, want)
	}
	if got, want := BucketIndex(at, warsaw), 2*24+1; got != want {
		t.Errorf("Warsaw bucket = %d, want %d", got, want)
	}
	// After the DST change (2026-10-25) Warsaw is UTC+1.
	winter := time.Date(2026, 11, 2, 23, 30, 0, 0, time.UTC)
	if got, want := BucketIndex(winter, warsaw), 2*24+0; got != want {
		t.Errorf("Warsaw winter bucket = %d, want %d", got, want)
	}
	var p Profile
	p.Add(model.HostObservation{At: at, Up: true}, warsaw)
	p.Add(model.HostObservation{At: at, Up: false}, warsaw)
	if b := p.Buckets[2*24+1]; b.Up != 1 || b.Down != 1 {
		t.Errorf("bucket = %+v", b)
	}
}

func TestProfileRecentIsSortedAndCapped(t *testing.T) {
	var p Profile
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.Add(model.HostObservation{At: base.Add(2 * time.Hour), Up: true}, time.UTC)
	p.Add(model.HostObservation{At: base, Up: false}, time.UTC) // late arrival of an older run
	if !p.Recent[0].At.Equal(base) {
		t.Errorf("Recent is not sorted: %v", p.Recent)
	}
	for i := 0; i < RecentCap+50; i++ {
		p.Add(model.HostObservation{At: base.Add(time.Duration(i+3) * time.Hour), Up: true}, time.UTC)
	}
	if len(p.Recent) != RecentCap {
		t.Errorf("Recent has %d entries, want %d", len(p.Recent), RecentCap)
	}
}

func TestPattern(t *testing.T) {
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, warsaw)
	mk := func(n int, every time.Duration, f func(time.Time) bool) [168]model.AvailBucket {
		p, _ := history(start, n, every, f)
		return p.Buckets
	}
	rng := rand.New(rand.NewSource(3))
	cases := []struct {
		name string
		b    [168]model.AvailBucket
		want string
	}{
		{"too little data", mk(8, time.Hour, officeHours), ""},
		{"office hours, hourly scans, 3 weeks", mk(3*168, time.Hour, officeHours), "zwykle aktywny pn–pt 08–16"},
		{"always on", mk(100, 6*time.Hour, func(time.Time) bool { return true }), "odpowiada stale (100% skanów)"},
		{"every day 08-16", mk(3*168, time.Hour, func(t time.Time) bool { return t.Hour() >= 8 && t.Hour() < 16 }), "zwykle aktywny codziennie 08–16"},
		{"night host", mk(3*168, time.Hour, func(t time.Time) bool { return t.Hour() >= 22 || t.Hour() < 6 }), "zwykle aktywny codziennie 22–06"},
		{"weekend only", mk(3*168, time.Hour, func(t time.Time) bool { return t.Weekday() == time.Saturday || t.Weekday() == time.Sunday }), "zwykle aktywny sb–nd"},
		{"one week of office hours names hours only", mk(168, time.Hour, func(t time.Time) bool { return t.Hour() >= 8 && t.Hour() < 16 }), "zwykle aktywny w godz. 08–16"},
		{"random half", mk(3*168, time.Hour, func(time.Time) bool { return rng.Intn(2) == 0 }), "odpowiada w ok. 50% skanów, bez wzorca dobowego"},
		{"never up", mk(50, time.Hour, func(time.Time) bool { return false }), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Pattern(c.b); got != c.want {
				t.Errorf("Pattern = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDayAndHourText(t *testing.T) {
	var d [7]bool
	d[1], d[3], d[5] = true, true, true
	if got := dayText(d); got != "pn, śr, pt" {
		t.Errorf("dayText = %q", got)
	}
	var h [24]bool
	h[23], h[0], h[1] = true, true, true
	if got := hourText(h); got != "23–02" {
		t.Errorf("hourText = %q", got)
	}
}

func TestApplyToHostAndAvailabilityProfile(t *testing.T) {
	start := time.Date(2026, 10, 5, 0, 0, 0, 0, warsaw)
	p, next := history(start, 20, 6*time.Hour, func(time.Time) bool { return true })
	p.Add(model.HostObservation{At: next, Up: false}, warsaw)
	a := Assess(p, warsaw)
	var h model.Host
	ApplyToHost(&h, a)
	if h.Status != model.HostUnstable || h.ConsecutiveMisses != 1 || h.PAlive <= 0 || h.PAlive >= 1 {
		t.Errorf("host = %+v", h)
	}
	ap := AvailabilityProfile(7, p, a)
	if ap.HostID != 7 || ap.DownAfterMisses != 1 || len(ap.Recent) != 21 {
		t.Errorf("profile: id=%d down_after=%d recent=%d", ap.HostID, ap.DownAfterMisses, len(ap.Recent))
	}
}

// The tolerance of an irregular host depends on the hours of its misses.
// This test shows the spread over many random histories.
func TestRandomHostToleranceDistribution(t *testing.T) {
	start := time.Date(2026, 10, 26, 0, 0, 0, 0, warsaw)
	hist := map[int]int{}
	const seeds = 300
	var all []int
	for seed := int64(1); seed <= seeds; seed++ {
		rng := rand.New(rand.NewSource(seed))
		p, next := history(start, 120, 6*time.Hour, func(time.Time) bool { return rng.Intn(2) == 0 })
		p.Add(model.HostObservation{At: next, Up: true}, warsaw)
		n := 0
		for i := 1; i <= 20; i++ {
			next = next.Add(6 * time.Hour)
			p.Add(model.HostObservation{At: next, Up: false}, warsaw)
			if Assess(p, warsaw).Status == model.HostDown {
				n = i
				break
			}
		}
		hist[n]++
		all = append(all, n)
	}
	sort.Ints(all)
	median := all[len(all)/2]
	t.Logf("random 50%% host, %d histories: misses until reported inactive -> count: %v; median %d, min %d, max %d", seeds, hist, median, all[0], all[len(all)-1])
	if median < 4 || median > 6 {
		t.Errorf("median tolerance = %d misses, want about 5", median)
	}
	if all[0] < 3 {
		t.Errorf("an irregular host was reported after only %d misses", all[0])
	}
}
