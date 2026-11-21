package analyze

import (
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func TestClockFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := ClockFromEnv(env(nil))
	if err != nil || !c.IsDefault() || c.Buckets() != 168 {
		t.Fatalf("default clock = %v, %v", c, err)
	}
	c, err = ClockFromEnv(env(map[string]string{"CZUJKA_AVAIL_BUCKET": "1m", "CZUJKA_AVAIL_PERIOD": "10m"}))
	if err != nil || c.Buckets() != 10 || c.IsDefault() {
		t.Fatalf("lab clock = %v, %v", c, err)
	}
	for _, bad := range []map[string]string{
		{"CZUJKA_AVAIL_BUCKET": "1m", "CZUJKA_AVAIL_PERIOD": "200m"},  // 200 buckets
		{"CZUJKA_AVAIL_BUCKET": "7m", "CZUJKA_AVAIL_PERIOD": "10m"},   // not whole
		{"CZUJKA_AVAIL_BUCKET": "soon", "CZUJKA_AVAIL_PERIOD": "10m"}, // not a duration
		{"CZUJKA_AVAIL_BUCKET": "100ms"},
	} {
		if _, err := ClockFromEnv(env(bad)); err == nil {
			t.Errorf("%v: no error", bad)
		}
	}
}

// A host on a 10-minute cycle (down for the first 4 minutes, like the lab's
// tod-night) scanned once a minute: under the hour-of-week clock every scan
// falls into one or two buckets and the misses are not explained; under a
// 1-minute/10-minute lab clock the model learns the cycle and calls the
// misses expected.
func TestLabClockLearnsAMinuteCycle(t *testing.T) {
	defer func() { clock = DefaultClock }()
	upAt := func(t time.Time) bool { return t.Unix()%600 >= 240 }
	start := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	build := func(n int) Profile {
		var p Profile
		for i := 0; i < n; i++ {
			at := start.Add(time.Duration(i) * time.Minute)
			p.Add(model.HostObservation{RunID: int64(i + 1), At: at, Up: upAt(at)}, time.UTC)
		}
		return p
	}
	// 82 scans: the last one is minute 81, i.e. minute 1 of the cycle (down, after a down minute 0).
	n := 82
	if upAt(start.Add(time.Duration(n-1) * time.Minute)) {
		t.Fatal("test setup: the last scan must be a miss")
	}

	clock = DefaultClock
	if a := Assess(build(n), time.UTC); a.Expected {
		t.Errorf("hour-of-week clock: miss explained (%s), want unexplained", a.Status)
	}

	if err := SetClock(Clock{Width: time.Minute, Period: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	a := Assess(build(n), time.UTC)
	if !a.Expected || a.Status != model.HostExpectedOffline {
		t.Errorf("lab clock: status %s expected=%v p_alive=%.2f steps=%+v, want expected-offline", a.Status, a.Expected, a.PAlive, a.Steps)
	}
	// A miss in a minute where the host always answers is not explained.
	p := build(n - 2) // ends at minute 79 (up)
	p.Add(model.HostObservation{RunID: 999, At: start.Add(80*time.Minute + 30*time.Second), Up: true}, time.UTC)
	p.Add(model.HostObservation{RunID: 1000, At: start.Add(89 * time.Minute), Up: false}, time.UTC) // minute 9: up-minute
	if a := Assess(p, time.UTC); a.Expected {
		t.Errorf("lab clock: miss in an up-minute explained: %+v", a.Steps)
	}
}
