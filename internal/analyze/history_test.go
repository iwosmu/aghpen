package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func withMs(s model.ServiceResult, ms int) model.ServiceResult {
	h := *s.HTTP
	h.ResponseMs = ms
	s.HTTP = &h
	return s
}

// The quickstart of the organisers: 8787 disappears in run 2 and comes back
// in run 3. Run 3 must say "returned", never "new".
func TestDiffServiceReturnedNotNew(t *testing.T) {
	gitea := httpSvc(3001, "Gitea", 200)
	flask := httpSvc(8787, "Hello", 200)
	prev := snap(2, host("192.168.65.254", model.HostUp, gitea))
	h := host("192.168.65.254", model.HostUp, gitea, flask)
	lastOpen := snap(1).At
	h.History = map[string]ServiceHistory{"8787/tcp": {LastOpenRun: 1, LastOpenAt: lastOpen, RunsAway: 1, Response: []int{12}}}
	cur := snap(3, h)
	cs, sum := Diff(&prev, cur, DiffOptions{})
	if find(cs, model.ChangeServiceNew) != nil {
		t.Fatalf("a service seen before must not be new: %v", kinds(cs))
	}
	c := find(cs, model.ChangeServiceReturned)
	if c == nil {
		t.Fatalf("no service_returned: %v", kinds(cs))
	}
	if c.Port != 8787 || c.After != "open" || sum.ServicesReturned != 1 || sum.ServicesNew != 0 || sum.ByKind["service_returned"] != 1 {
		t.Errorf("change %+v summary %+v", c, sum)
	}
	b, _ := c.Before.(map[string]any)
	if b["runs_away"] != 1 || b["away_seconds"] != int64(2*time.Hour/time.Second) || b["last_open_run_id"] != int64(1) || b["state"] != "gone" {
		t.Errorf("before = %v", c.Before)
	}
	if !strings.Contains(c.Summary, "wróciła po 2 h") || !strings.Contains(c.Summary, "1 skanie") {
		t.Errorf("summary %q", c.Summary)
	}

	// Without history the same service is new.
	h.History = nil
	cs, _ = Diff(&prev, snap(3, h), DiffOptions{})
	if find(cs, model.ChangeServiceNew) == nil || find(cs, model.ChangeServiceReturned) != nil {
		t.Errorf("no history: %v", kinds(cs))
	}
}

func TestResponseSeriesRule(t *testing.T) {
	cases := []struct {
		vals []int
		slow []bool
	}{
		{[]int{100, 650}, []bool{false, true}},                        // one observation is a baseline; 6.5x and +550 ms
		{[]int{100, 350}, []bool{false, false}},                       // +250 ms: under the 300 ms floor
		{[]int{400, 750}, []bool{false, false}},                       // +350 ms but under 2x
		{[]int{400, 800}, []bool{false, true}},                        // 2x and +400 ms
		{[]int{100, 700, 700, 110}, []bool{false, true, true, false}}, // slow points stay out of the baseline
		{[]int{-1, -1}, []bool{false, false}},                         // never answered HTTP: no baseline, never slow
		{[]int{100, -1}, []bool{false, true}},                         // port open, HTTP stopped answering
		{[]int{5, 0, 3, 900}, []bool{false, false, false, true}},
	}
	for _, c := range cases {
		pts := ResponseSeries(c.vals)
		for i := range pts {
			if pts[i].Slow != c.slow[i] {
				t.Errorf("%v: point %d slow=%v want %v (baseline %d)", c.vals, i, pts[i].Slow, c.slow[i], pts[i].Baseline)
			}
		}
	}
	if b := ResponseSeries([]int{100, 110, 120, 130, 140, 150, 50})[6].Baseline; b != 130 {
		t.Errorf("baseline = median of the last 5 = %d, want 130", b)
	}
}

// The Toxiproxy case: run 1 without latency, run 2 with 500 ms latency, run
// 3 without again.
func TestDiffResponseSlowerAndRecovered(t *testing.T) {
	wp := httpSvc(8085, "WordPress", 200)
	run := func(id int64, ms int, hist []int) ([]model.Change, model.RunDiffSummary) {
		prev := snap(id-1, host("192.168.65.254", model.HostUp, withMs(wp, hist[len(hist)-1])))
		h := host("192.168.65.254", model.HostUp, withMs(wp, ms))
		h.History = map[string]ServiceHistory{"8085/tcp": {LastOpenRun: id - 1, Response: hist}}
		return Diff(&prev, snap(id, h), DiffOptions{})
	}
	cs, sum := run(2, 640, []int{90})
	c := find(cs, model.ChangeResponseSlower)
	if c == nil || sum.ResponsesSlower != 1 {
		t.Fatalf("no response_slower: %v %+v", kinds(cs), sum)
	}
	if c.Field != "http.response_ms" || c.Severity != model.SevLow || !strings.Contains(c.Summary, "640 ms (zwykle 90 ms)") {
		t.Errorf("change %+v", c)
	}
	if a, _ := c.After.(map[string]any); a["ms"] != 640 {
		t.Errorf("after %v", c.After)
	}
	// Still slow: not reported again.
	if cs, _ = run(3, 650, []int{90, 640}); find(cs, model.ChangeResponseSlower) != nil {
		t.Errorf("a service that stays slow is reported again: %v", kinds(cs))
	}
	cs, _ = run(4, 95, []int{90, 640, 650})
	if c := find(cs, model.ChangeResponseRecovered); c == nil || c.Severity != model.SevInfo {
		t.Fatalf("no response_recovered: %v", kinds(cs))
	}
	// Normal jitter: nothing.
	if cs, _ = run(5, 140, []int{90, 95}); len(cs) != 0 {
		t.Errorf("jitter reported: %v", kinds(cs))
	}
	// HTTP stops answering while the port is open: slower with no_answer, never gone.
	prev := snap(5, host("192.168.65.254", model.HostUp, withMs(wp, 90)))
	silent := wp
	silent.HTTP = nil
	h := host("192.168.65.254", model.HostUp, silent)
	h.History = map[string]ServiceHistory{"8085/tcp": {LastOpenRun: 5, Response: []int{90}}}
	cs, _ = Diff(&prev, snap(6, h), DiffOptions{})
	c = find(cs, model.ChangeResponseSlower)
	if c == nil || find(cs, model.ChangeServiceGone) != nil {
		t.Fatalf("timeout: %v", kinds(cs))
	}
	if a, _ := c.After.(map[string]any); a["error"] != "no_answer" || a["ms"] != nil {
		t.Errorf("after %v", c.After)
	}
}
