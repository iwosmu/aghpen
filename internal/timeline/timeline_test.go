package timeline

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)

func day(n int) time.Time { return t0.Add(time.Duration(n) * 24 * time.Hour) }

func TestHostIntervals(t *testing.T) {
	obs := []hostObs{
		{RunID: 1, At: day(0), Up: true},
		{RunID: 2, At: day(1), Up: true},
		{RunID: 3, At: day(2), Up: false, Status: "unstable"},
		{RunID: 3, At: day(2).Add(time.Minute), Up: true}, // resumed chunk of the same run answered
		{RunID: 4, At: day(3), Up: false, Status: "unstable"},
		{RunID: 5, At: day(4), Up: false, Status: "down"},
		{RunID: 6, At: day(5), Up: false, Status: "down"},
		{RunID: 7, At: day(6), Up: true},
	}
	got := hostIntervals(obs)
	want := []struct {
		state, status string
		from, to      int64
		n             int
		ongoing       bool
	}{
		{"up", "up", 1, 3, 3, false},
		{"missing", "unstable", 4, 4, 1, false},
		{"down", "down", 5, 6, 2, false},
		{"up", "up", 7, 7, 1, true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d intervals: %+v", len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if g.State != w.state || g.Status != w.status || g.FromRun != w.from || g.ToRun != w.to || g.Observations != w.n || g.Ongoing != w.ongoing {
			t.Errorf("interval %d = %+v, want %+v", i, g, w)
		}
	}
	// An interval lasts until the first observation of the next one.
	if !got[0].To.Equal(day(3)) || !got[1].To.Equal(day(4)) {
		t.Errorf("interval ends: %v %v", got[0].To, got[1].To)
	}
	if !got[3].To.Equal(day(6)) {
		t.Errorf("last interval ends at its last observation, got %v", got[3].To)
	}
}

func TestServiceLane(t *testing.T) {
	host := []hostObs{
		{RunID: 1, At: day(0), Up: true},
		{RunID: 2, At: day(1), Up: true},
		{RunID: 3, At: day(2), Up: false, Status: "unstable"}, // silent: service unknown
		{RunID: 4, At: day(3), Up: true},                      // answered with the service, new version
		{RunID: 5, At: day(4), Up: true},                      // answered without the service: gone
		{RunID: 6, At: day(5), Up: false, Status: "unstable"}, // silent while gone: stays gone
		{RunID: 7, At: day(6), Up: true},                      // back
	}
	obs := []svcObs{
		{RunID: 1, At: day(0), Product: "nginx", Version: "1.24.0"},
		{RunID: 2, At: day(1), Product: "nginx", Version: "1.24.0"},
		{RunID: 4, At: day(3), Product: "nginx", Version: "1.26.1"},
		{RunID: 7, At: day(6), Product: "nginx", Version: "1.26.1"},
	}
	iv, marks := serviceLane(host, obs)
	type w struct {
		state    string
		from, to int64
		ongoing  bool
	}
	want := []w{{"open", 1, 2, false}, {"unknown", 3, 3, false}, {"open", 4, 4, false}, {"open", 7, 7, true}}
	if len(iv) != len(want) {
		t.Fatalf("got %+v", iv)
	}
	for i := range want {
		if iv[i].State != want[i].state || iv[i].FromRun != want[i].from || iv[i].ToRun != want[i].to || iv[i].Ongoing != want[i].ongoing {
			t.Errorf("interval %d = %+v, want %+v", i, iv[i], want[i])
		}
	}
	if !iv[2].To.Equal(day(4)) {
		t.Errorf("open interval must end at the run that did not see the service, got %v", iv[2].To)
	}
	if len(marks) != 1 || marks[0].Before != "nginx 1.24.0" || marks[0].After != "nginx 1.26.1" || marks[0].RunID != 4 {
		t.Errorf("marks = %+v", marks)
	}
}

func TestServiceLaneStartsAtFirstObservation(t *testing.T) {
	host := []hostObs{{RunID: 1, At: day(0), Up: false}, {RunID: 2, At: day(1), Up: true}, {RunID: 3, At: day(2), Up: true}}
	iv, _ := serviceLane(host, []svcObs{{RunID: 3, At: day(2)}})
	if len(iv) != 1 || iv[0].FromRun != 3 || !iv[0].Ongoing {
		t.Fatalf("got %+v", iv)
	}
}

func TestFieldHistories(t *testing.T) {
	mk := func(run int64, title, version, headers string) fieldObs {
		return fieldObs{RunID: run, At: day(int(run)), Values: map[string]string{"title": title, "version": version, "headers": headers, "name": "http"}}
	}
	obs := []fieldObs{mk(1, "Login", "nginx 1.24", "server"), mk(2, "Login", "nginx 1.24", "server"), mk(3, "Panel", "nginx 1.24", "server, x-frame-options"),
		mk(4, "Login", "nginx 1.24", "server, x-frame-options")}
	changed, unchanged := fieldHistories(obs)
	if len(changed) != 2 || changed[0].Field != "title" || changed[1].Field != "headers" {
		t.Fatalf("changed = %+v", changed)
	}
	titles := changed[0].Values
	if len(titles) != 3 || titles[0].Value != "Login" || titles[0].Observations != 2 || titles[0].ToRun != 2 || titles[1].Value != "Panel" || titles[2].FromRun != 4 {
		t.Errorf("title history = %+v", titles)
	}
	if unchanged["version"] != "nginx 1.24" || unchanged["name"] != "http" {
		t.Errorf("unchanged = %v", unchanged)
	}
}

func TestHeaderSetIgnoresVolatileHeaders(t *testing.T) {
	a := headerSet([]string{"Date", "Server", "Content-Length", "X-Frame-Options", "ETag"})
	b := headerSet([]string{"X-Frame-Options", "Server", "Transfer-Encoding"})
	if a != b || a != "server, x-frame-options" {
		t.Errorf("a=%q b=%q", a, b)
	}
}

func TestCertText(t *testing.T) {
	if got := certText("abcdef0123456789abcdef", "2027-01-31T12:00:00Z"); got != "sha256:abcdef0123456789 do 2027-01-31" {
		t.Errorf("got %q", got)
	}
	if certText("", "") != "" {
		t.Error("no certificate must give an empty value")
	}
}

func TestScrubCounts(t *testing.T) {
	// Runs 0..3. Host 1: up, up, silent (unstable), up. Host 2: new in run 1, down in runs 2 and 3.
	hosts := []hostRunRow{
		{HostID: 1, Run: 0, Up: true}, {HostID: 1, Run: 1, Up: true}, {HostID: 1, Run: 2, Status: "unstable"}, {HostID: 1, Run: 3, Up: true},
		{HostID: 2, Run: 1, Up: true}, {HostID: 2, Run: 2, Status: "down"}, {HostID: 2, Run: 3, Status: "down"},
	}
	// Service 10 on host 1: runs 0, 1, 3 (unknown in 2). Service 11 on host 1: run 0 only (gone in run 1).
	// Service 20 on host 2: run 1 (unknown while the host is down).
	svcs := []svcRunRow{
		{ServiceID: 10, HostID: 1, Run: 0}, {ServiceID: 10, HostID: 1, Run: 1}, {ServiceID: 10, HostID: 1, Run: 3},
		{ServiceID: 11, HostID: 1, Run: 0},
		{ServiceID: 20, HostID: 2, Run: 1},
	}
	up, missing, down, open, unknown := scrubCounts(4, hosts, svcs)
	check := func(name string, got, want []int) {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("up", up, []int{1, 2, 0, 1})
	check("missing", missing, []int{0, 0, 1, 0})
	check("down", down, []int{0, 0, 1, 1})
	check("open", open, []int{2, 2, 0, 1})
	check("unknown", unknown, []int{0, 0, 2, 1})
}

func TestFindingsOpen(t *testing.T) {
	runs := []int64{1, 2, 3, 4}
	first := map[int64]int{1: 5, 3: 2}
	resolvedLast := map[int64]int{1: 1, 3: 1} // resolved after last seen in run 1, and after run 3
	got := findingsOpen(runs, first, resolvedLast)
	if !reflect.DeepEqual(got, []int{5, 4, 6, 5}) {
		t.Errorf("got %v", got)
	}
}

func TestDiffSentencesPolishPlural(t *testing.T) {
	s := diffSentences(AtDiff{ServicesGoneSince: 12, ServicesNewSince: 3, HostsDownSince: 1, HostsNewSince: 22})
	joined := strings.Join(s, " | ")
	for _, want := range []string{"12 usług, które wtedy istniały, dziś nie odpowiada.", "3 usługi są dziś otwarte, a wtedy ich nie było.",
		"1 host odpowiadał wtedy, a dziś nie jest aktywny.", "22 hosty pojawiły się później."} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	if got := diffSentences(AtDiff{}); len(got) != 1 || !strings.Contains(got[0], "nie zmienił") {
		t.Errorf("empty diff: %v", got)
	}
	if plural(1, "a", "b", "c") != "a" || plural(3, "a", "b", "c") != "b" || plural(13, "a", "b", "c") != "c" || plural(24, "a", "b", "c") != "b" || plural(25, "a", "b", "c") != "c" {
		t.Error("plural forms")
	}
}

func TestValidCIDR(t *testing.T) {
	if c, ok := validCIDR("10.66.1.7"); !ok || c != "10.66.1.7/32" {
		t.Errorf("got %q %v", c, ok)
	}
	if c, ok := validCIDR("10.66.1.7/24"); !ok || c != "10.66.1.0/24" {
		t.Errorf("got %q %v", c, ok)
	}
	if _, ok := validCIDR("x; DROP"); ok {
		t.Error("garbage accepted")
	}
}
