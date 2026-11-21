package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// TestTwoPassMissingHost is the jury's case: run 1 sees a host with three
// open services, the container is stopped, run 2 gets no answer. The host
// must be visible after the second pass, with and without the profile rule.
// Run with -v to print the summaries quoted in docs/ALGORYTMY.md.
func TestTwoPassMissingHost(t *testing.T) {
	t1 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(30 * time.Minute)
	svcs := []model.ServiceResult{
		{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH"},
		{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "nginx"},
		{Port: 8080, Proto: "tcp", State: "open", Name: "http", Product: "Jenkins"},
	}
	cases := []struct {
		name        string
		history     int // runs with an answer before the miss (the jury: 1)
		rule        int
		wantKinds   []string
		wantStatus  model.HostStatus
		wantSummary string
		missing     int
		gone        int
		unreachable int
		svcGone     int
	}{
		{"model decides, one earlier run", 1, 0, []string{"host_missing", "service_unreachable", "service_unreachable", "service_unreachable"}, model.HostUnstable,
			"nie odpowiada (niepotwierdzone): w poprzednim przebiegu odpowiadał i miał 3 otwarte usługi: 22/tcp ssh OpenSSH, 80/tcp http nginx, 8080/tcp http Jenkins; model: p_alive 0,", 1, 0, 3, 0},
		{"model decides, long stable history", 40, 0, []string{"host_missing", "service_unreachable", "service_unreachable", "service_unreachable"}, model.HostUnstable,
			"zgłoszenie nieaktywności po kolejnym braku", 1, 0, 3, 0},
		{"rule N=1", 1, 1, []string{"host_gone", "service_gone", "service_gone", "service_gone"}, model.HostDown,
			"brak odpowiedzi w 1 przebiegu z rzędu (reguła profilu: zgłoszenie po 1 braku)", 0, 1, 0, 3},
		{"rule N=2", 1, 2, []string{"host_missing", "service_unreachable", "service_unreachable", "service_unreachable"}, model.HostUnstable,
			"zgłoszenie nieaktywności po kolejnym braku, reguła profilu: 2 braki z rzędu", 1, 0, 3, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p Profile
			at := t1.Add(-time.Duration(c.history-1) * 6 * time.Hour)
			for i := 0; i < c.history; i++ {
				p.Add(model.HostObservation{RunID: int64(i + 1), At: at, Up: true}, time.UTC)
				at = at.Add(6 * time.Hour)
			}
			missRun := int64(c.history + 1)
			p.Add(model.HostObservation{RunID: missRun, At: t2, Up: false}, time.UTC)
			// The engine reported the silent host twice (a chunk scanned
			// again after a resume): it must count once.
			p.Add(model.HostObservation{RunID: missRun, At: t2.Add(time.Minute), Up: false}, time.UTC)
			a := AssessWith(p, time.UTC, AssessOptions{DownAfterMisses: c.rule})
			if a.Status != c.wantStatus || a.ConsecutiveMisses != 1 {
				t.Fatalf("status %s misses %d, want %s 1 (p=%.3f)", a.Status, a.ConsecutiveMisses, c.wantStatus, a.PAlive)
			}
			prev := Snapshot{RunID: missRun - 1, At: t1, Hosts: []HostSnapshot{{HostID: 7, IP: "10.66.3.17", Up: true, Status: model.HostUp, Services: svcs}}}
			cur := HostSnapshot{HostID: 7, IP: "10.66.3.17", Up: false}
			cur.SetAssessment(a, c.history+1)
			cs, sum := Diff(&prev, Snapshot{RunID: missRun, At: t2, Hosts: []HostSnapshot{cur}}, DiffOptions{})
			if got := strings.Join(kinds(cs), ","); got != strings.Join(c.wantKinds, ",") {
				t.Fatalf("kinds = %s, want %v", got, c.wantKinds)
			}
			t.Logf("p_alive=%.3f down_after=%d: %s", a.PAlive, a.DownAfterMisses, cs[0].Summary)
			if !strings.Contains(cs[0].Summary, c.wantSummary) {
				t.Errorf("summary %q, want it to contain %q", cs[0].Summary, c.wantSummary)
			}
			if cs[0].Severity != model.SevMedium {
				t.Errorf("severity %s", cs[0].Severity)
			}
			if sum.HostsMissing != c.missing || sum.HostsGone != c.gone || sum.ServicesUnreachable != c.unreachable || sum.ServicesGone != c.svcGone {
				t.Errorf("summary counters %+v", sum)
			}
		})
	}
}

func TestTwoPassExpectedMissStaysExpected(t *testing.T) {
	// A workstation that is off every night: a night miss after a day
	// answer is explained by the profile and is not host_missing.
	prev := Snapshot{RunID: 1, Hosts: []HostSnapshot{{IP: "10.0.0.9", Up: true, Status: model.HostUp}}}
	cur := Snapshot{RunID: 2, Hosts: []HostSnapshot{{IP: "10.0.0.9", Status: model.HostExpectedOffline, Pattern: "zwykle aktywny pn–pt 08–16"}}}
	cs, sum := Diff(&prev, cur, DiffOptions{})
	if got := strings.Join(kinds(cs), ","); got != "host_gone(expected)" || sum.HostsMissing != 0 {
		t.Fatalf("kinds %s sum %+v", got, sum)
	}
}

func TestRuleSecondMissReportsGone(t *testing.T) {
	var p Profile
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	p.Add(model.HostObservation{RunID: 1, At: t0, Up: true}, time.UTC)
	p.Add(model.HostObservation{RunID: 2, At: t0.Add(time.Hour)}, time.UTC)
	p.Add(model.HostObservation{RunID: 3, At: t0.Add(2 * time.Hour)}, time.UTC)
	if a := AssessWith(p, time.UTC, AssessOptions{DownAfterMisses: 2}); a.Status != model.HostDown {
		t.Fatalf("rule 2 after 2 misses: %s", a.Status)
	}
	if a := AssessWith(p, time.UTC, AssessOptions{DownAfterMisses: 5}); a.Status == model.HostDown || a.DownAfterMisses != 3 {
		t.Fatalf("rule 5 after 2 misses: %s %d", a.Status, a.DownAfterMisses)
	}
}

func TestNormalizeProfileMergesDuplicateRun(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	// What the store holds after a resumed chunk: run 2 twice, once silent
	// and once with an answer, and the histogram counted both.
	p := Profile{Recent: []model.HostObservation{
		{RunID: 1, At: t0, Up: true},
		{RunID: 2, At: t0.Add(time.Hour), Up: false},
		{RunID: 2, At: t0.Add(time.Hour + time.Minute), Up: true},
	}}
	p.Buckets[BucketIndex(t0, time.UTC)].Up++
	p.Buckets[BucketIndex(t0.Add(time.Hour), time.UTC)].Down++
	p.Buckets[BucketIndex(t0.Add(time.Hour), time.UTC)].Up++
	n := NormalizeProfile(p, time.UTC)
	if len(n.Recent) != 2 || !n.Recent[1].Up {
		t.Fatalf("recent %+v", n.Recent)
	}
	total := 0
	for _, b := range n.Buckets {
		total += b.Up + b.Down
	}
	if total != 2 {
		t.Fatalf("histogram holds %d observations, want 2", total)
	}
	if a := Assess(p, time.UTC); a.Status != model.HostUp {
		t.Fatalf("answered in run 2: %s", a.Status)
	}
}

func TestMergeHostResults(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	in := []model.HostResult{
		{IP: "10.0.0.1", Up: false, ObservedAt: t0, Attempts: 3},
		{IP: "10.0.0.2", Up: true, ObservedAt: t0},
		{IP: "10.0.0.1", Up: true, ObservedAt: t0.Add(time.Minute), Attempts: 1, Hostnames: []string{"a"},
			Services: []model.ServiceResult{{Port: 80, State: "open"}, {Port: 22, State: "closed"}}},
		{IP: "::ffff:10.0.0.1", Up: true, ObservedAt: t0.Add(2 * time.Minute), Hostnames: []string{"a", "b"},
			Services: []model.ServiceResult{{Port: 22, State: "open"}, {Port: 80, State: "closed"}}},
	}
	out := MergeHostResults(in)
	if len(out) != 2 || out[0].IP != "10.0.0.1" || !out[0].Up || out[0].Attempts != 3 {
		t.Fatalf("out %+v", out)
	}
	if len(out[0].Services) != 2 || !isOpen(&out[0].Services[0]) || !isOpen(&out[0].Services[1]) {
		t.Fatalf("an open port must win: %+v", out[0].Services)
	}
	if strings.Join(out[0].Hostnames, ",") != "a,b" {
		t.Fatalf("hostnames %v", out[0].Hostnames)
	}
	if ObservationKey(5, "::ffff:10.0.0.1") != ObservationKey(5, "10.0.0.1") {
		t.Fatal("observation key must unmap IPv4")
	}
}
