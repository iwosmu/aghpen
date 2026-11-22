package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// modifiedSample changes the real nmap file the way a second scan could differ:
// nginx has a new version, the redis host opens SSH, the Apache port is closed
// and the fourth host does not answer.
func modifiedSample(t *testing.T, data []byte) []byte {
	t.Helper()
	s := string(data)
	steps := [][2]string{
		{"1.31.9", "1.33.0"},
		{`<port protocol="tcp" portid="22"><state state="closed" reason="reset" reason_ttl="64"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="closed"`, `<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" product="OpenSSH" version="9.9" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="closed"`},
		{`<state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" product="Apache httpd"`, `<state state="closed" reason="reset" reason_ttl="64"/><service name="http" product="Apache httpd"`},
		{`<status state="up" reason="localhost-response" reason_ttl="0"/>`, `<status state="down" reason="no-response" reason_ttl="0"/>`},
	}
	for _, st := range steps {
		if !strings.Contains(s, st[0]) {
			t.Fatalf("the sample no longer contains %q", st[0])
		}
		s = strings.ReplaceAll(s, st[0], st[1])
	}
	return []byte(s)
}

func kinds(changes []model.Change) map[string]int {
	out := map[string]int{}
	for _, c := range changes {
		out[fmt.Sprintf("%s %s:%d", c.Kind, c.IP, c.Port)]++
	}
	return out
}

func TestImportAnalysisDiffAndRoundTrip(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	an := NewAnalysis(st, time.UTC, quiet())
	m := runner.New(st, runner.Options{Analyzer: an})
	ic := Interchange{st: st}
	data, err := os.ReadFile("../../lab/defectdojo/sample-nmap.xml")
	if err != nil {
		t.Fatal(err)
	}

	// ---- first import: the baseline ----
	hosts, rep, err := ic.ParseResults(ctx, "sample-nmap.xml", data)
	if err != nil || rep.Format != "nmap-xml" || len(hosts) != 4 {
		t.Fatalf("parse: %d hosts, report %+v, err %v", len(hosts), rep, err)
	}
	run1, err := m.Import(ctx, "sample-nmap.xml", hosts, nil)
	if err != nil || run1.Status != model.RunCompleted || run1.Error != "" || run1.Summary == nil {
		t.Fatalf("import 1: %+v %v", run1, err)
	}
	ch1, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: run1.ID})
	if ch1.Total != 0 {
		t.Fatalf("the first run has no baseline, so no changes: %+v", ch1.Items)
	}
	svcs, _ := st.ListServices(ctx, store.ServiceFilter{State: []string{"open"}, ListOpts: store.ListOpts{Sort: "ip"}})
	if svcs.Total != 3 {
		t.Fatalf("open services after import 1: %d", svcs.Total)
	}
	var redis, nginx model.Service
	for _, s := range svcs.Items {
		t.Logf("service %s:%d %s %s interest=%d why=%v classes=%v group=%s", s.IP, s.Port, s.Product, s.Version, s.Interest, s.InterestWhy, s.Classes, s.GroupKey)
		if s.GroupKey == "" {
			t.Errorf("service %s:%d has no group key", s.IP, s.Port)
		}
		switch s.Port {
		case 6379:
			redis = s
		case 80:
			if strings.Contains(s.Product, "nginx") {
				nginx = s
			}
		}
	}
	if redis.Interest == 0 || len(redis.InterestWhy) == 0 {
		t.Fatalf("an exposed database must have an interest score with reasons: %+v", redis)
	}
	f1, _ := st.ListFindings(ctx, store.FindingFilter{})
	if f1.Total == 0 || run1.Summary.FindingsNew != f1.Total {
		t.Fatalf("findings after import 1: %d, summary %+v", f1.Total, run1.Summary)
	}
	var redisFinding model.Finding
	for _, f := range f1.Items {
		t.Logf("finding %s %s:%d %q interest=%d key=%s", f.Type, f.IP, f.Port, f.Title, f.Interest, f.Key)
		if f.Port == 6379 {
			redisFinding = f
		}
	}
	if redisFinding.ID == 0 {
		t.Fatal("no finding for the exposed Redis")
	}
	hostsPage, _ := st.ListHosts(ctx, store.HostFilter{ListOpts: store.ListOpts{Sort: "ip"}})
	for _, h := range hostsPage.Items {
		if h.Status != model.HostUp || h.PAlive < 0.99 {
			t.Errorf("host %s after import 1: status %s p_alive %.2f", h.IP, h.Status, h.PAlive)
		}
	}

	// ---- analyst edits ----
	if _, err := st.PatchService(ctx, nginx.ID, map[string]json.RawMessage{"product": json.RawMessage(`"nginx (reverse proxy dziekanatu)"`), "note": json.RawMessage(`"zgłoszone do DSI"`)}, "analityk@example.org"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PatchFinding(ctx, redisFinding.ID, map[string]json.RawMessage{"status": json.RawMessage(`"accepted"`), "note": json.RawMessage(`"baza testowa, ryzyko zaakceptowane"`)}, "analityk@example.org"); err != nil {
		t.Fatal(err)
	}

	// ---- second import: the modified file ----
	hosts2, rep2, err := ic.ParseResults(ctx, "sample-nmap-2.xml", modifiedSample(t, data))
	if err != nil || len(hosts2) != 4 {
		t.Fatalf("parse 2: %d hosts, report %+v, err %v", len(hosts2), rep2, err)
	}
	run2, err := m.Import(ctx, "sample-nmap-2.xml", hosts2, nil)
	if err != nil || run2.Status != model.RunCompleted || run2.Error != "" {
		t.Fatalf("import 2: %+v %v", run2, err)
	}
	ch2, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: run2.ID, ListOpts: store.ListOpts{Limit: 100}})
	got := kinds(ch2.Items)
	for _, c := range ch2.Items {
		t.Logf("change %-16s %-8s %s:%d %s (expected=%v) before=%v after=%v", c.Kind, c.Severity, c.IP, c.Port, c.Summary, c.Expected, c.Before, c.After)
	}
	for _, want := range []string{"service_changed 172.31.250.2:80", "service_new 172.31.250.4:22", "service_gone 172.31.250.3:80", "host_missing 172.31.250.5:0"} {
		if got[want] == 0 {
			t.Errorf("missing change %q; got %v", want, got)
		}
	}
	sum := run2.Summary
	if sum == nil || sum.PrevRunID == nil || *sum.PrevRunID != run1.ID || sum.ServicesNew != 1 || sum.ServicesGone != 1 || sum.ServicesChanged < 1 || sum.HostsMissing != 1 {
		t.Fatalf("summary of run 2: %+v", sum)
	}
	// The override and the notes survive; the observed value is recorded beside the override.
	nginx2, _ := st.GetService(ctx, nginx.ID, false)
	if nginx2.Product != "nginx (reverse proxy dziekanatu)" || nginx2.Note != "zgłoszone do DSI" || nginx2.Version != "1.33.0" || nginx2.Overrides["product"].Observed != "nginx" {
		t.Fatalf("service after import 2: %+v", nginx2)
	}
	rf, _ := st.GetFinding(ctx, redisFinding.ID)
	if rf.Status != model.FindingAccepted || rf.Note != "baza testowa, ryzyko zaakceptowane" || rf.LastRunID != run2.ID {
		t.Fatalf("finding after import 2: %+v", rf)
	}
	// The closed Apache port: the service is gone and its untouched findings are resolved.
	gone, _ := st.ListServices(ctx, store.ServiceFilter{State: []string{"gone"}})
	if gone.Total != 1 || gone.Items[0].IP != "172.31.250.3" {
		t.Fatalf("gone services: %+v", gone.Items)
	}
	f2, _ := st.ListFindings(ctx, store.FindingFilter{ListOpts: store.ListOpts{Limit: 100}})
	resolved, sshFinding := 0, false
	for _, f := range f2.Items {
		t.Logf("finding after run 2: %-22s %s:%d status=%s first_run=%d last_run=%d", f.Type, f.IP, f.Port, f.Status, f.FirstRunID, f.LastRunID)
		if f.IP == "172.31.250.3" && f.Status == model.FindingResolved {
			resolved++
		}
		if f.IP == "172.31.250.3" && f.Status != model.FindingResolved {
			t.Errorf("finding of the closed port must be resolved: %+v", f)
		}
		if f.IP == "172.31.250.4" && f.Port == 22 && f.FirstRunID == run2.ID {
			sshFinding = true
		}
	}
	if !sshFinding {
		t.Error("the new SSH service must produce a finding")
	}
	t.Logf("resolved findings of the closed port: %d", resolved)
	// The silent host: one miss after one answer is "unstable", not "down".
	silent, _ := st.ListHosts(ctx, store.HostFilter{CIDR: "172.31.250.5"})
	if len(silent.Items) != 1 || silent.Items[0].Status != model.HostUnstable || silent.Items[0].ConsecutiveMisses != 1 || silent.Items[0].PAlive >= 1 || silent.Items[0].PAlive < 0.2 {
		t.Fatalf("silent host: %+v", silent.Items)
	}
	prof, _ := st.Availability(ctx, silent.Items[0].ID)
	if n := an.DownAfterMisses(prof); n < 1 {
		t.Fatalf("down_after_misses of an unstable host must be at least 1, got %d", n)
	} else {
		t.Logf("silent host: p_alive=%.3f, reported inactive after %d more misses", silent.Items[0].PAlive, n)
	}

	// ---- GET /diff seam: any two runs ----
	diff, err := an.Diff(ctx, run1.ID, run2.ID)
	if err != nil || diff.From.ID != run1.ID || diff.To.ID != run2.ID {
		t.Fatalf("diff: %v", err)
	}
	dk := kinds(diff.Changes)
	for _, want := range []string{"service_changed 172.31.250.2:80", "service_new 172.31.250.4:22", "service_gone 172.31.250.3:80"} {
		if dk[want] == 0 {
			t.Errorf("diff misses %q; got %v", want, dk)
		}
	}
	if back, _ := an.Diff(ctx, run2.ID, run2.ID); len(back.Changes) != 0 {
		t.Errorf("a run compared with itself has no changes: %v", kinds(back.Changes))
	}

	// ---- exports import again without a change ----
	for _, format := range []string{"json", "xml", "csv"} {
		var buf bytes.Buffer
		w, err := ic.RunWriter(&buf, format, run2)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		if err := st.EachRunResult(ctx, run2.ID, func(h *model.HostResult) error { n++; return w.WriteHost(*h) }); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		again, rep, err := ic.ParseResults(ctx, "export."+format, buf.Bytes())
		if err != nil || len(again) != n || len(rep.Invalid) != 0 {
			t.Fatalf("%s: re-import gave %d hosts of %d, report %+v, err %v", format, len(again), n, rep, err)
		}
		// The run observed four hosts, one of them down (172.31.250.5): the
		// export carries it with that state in every format, and the import
		// reads it back as a down host (ImportReport.HostsDown).
		down := ""
		for _, h := range again {
			if !h.Up {
				down += h.IP
			}
		}
		if n != 4 || rep.HostsDown != 1 || down != "172.31.250.5" {
			t.Errorf("%s: exported %d hosts, re-import down hosts %d (%q); want 4 and the silent host", format, n, rep.HostsDown, down)
		}
		runN, err := m.Import(ctx, "export."+format, again, nil)
		if err != nil || runN.Error != "" {
			t.Fatalf("%s: import of the export: %+v %v", format, runN, err)
		}
		d, err := an.Diff(ctx, run2.ID, runN.ID)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%-4s export: %d bytes, %d hosts; diff against the source run: %d changes %v", format, buf.Len(), n, len(d.Changes), kinds(d.Changes))
		if len(d.Changes) != 0 {
			t.Errorf("%s: the export must import without a change", format)
		}
	}
}

func TestPartialRunsAndStability(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	an := NewAnalysis(st, time.UTC, quiet())
	start := time.Now().UTC().Add(-20 * 24 * time.Hour).Truncate(time.Hour)
	day := 0
	scan := func(results ...model.HostResult) (model.ScanRun, []model.Change) {
		t.Helper()
		run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunAnalyzing, Trigger: "import", ProfileName: "test"})
		if err != nil {
			t.Fatal(err)
		}
		at := start.Add(time.Duration(day) * 24 * time.Hour)
		day++
		for i := range results {
			results[i].RunID, results[i].ObservedAt = run.ID, at
		}
		if err := st.IngestHosts(ctx, results, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := an.AnalyzeRun(ctx, run.ID); err != nil {
			t.Fatal(err)
		}
		run.Status = model.RunCompleted
		_ = st.SaveRun(ctx, run)
		page, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: run.ID, ListOpts: store.ListOpts{Limit: 100}})
		return run, page.Items
	}
	web := func(ip string, up bool) model.HostResult {
		h := model.HostResult{IP: ip, Up: up}
		if up {
			h.Services = []model.ServiceResult{{Port: 443, Proto: "tcp", State: "open", Name: "https", Product: "nginx", Tunnel: "ssl"}}
		}
		return h
	}
	host := func(ip string) model.Host {
		t.Helper()
		p, _ := st.ListHosts(ctx, store.HostFilter{CIDR: ip})
		if len(p.Items) != 1 {
			t.Fatalf("host %s not found", ip)
		}
		return p.Items[0]
	}
	const a, b = "10.77.0.1", "10.77.0.2"
	// Five full runs: both hosts answer.
	for i := 0; i < 5; i++ {
		scan(web(a, true), web(b, true))
	}
	// A partial run (its window closed): it reached only A. B was not probed, so it is not a miss.
	_, ch := scan(web(a, true))
	if hb := host(b); hb.Status != model.HostUp || hb.ConsecutiveMisses != 0 || len(ch) != 0 {
		t.Fatalf("a host that the run did not reach must not change: %+v, changes %v", hb, kinds(ch))
	}
	// Analysing the same run again changes nothing (resume, restart).
	last, _ := st.ListRuns(ctx, store.RunFilter{ListOpts: store.ListOpts{Limit: 1}})
	before := host(a)
	if _, err := an.AnalyzeRun(ctx, last.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if after := host(a); after.Status != before.Status || after.PAlive != before.PAlive || after.Interest != before.Interest {
		t.Fatalf("a repeated analysis must be stable: %+v vs %+v", before, after)
	}
	// B stops answering. The first miss is "unstable"; "down" (host_gone) comes after a few misses, once.
	var trail []string
	gone, unstable := 0, 0
	for i := 0; i < 8 && gone == 0; i++ {
		_, ch = scan(web(a, true), web(b, false))
		hb := host(b)
		trail = append(trail, fmt.Sprintf("miss %d: status=%s p_alive=%.3f", i+1, hb.Status, hb.PAlive))
		for _, c := range ch {
			switch c.Kind {
			case model.ChangeHostGone:
				gone++
			case model.ChangeHostUnstable, model.ChangeHostMissing:
				// A host that answered in the previous run and is silent now is host_missing (analyze.Diff).
				unstable++
			}
		}
		if i == 0 && (hb.Status != model.HostUnstable || unstable != 1) {
			t.Fatalf("first miss: status %s, changes %v", hb.Status, kinds(ch))
		}
	}
	t.Logf("a host that answered in 5 runs then stops:\n  %s", strings.Join(trail, "\n  "))
	if gone != 1 || unstable != 1 || host(b).Status != model.HostDown || len(trail) < 2 {
		t.Fatalf("host_gone must come once, after more than one miss: gone=%d unstable=%d status=%s", gone, unstable, host(b).Status)
	}
	// More misses of a host that is already down are not reported again.
	if _, ch = scan(web(a, true), web(b, false)); len(ch) != 0 {
		t.Fatalf("a host that is already down must not be reported again: %v", kinds(ch))
	}
	// Its services were not reported gone: they are unknown while the host is silent.
	sv, _ := st.ListServices(ctx, store.ServiceFilter{HostID: host(b).ID})
	if len(sv.Items) != 1 || sv.Items[0].State != model.ServiceUnknown {
		t.Fatalf("service of a silent host: %+v", sv.Items)
	}
	// B answers again: host_back, and no "new service" noise.
	_, ch = scan(web(a, true), web(b, true))
	got := kinds(ch)
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) != 1 || keys[0] != "host_back "+b+":0" || host(b).Status != model.HostUp {
		t.Fatalf("host back: changes %v status %s", keys, host(b).Status)
	}
}

func TestParsePorts(t *testing.T) {
	in, ok := ParsePorts("22,80,443,8000-8100,U:53")
	if !ok || !in("tcp", 22) || !in("", 8050) || in("tcp", 21) || !in("udp", 53) || in("tcp", 53) {
		t.Fatal("explicit list")
	}
	for _, spec := range []string{"top-100", "-", "", "http", "80-70"} {
		if _, ok := ParsePorts(spec); ok {
			t.Errorf("%q names no explicit ports", spec)
		}
	}
}
