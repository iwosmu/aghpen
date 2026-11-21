package wire

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// TestReportPassiveSignaturesAndPortScope runs the adapters of Build against
// a real database: an imported run, its report, a passive file, hostnames,
// a signature file and the port scope of the diff.
func TestReportPassiveSignaturesAndPortScope(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	w := Build(config.Config{Timezone: "Europe/Warsaw"}, st, quiet())
	if err := w.Signatures.Start(ctx); err != nil {
		t.Fatal(err)
	}
	m := runner.New(st, runner.Options{Analyzer: w.RunAnalyzer})
	ic := Interchange{st: st}
	data, err := os.ReadFile("../../lab/defectdojo/sample-nmap.xml")
	if err != nil {
		t.Fatal(err)
	}
	hosts, _, err := ic.ParseResults(ctx, "sample-nmap.xml", data)
	if err != nil {
		t.Fatal(err)
	}
	run, err := m.Import(ctx, "sample-nmap.xml", hosts, nil)
	if err != nil || run.Status != model.RunCompleted {
		t.Fatalf("import: %+v %v", run, err)
	}

	// report of the run, both formats
	var md, html bytes.Buffer
	if err := w.API.Reporter.RunReport(ctx, run.ID, "md", &md); err != nil {
		t.Fatal(err)
	}
	if err := w.API.Reporter.RunReport(ctx, run.ID, "html", &html); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "172.31.250.4") || !strings.Contains(html.String(), "<html") {
		t.Errorf("report misses the run data:\n%s", md.String()[:min(800, md.Len())])
	}
	if err := w.API.Reporter.RunReport(ctx, 99999, "md", &md); err == nil {
		t.Error("a missing run must be an error")
	}

	// passive: a file with one address in scope, one outside, against a scope with a CIDR
	sc, err := st.CreateScope(ctx, model.Scope{Name: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.AddTargets(ctx, sc.ID, []model.Target{{Kind: model.TargetCIDR, Value: "172.31.250.0/24", Enabled: true, Addresses: 256}}, nil); err != nil {
		t.Fatal(err)
	}
	res, err := w.API.Passive.ImportFile(ctx, "pdns.csv", []byte("hostname,ip\nwww.lab.test,172.31.250.9\nobcy.example.org,192.0.2.10\nnginx.lab.test,172.31.250.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	var cand []string
	for _, c := range res.Candidates {
		cand = append(cand, c.Value)
	}
	if !strings.Contains(strings.Join(cand, " "), "172.31.250.9") || strings.Contains(strings.Join(cand, " "), "192.0.2.10") || len(res.OutOfScope) == 0 || res.File == nil {
		t.Errorf("passive import: candidates %v, out of scope %d, file %v", cand, len(res.OutOfScope), res.File)
	}
	if _, err := w.API.Passive.CT(ctx); err == nil {
		t.Error("crt.sh must be off by default")
	}

	// hostnames from PTR go to known hosts only, once
	if ok, err := st.AddHostnames(ctx, "172.31.250.2", []string{"nginx.lab.test"}); err != nil || !ok {
		t.Fatalf("add hostnames: %v %v", ok, err)
	}
	if ok, _ := st.AddHostnames(ctx, "172.31.250.2", []string{"nginx.lab.test"}); ok {
		t.Error("the same name twice must not count as a change")
	}
	if ok, _ := st.AddHostnames(ctx, "10.255.0.1", []string{"x.test"}); ok {
		t.Error("an unknown address must not change anything")
	}
	hp, _ := st.ListHosts(ctx, store.HostFilter{Q: "172.31.250.2"})
	found := false
	for _, h := range hp.Items {
		for _, n := range h.Hostnames {
			found = found || n == "nginx.lab.test"
		}
	}
	if !found {
		t.Errorf("hostname not stored: %+v", hp.Items)
	}

	// signature file: one valid, one unsafe; the match counts run after an analysis
	rep, err := w.API.SigImporter.ImportSignatures(ctx, "- id: e2e-ok\n  name: OK\n  body: 'nginx'\n- id: e2e-bad\n  name: Bad\n  requests:\n    - {path: /login, method: POST}\n  body: x\n", "test")
	if err != nil || len(rep.Created) != 1 || rep.Created[0] != "e2e-ok" {
		t.Fatalf("signature import: %+v %v", rep, err)
	}
	bad := 0
	for _, is := range rep.Validation.Issues {
		if is.Level == "error" {
			bad++
		}
	}
	if bad == 0 {
		t.Errorf("the unsafe signature must be rejected with a reason: %+v", rep.Validation)
	}

	// port scope: top-100 resolves to the engine's real list, the policy deny list applies
	a := NewAnalysis(st, time.UTC, quiet())
	in := a.portScope(ctx, model.ScanProfile{Ports: "top-100"})
	if in == nil || !in("tcp", 80) || !in("", 443) || in("tcp", 6379) || in("udp", 53) {
		t.Error("top-100: 80 and 443 in, 6379 (not in the list) and udp out")
	}
	pol, _ := st.GetSafetyPolicy(ctx)
	pol.DeniedPorts = "443"
	if _, err := st.PutSafetyPolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	in = a.portScope(ctx, model.ScanProfile{Ports: "22,80,443"})
	if !in("tcp", 22) || in("tcp", 443) || in("tcp", 8080) {
		t.Error("explicit list minus the deny list")
	}
}
