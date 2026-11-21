package wire

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
	"github.com/iwosmu/aghpen/internal/targets"
)

// The organisers' template: one docker host, services on published ports.
// Run 2 stops 8787 and slows WordPress down (Toxiproxy), run 3 brings 8787
// back and removes the latency. The store, the ingest and the analysis are
// real; only the scan results are given.
func TestJuryTemplateReturnedServiceAndResponseTime(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	targets.SetHostGateway(netip.MustParseAddr("192.168.65.254"))
	defer targets.SetHostGateway(netip.Addr{})
	an := NewAnalysis(st, time.UTC, quiet())
	an.SelfPort = 18080
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)
	n := 0
	scan := func(svcs ...model.ServiceResult) (model.ScanRun, []model.Change) {
		t.Helper()
		run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunAnalyzing, Trigger: "manual", ProfileName: "test"})
		if err != nil {
			t.Fatal(err)
		}
		at := start.Add(time.Duration(n) * 5 * time.Minute)
		n++
		h := model.HostResult{RunID: run.ID, ObservedAt: at, IP: "192.168.65.254", Up: true, Hostnames: []string{"localhost"}, Services: svcs}
		if err := st.IngestHosts(ctx, []model.HostResult{h}, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := an.AnalyzeRun(ctx, run.ID); err != nil {
			t.Fatal(err)
		}
		run, _ = st.GetRun(ctx, run.ID) // with the summary of the analysis
		run.Status = model.RunCompleted
		_ = st.SaveRun(ctx, run)
		page, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: run.ID, ListOpts: store.ListOpts{Limit: 100}})
		return run, page.Items
	}
	web := func(port int, title string, ms int) model.ServiceResult {
		return model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http",
			HTTP: &model.HTTPFingerprint{Scheme: "http", URL: "http://localhost/", Status: 200, Title: title, ResponseMs: ms}}
	}
	self := web(18080, "Czujka", 3)
	gitea := web(3001, "Gitea", 40)
	flask := web(8787, "Hello", 5)

	_, ch := scan(self, gitea, flask, web(8085, "WordPress", 90))
	if len(ch) != 0 {
		t.Fatalf("run 1 has no baseline: %v", kinds(ch))
	}
	_, ch = scan(self, gitea, web(8085, "WordPress", 640))
	k := kinds(ch)
	if k["service_gone 192.168.65.254:8787"] != 1 || k["response_slower 192.168.65.254:8085"] != 1 {
		t.Fatalf("run 2: %v", k)
	}
	run3, ch := scan(self, gitea, flask, web(8085, "WordPress", 95))
	k = kinds(ch)
	if k["service_returned 192.168.65.254:8787"] != 1 || k["service_new 192.168.65.254:8787"] != 0 || k["response_recovered 192.168.65.254:8085"] != 1 {
		t.Fatalf("run 3: %v", k)
	}
	for _, c := range ch {
		if c.Kind == model.ChangeServiceReturned {
			b, _ := c.Before.(map[string]any)
			if b["runs_away"] != float64(1) || b["away_seconds"] != float64(600) {
				t.Errorf("returned before = %v", c.Before)
			}
		}
	}
	got, _ := st.GetRun(ctx, run3.ID)
	if got.Summary == nil || got.Summary.ServicesReturned != 1 || got.Summary.ServicesNew != 0 {
		t.Errorf("run 3 summary %+v", got.Summary)
	}

	// The docker host is named, Czujka's own service is tagged and has no finding.
	hp, _ := st.ListHosts(ctx, store.HostFilter{CIDR: "192.168.65.254"})
	if len(hp.Items) != 1 || hp.Items[0].Label != store.DockerHostLabel || !slices.Contains(hp.Items[0].Hostnames, "localhost") {
		t.Fatalf("docker host: %+v", hp.Items)
	}
	sp, _ := st.ListServices(ctx, store.ServiceFilter{HostID: hp.Items[0].ID, Port: 18080})
	if len(sp.Items) != 1 || !slices.Contains(sp.Items[0].Tags, store.SelfTag) {
		t.Fatalf("self service: %+v", sp.Items)
	}
	fp, _ := st.ListFindings(ctx, store.FindingFilter{HostIDs: []int64{hp.Items[0].ID}})
	for _, f := range fp.Items {
		if f.Port == 18080 {
			t.Errorf("a finding about Czujka itself: %+v", f)
		}
	}

	// The response series of WordPress for the chart.
	wp, _ := st.ListServices(ctx, store.ServiceFilter{HostID: hp.Items[0].ID, Port: 8085})
	pts, err := st.ResponseSeries(ctx, wp.Items[0].ID, 50)
	if err != nil || len(pts) != 3 || pts[0].Ms != 90 || pts[1].Ms != 640 || pts[2].Ms != 95 {
		t.Fatalf("series %+v %v", pts, err)
	}
}
