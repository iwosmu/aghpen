package wire

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// A host with 30 known services gets a manual entry (or an imported file)
// that names one of them. The entry states only what it contains: no
// "gone" for the 29 others, no response-time verdict for a source that did
// not measure a response, the services stay open.
func TestManualEntryAndImportStateOnlyWhatTheyContain(t *testing.T) {
	for _, trigger := range []string{"manual-entry", "import"} {
		t.Run(trigger, func(t *testing.T) {
			st := storetest.New(t)
			ctx := context.Background()
			an := NewAnalysis(st, time.UTC, quiet())
			const ip = "172.18.0.1"
			var svcs []model.ServiceResult
			for p := 8000; p < 8030; p++ {
				s := model.ServiceResult{Port: p, Proto: "tcp", State: "open", Name: "http", Product: "nginx"}
				s.HTTP = &model.HTTPFingerprint{Scheme: "http", URL: fmt.Sprintf("http://%s:%d/", ip, p), Status: 200, ResponseMs: 4}
				svcs = append(svcs, s)
			}
			at := time.Now().UTC().Add(-time.Hour)
			run := func(trigger string, source string, mark bool, hs ...model.ServiceResult) map[string]int {
				t.Helper()
				r, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunAnalyzing, Trigger: trigger, ProfileName: "test"})
				if err != nil {
					t.Fatal(err)
				}
				at = at.Add(10 * time.Minute)
				h := model.HostResult{RunID: r.ID, ObservedAt: at, IP: ip, Up: true, Reason: "syn-ack", Services: hs}
				if err := st.IngestHosts(ctx, []model.HostResult{h}, store.SinkOptions{Source: source, MarkMissing: mark}); err != nil {
					t.Fatal(err)
				}
				if _, err := an.AnalyzeRun(ctx, r.ID); err != nil {
					t.Fatal(err)
				}
				page, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: r.ID, ListOpts: store.ListOpts{Limit: 100}})
				return kinds(page.Items)
			}
			run("manual", "scan", true, svcs...)
			run("manual", "scan", true, svcs...) // a baseline of two scans with response times
			source := map[string]string{"manual-entry": "manual", "import": "import"}[trigger]
			k := run(trigger, source, false, model.ServiceResult{Port: 8020, Proto: "tcp", State: "open", Name: "http"})
			if len(k) != 0 {
				t.Errorf("%s of one service on a host with 30: %v, want no change", trigger, k)
			}
			var open int
			if err := st.Pool().QueryRow(ctx, "SELECT count(*) FROM services WHERE state = 'open'").Scan(&open); err != nil || open != 30 {
				t.Errorf("open services after the %s: %d (%v), want 30", trigger, open, err)
			}
		})
	}
}
