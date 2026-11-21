package wire

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// cov is a coverage of TCP ranges.
func cov(r ...[2]int) *model.PortCoverage {
	c := &model.PortCoverage{UDP: []model.PortRange{}}
	for _, x := range r {
		c.TCP = append(c.TCP, model.PortRange{Lo: x[0], Hi: x[1]})
	}
	return c
}

// The jury's template on the default profile: port 8787 is outside the
// profile's top ports, and only the full-range pass finds it. A later
// complete run whose full range covered the host and did not see 8787
// reports it gone; when it is back, returned. When the full range did not
// cover the host, 8787 keeps its state, the run carries it, and no change
// is reported then or in the next run.
func TestFullRangeOnlyPortGoneAndBack(t *testing.T) {
	const ip = "172.31.0.9"
	top := cov([2]int{80, 80}, [2]int{443, 443}) // stands for the profile's list (8787 not in it)
	full := cov([2]int{1, 65535})                // the full-range pass finished for the host
	svc80 := model.ServiceResult{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "nginx"}
	svc8787 := model.ServiceResult{Port: 8787, Proto: "tcp", State: "open", Name: "http", Product: "nginx", HTTP: &model.HTTPFingerprint{Scheme: "http", URL: "http://x:8787/", Status: 200, Title: "Shop", ResponseMs: 5}}

	setup := func(t *testing.T) (*store.Store, func(t *testing.T, c *model.PortCoverage, svcs ...model.ServiceResult) map[string]int) {
		st := storetest.New(t)
		ctx := context.Background()
		an := NewAnalysis(st, time.UTC, quiet())
		prof, err := st.CreateProfile(ctx, model.ScanProfile{Name: "domyślny", Ports: "top-100", ScopeIDs: []int64{}, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Add(-time.Hour)
		scan := func(t *testing.T, c *model.PortCoverage, svcs ...model.ServiceResult) map[string]int {
			t.Helper()
			r, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunAnalyzing, Trigger: "manual", ProfileID: &prof.ID, ProfileName: prof.Name})
			if err != nil {
				t.Fatal(err)
			}
			at = at.Add(10 * time.Minute)
			h := model.HostResult{RunID: r.ID, ObservedAt: at, IP: ip, Up: true, Reason: "syn-ack", Services: svcs, Coverage: c}
			if err := st.IngestHosts(ctx, []model.HostResult{h}, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := an.AnalyzeRun(ctx, r.ID); err != nil {
				t.Fatal(err)
			}
			r, _ = st.GetRun(ctx, r.ID)
			r.Status = model.RunCompleted
			_ = st.SaveRun(ctx, r)
			page, _ := st.ListChanges(ctx, store.ChangeFilter{RunID: r.ID, ListOpts: store.ListOpts{Limit: 100}})
			return kinds(page.Items)
		}
		return st, scan
	}
	state := func(t *testing.T, st *store.Store) string {
		t.Helper()
		var s string
		if err := st.Pool().QueryRow(context.Background(), "SELECT state FROM services WHERE port = 8787").Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	g8787, r8787, n8787 := "service_gone "+ip+":8787", "service_returned "+ip+":8787", "service_new "+ip+":8787"

	t.Run("full range covered: gone, then returned", func(t *testing.T) {
		st, scan := setup(t)
		scan(t, full, svc80, svc8787) // run A: the first run of the profile, no earlier run to compare
		k := scan(t, full, svc80)
		if k[g8787] != 1 || len(k) != 1 {
			t.Fatalf("run B (8787 stopped, full range done): %v, want only %s", k, g8787)
		}
		if s := state(t, st); s != "gone" {
			t.Errorf("state after run B: %s", s)
		}
		k = scan(t, full, svc80, svc8787)
		if k[r8787] != 1 || k[n8787] != 0 {
			t.Fatalf("run C (8787 back): %v, want %s", k, r8787)
		}
	})

	t.Run("full range skipped: nothing gone, nothing in the next run", func(t *testing.T) {
		st, scan := setup(t)
		scan(t, full, svc80, svc8787)
		if k := scan(t, top, svc80); len(k) != 0 {
			t.Fatalf("run B (full range skipped): %v, want no change", k)
		}
		if s := state(t, st); s != "open" {
			t.Errorf("state after a run that did not scan 8787: %s, want open", s)
		}
		var carried bool
		if err := st.Pool().QueryRow(context.Background(), `SELECT COALESCE((result->>'carried')::boolean, false) FROM service_observations o
			JOIN services s ON s.id = o.service_id WHERE s.port = 8787 ORDER BY o.run_id DESC LIMIT 1`).Scan(&carried); err != nil || !carried {
			t.Errorf("run B has no carried observation of 8787 (%v)", err)
		}
		// next run with the full range: 8787 still there, so nothing (no false "returned")
		if k := scan(t, full, svc80, svc8787); len(k) != 0 {
			t.Fatalf("run C (8787 open, full range): %v, want no change", k)
		}
		// and a skipped run, then a covered run without 8787: gone in that run
		scan(t, top, svc80)
		if k := scan(t, full, svc80); k[g8787] != 1 {
			t.Fatalf("run E (covered, 8787 stopped): %v, want %s", k, g8787)
		}
	})

	t.Run("the response series ignores carried copies", func(t *testing.T) {
		st, scan := setup(t)
		scan(t, full, svc80, svc8787)
		scan(t, top, svc80)
		scan(t, top, svc80)
		var id int64
		_ = st.Pool().QueryRow(context.Background(), "SELECT id FROM services WHERE port = 8787").Scan(&id)
		series, err := st.ResponseSeries(context.Background(), id, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(series) != 1 {
			t.Errorf("response series %+v, want the one measurement", series)
		}
	})
}
