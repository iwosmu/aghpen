package store_test

import (
	"context"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// A host reported twice in one run (two batches, for example a retry chunk)
// is one observation; a later "up" corrects an earlier "down" of the same run,
// a later "down" never hides an earlier "up".
func TestIngestDedupsObservationsPerRun(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning})
	if err != nil {
		t.Fatal(err)
	}
	counts := func(ip string) (total, up, rows int) {
		t.Helper()
		err := st.Pool().QueryRow(ctx, `SELECT h.obs_total, h.obs_up, (SELECT count(*) FROM host_observations o WHERE o.host_id = h.id AND o.run_id = $2)
			FROM hosts h WHERE h.ip = $1::inet`, ip, run.ID).Scan(&total, &up, &rows)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	ingest := func(h model.HostResult) {
		t.Helper()
		h.RunID = run.ID
		if err := st.IngestHosts(ctx, []model.HostResult{h}, store.SinkOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// Up, then up again in another batch.
	ingest(model.HostResult{IP: "10.60.0.1", Up: true, Services: []model.ServiceResult{{Port: 22, Proto: "tcp", State: "open"}}})
	ingest(model.HostResult{IP: "10.60.0.1", Up: true, Services: []model.ServiceResult{{Port: 80, Proto: "tcp", State: "open"}}})
	if total, up, rows := counts("10.60.0.1"); total != 1 || up != 1 || rows != 1 {
		t.Fatalf("up twice: obs_total=%d obs_up=%d rows=%d, want 1 1 1", total, up, rows)
	}
	// Up, then down: the down repeat is dropped.
	ingest(model.HostResult{IP: "10.60.0.1", Up: false})
	if total, up, rows := counts("10.60.0.1"); total != 1 || up != 1 || rows != 1 {
		t.Fatalf("up then down: obs_total=%d obs_up=%d rows=%d, want 1 1 1", total, up, rows)
	}
	// Down first (a known host), then up: one observation, up.
	other, _ := st.CreateRun(ctx, model.ScanRun{Status: model.RunCompleted})
	if err := st.IngestHosts(ctx, []model.HostResult{{RunID: other.ID, IP: "10.60.0.2", Up: true}}, store.SinkOptions{}); err != nil {
		t.Fatal(err)
	}
	ingest(model.HostResult{IP: "10.60.0.2", Up: false})
	ingest(model.HostResult{IP: "10.60.0.2", Up: true})
	if total, up, rows := counts("10.60.0.2"); total != 2 || up != 2 || rows != 1 {
		t.Fatalf("down then up: obs_total=%d obs_up=%d rows=%d, want 2 2 1", total, up, rows)
	}
	// The services of both batches are stored.
	ids, err := st.HostIDsByIP(ctx, []string{"10.60.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := st.ServiceIDsOf(ctx, []int64{ids["10.60.0.1"]})
	if err != nil || len(svcs[ids["10.60.0.1"]]) != 2 {
		t.Fatalf("services of the repeated host: %v %v", svcs, err)
	}
}

// A run note and label are stored and found by the run search.
func TestRunNoteLabelAndAdHoc(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunCompleted, Trigger: "reprobe",
		AdHoc: &model.AdHocScope{ProfileID: 0, Addresses: []string{"10.1.1.1"}, Ports: "80", Reason: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.SetRunNote(ctx, run.ID, "notatka", "etykieta")
	if err != nil || got.Note != "notatka" || got.Label != "etykieta" || got.AdHoc == nil || got.AdHoc.Ports != "80" {
		t.Fatalf("set note: %+v %v", got, err)
	}
	page, err := st.ListRuns(ctx, store.RunFilter{ListOpts: store.ListOpts{Q: "etykieta", Limit: 10}})
	if err != nil || page.Total != 1 {
		t.Fatalf("search by label: %+v %v", page, err)
	}
}
