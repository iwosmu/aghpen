package wire

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// A host that answered discovery but whose port scan got no answer (the
// engine reports it up with ports_unknown and no services) keeps its
// services: no service_gone in that run, and the next run with the ports
// seen again reports nothing either (the case of run 138 on the UI stack:
// 10 x service_gone, then 10 x service_new two minutes later).
func TestSilentPortScanMakesNoChange(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	an := NewAnalysis(st, time.UTC, quiet())
	prof, err := st.CreateProfile(ctx, model.ScanProfile{Name: "co 2 minuty", Ports: "top-100", ScopeIDs: []int64{}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const ip = "172.31.6.9"
	svcs := []model.ServiceResult{{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "nginx"}, {Port: 2222, Proto: "tcp", State: "open", Name: "ssh"}}
	top := &model.PortCoverage{TCP: []model.PortRange{{Lo: 1, Hi: 1000}, {Lo: 2222, Hi: 2222}}}
	at := time.Now().UTC().Add(-time.Hour)
	run := func(h model.HostResult) []model.Change {
		t.Helper()
		r, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunAnalyzing, Trigger: "schedule", ProfileID: &prof.ID, ProfileName: prof.Name})
		if err != nil {
			t.Fatal(err)
		}
		at = at.Add(2 * time.Minute)
		h.RunID, h.ObservedAt, h.IP, h.Up = r.ID, at, ip, true
		if err := st.IngestHosts(ctx, []model.HostResult{h}, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := an.AnalyzeRun(ctx, r.ID); err != nil {
			t.Fatal(err)
		}
		r, _ = st.GetRun(ctx, r.ID)
		r.Status = model.RunCompleted
		_ = st.SaveRun(ctx, r)
		page, err := st.ListChanges(ctx, store.ChangeFilter{RunID: r.ID, ListOpts: store.ListOpts{Limit: 100}})
		if err != nil {
			t.Fatal(err)
		}
		return page.Items
	}
	run(model.HostResult{Reason: "syn-ack", Services: svcs, Coverage: top})
	if ch := run(model.HostResult{Reason: model.ReasonPortsUnknown, PortsUnknown: true}); len(ch) != 0 {
		t.Errorf("the silent run reported %d changes: %+v", len(ch), ch)
	}
	var open int
	if err := st.Pool().QueryRow(ctx, "SELECT count(*) FROM services WHERE host(ip) = $1 AND state = 'open'", ip).Scan(&open); err != nil || open != 2 {
		t.Errorf("open services after the silent run = %d (%v), want 2", open, err)
	}
	if ch := run(model.HostResult{Reason: "syn-ack", Services: svcs, Coverage: top}); len(ch) != 0 {
		t.Errorf("the run after it reported %d changes: %+v", len(ch), ch)
	}
}
