package wire

import (
	"context"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// The deep pass end to end in the store: a host's second, full result of a
// run records when every port was scanned (HostHint.DeepAt for the next
// run's priority), counts as one observation, and the service it found
// gets a change marked deep_pass ("found by the deeper pass").
func TestDeepPassInTheStore(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	an := NewAnalysis(st, time.UTC, quiet())
	prof, err := st.CreateProfile(ctx, model.ScanProfile{Name: "duży zakres", Ports: "top-100", ScopeIDs: []int64{}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const ip = "172.31.5.7"
	svc80 := model.ServiceResult{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "nginx"}
	svcHigh := model.ServiceResult{Port: 40000, Proto: "tcp", State: "open", Name: "http", Product: "nginx", DeepPass: true}
	at := time.Now().UTC().Add(-time.Hour)
	run := func(results ...model.HostResult) int64 {
		t.Helper()
		r, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunAnalyzing, Trigger: "manual", ProfileID: &prof.ID, ProfileName: prof.Name})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range results {
			h.RunID = r.ID
			if err := st.IngestHosts(ctx, []model.HostResult{h}, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := an.AnalyzeRun(ctx, r.ID); err != nil {
			t.Fatal(err)
		}
		r, _ = st.GetRun(ctx, r.ID)
		r.Status = model.RunCompleted
		_ = st.SaveRun(ctx, r)
		return r.ID
	}
	top := &model.PortCoverage{TCP: []model.PortRange{{Lo: 80, Hi: 80}}}
	full := &model.PortCoverage{TCP: []model.PortRange{{Lo: 1, Hi: 65535}}}

	// run 1: the general pass only
	at = at.Add(time.Minute)
	run(model.HostResult{ObservedAt: at, IP: ip, Up: true, Reason: "syn-ack", Services: []model.ServiceResult{svc80}, Coverage: top})
	hints, err := st.HostHintsIn(ctx, []string{ip})
	if err != nil || len(hints) != 1 || hints[0].DeepAt != nil {
		t.Fatalf("after the general pass: hints %+v, %v", hints, err)
	}

	// run 2: the general result, then the deep pass's result of the same host
	at = at.Add(10 * time.Minute)
	deepAt := at.Add(2 * time.Minute)
	r2 := run(
		model.HostResult{ObservedAt: at, IP: ip, Up: true, Reason: "syn-ack", Services: []model.ServiceResult{svc80}, Coverage: top},
		model.HostResult{ObservedAt: deepAt, IP: ip, Up: true, Reason: "syn-ack", Services: []model.ServiceResult{svc80, svcHigh}, Coverage: full, FullPorts: true},
	)
	hints, err = st.HostHintsIn(ctx, []string{ip})
	if err != nil || len(hints) != 1 || hints[0].DeepAt == nil || hints[0].DeepAt.Sub(deepAt).Abs() > time.Microsecond {
		t.Fatalf("after the deep pass: hints %+v, %v", hints, err)
	}
	h, err := st.ListHosts(ctx, store.HostFilter{Q: ip})
	if err != nil || len(h.Items) != 1 {
		t.Fatalf("hosts: %+v, %v", h.Items, err)
	}
	obs, err := st.HostObservations(ctx, []int64{h.Items[0].ID}, 10)
	n2 := 0
	for _, o := range obs[h.Items[0].ID] {
		if o.RunID == r2 {
			n2++
		}
	}
	if err != nil || n2 != 1 {
		t.Errorf("run 2 has %d observations of the host (%v): the deep result is the same run's observation", n2, err)
	}
	ch, err := st.ListChanges(ctx, store.ChangeFilter{RunID: r2, ListOpts: store.ListOpts{Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	var deep, other int
	for _, c := range ch.Items {
		if c.Port == 40000 && c.DeepPass {
			deep++
		} else if c.DeepPass {
			other++
		}
	}
	if deep == 0 || other != 0 {
		t.Errorf("changes of run 2: %+v (want the 40000 change marked deep_pass, nothing else)", ch.Items)
	}

	// run 3: a general pass only; the deep service is outside the coverage and keeps its state
	at = at.Add(10 * time.Minute)
	r3 := run(model.HostResult{ObservedAt: at, IP: ip, Up: true, Reason: "syn-ack", Services: []model.ServiceResult{svc80}, Coverage: top})
	ch, err = st.ListChanges(ctx, store.ChangeFilter{RunID: r3, ListOpts: store.ListOpts{Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range ch.Items {
		if c.Port == 40000 {
			t.Errorf("run 3 reported %s on 40000: a port outside the coverage must not change", c.Kind)
		}
	}
	hints, _ = st.HostHintsIn(ctx, []string{ip})
	if len(hints) != 1 || hints[0].DeepAt == nil || hints[0].DeepAt.Sub(deepAt).Abs() > time.Microsecond {
		t.Errorf("a general pass must keep the deep scan time: %+v", hints)
	}
}
