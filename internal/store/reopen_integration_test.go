package store_test

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// One reopen rule for the engine's findings and the policy findings: accepted
// and false positive are never reopened; resolved is reopened once, only by
// an observation newer than the resolution, with an audit entry.
func TestReopenRuleOncePerResolution(t *testing.T) {
	st := storetest.New(t)
	sink := st.NewSink(store.SinkOptions{})
	run := mkRun(t, st)
	if err := sink.OnHost(ctx, model.HostResult{RunID: run.ID, IP: "10.30.0.7", Up: true,
		Services: []model.ServiceResult{{Port: 6379, Proto: "tcp", State: "open", Name: "redis"}}}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	hosts, _ := st.ListHosts(ctx, store.HostFilter{})
	host := hosts.Items[0]
	for _, typ := range []string{"database-exposed", "policy-violation"} {
		t.Run(typ, func(t *testing.T) {
			key := typ + "|10.30.0.7|6379/tcp"
			f := func(seen time.Time) []model.Finding {
				return []model.Finding{{Key: key, Type: typ, Title: "Redis dostępny z sieci", Severity: model.SevHigh, HostID: host.ID,
					IP: "10.30.0.7", Port: 6379, LastSeen: seen, LastRunID: run.ID}}
			}
			id := func() int64 {
				var v int64
				if err := st.Pool().QueryRow(ctx, `SELECT id FROM findings WHERE key = $1`, key).Scan(&v); err != nil {
					t.Fatalf("finding %s: %v", key, err)
				}
				return v
			}
			status := func() model.FindingStatus {
				f, err := st.GetFinding(ctx, id())
				if err != nil {
					t.Fatal(err)
				}
				return f.Status
			}
			reopens := func() int {
				var n int
				_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'finding.reopen' AND entity_id = $1`, strconv.FormatInt(id(), 10)).Scan(&n)
				return n
			}
			set := func(s model.FindingStatus) {
				if _, err := st.PatchFinding(ctx, id(), map[string]json.RawMessage{"status": raw(s)}, "analityk@example.org"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.UpsertFindings(ctx, f(time.Now().Add(-time.Hour))); err != nil {
				t.Fatal(err)
			}
			// Accepted and false positive stay, whatever the scan sees.
			for _, s := range []model.FindingStatus{model.FindingAccepted, model.FindingFalsePositive} {
				set(s)
				_, _ = st.UpsertFindings(ctx, f(time.Now().Add(time.Minute)))
				if got := status(); got != s {
					t.Fatalf("%s was changed by a new observation to %s", s, got)
				}
			}
			// Resolved: an observation older than the resolution (a rule
			// evaluation over unchanged data) does not reopen.
			set(model.FindingResolved)
			_, _ = st.UpsertFindings(ctx, f(time.Now().Add(-10*time.Minute)))
			if got := status(); got != model.FindingResolved {
				t.Fatalf("an older observation reopened the finding: %s", got)
			}
			// A newer observation reopens it once, with an audit entry.
			_, _ = st.UpsertFindings(ctx, f(time.Now().Add(2*time.Minute)))
			if got := status(); got != model.FindingNew || reopens() != 1 {
				t.Fatalf("a newer observation must reopen once: %s, %d audit entries", got, reopens())
			}
			_, _ = st.UpsertFindings(ctx, f(time.Now().Add(3*time.Minute)))
			if reopens() != 1 {
				t.Fatalf("an open finding is not reopened again: %d", reopens())
			}
			// Resolved by the scan (gone), then the same old data again: stays resolved.
			if n, err := st.ResolveFindings(ctx, []int64{id()}); err != nil || n != 1 {
				t.Fatalf("auto resolve: %d %v", n, err)
			}
			_, _ = st.UpsertFindings(ctx, f(time.Now().Add(-5*time.Minute)))
			if got := status(); got != model.FindingResolved || reopens() != 1 {
				t.Fatalf("re-evaluating old data flipped the finding: %s, %d", got, reopens())
			}
		})
	}
}
