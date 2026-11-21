package rules_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/rules"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

func httpSvc(port int, scheme, title string, classes ...string) model.ServiceResult {
	sv := model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http", Classes: classes,
		HTTP: &model.HTTPFingerprint{Scheme: scheme, URL: fmt.Sprintf("%s://x:%d/", scheme, port), Status: 200, Title: title,
			Headers: map[string][]string{"Server": {"nginx"}}}}
	if scheme == "https" {
		sv.Tunnel = "ssl"
	}
	return sv
}

func ingest(t testing.TB, st *store.Store, hosts []model.HostResult) int64 {
	t.Helper()
	ctx := context.Background()
	run, err := st.CreateRun(ctx, model.ScanRun{Status: model.RunRunning, ProfileName: "policy-test"})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	for i := range hosts {
		hosts[i].RunID, hosts[i].ObservedAt, hosts[i].Up = run.ID, at, true
	}
	if err := st.IngestHosts(ctx, hosts, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
		t.Fatal(err)
	}
	return run.ID
}

func findings(t *testing.T, st *store.Store) map[string]model.Finding {
	t.Helper()
	out := map[string]model.Finding{}
	if err := st.EachFinding(context.Background(), store.FindingFilter{Type: rules.FindingType}, func(f *model.Finding) error {
		out[f.Key] = *f
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEvaluateStoresAndResolvesViolations(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := rules.New(st, nil)
	svc.EvalOnChange = false
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(ctx); err != nil { // idempotent
		t.Fatal(err)
	}
	var amF, amR string
	if err := st.Pool().QueryRow(ctx, `SELECT (SELECT a.amname::text FROM pg_class c JOIN pg_am a ON a.oid = c.relam WHERE c.oid = 'findings'::regclass),
		(SELECT a.amname::text FROM pg_class c JOIN pg_am a ON a.oid = c.relam WHERE c.oid = 'policy_rules'::regclass)`).Scan(&amF, &amR); err != nil {
		t.Fatal(err)
	}
	t.Logf("access method: findings=%s policy_rules=%s", amF, amR)
	if amF != amR {
		t.Fatalf("policy_rules uses %s, findings uses %s", amR, amF)
	}
	list, err := svc.List(ctx)
	if err != nil || len(list) < 12 {
		t.Fatalf("seeded %d rules, err %v", len(list), err)
	}
	expired := httpSvc(443, "https", "Intranet")
	expired.TLS = &model.TLSInfo{SubjectCN: "intra.test", NotAfter: time.Now().Add(-48 * time.Hour), Expired: true}
	mysql := model.ServiceResult{Port: 3306, Proto: "tcp", State: "open", Name: "mysql", Product: "MySQL"}
	run1 := ingest(t, st, []model.HostResult{
		{IP: "10.66.1.10", Services: []model.ServiceResult{httpSvc(8080, "http", "Panel administracyjny", model.ClassAdminPanel, model.ClassLogin), expired}},
		{IP: "10.66.1.11", Services: []model.ServiceResult{mysql}},
		{IP: "10.66.1.12", Services: []model.ServiceResult{httpSvc(80, "http", "Strona")}},
	})
	rep, err := svc.Evaluate(ctx, run1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first evaluation: %+v", rep)
	got := findings(t, st)
	want := []string{
		"policy-violation|admin-panel-outside-mgmt|10.66.1.10|8080/tcp",
		"policy-violation|login-over-plain-http|10.66.1.10|8080/tcp",
		"policy-violation|tls-certificate-expired|10.66.1.10|443/tcp",
		"policy-violation|database-port-exposed|10.66.1.11|3306/tcp",
	}
	for _, k := range want {
		f, ok := got[k]
		if !ok {
			t.Fatalf("missing finding %s; have %v", k, keys(got))
		}
		if f.Status != model.FindingNew || f.LastRunID != run1 || len(f.Evidence) < 2 || f.HostID == 0 {
			t.Fatalf("bad finding %s: %+v", k, f)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %v", len(got), len(want), keys(got))
	}
	if rep.Created != len(want) {
		t.Fatalf("created %d", rep.Created)
	}
	// The per-rule counters follow the evaluation.
	list, _ = svc.List(ctx)
	for _, r := range list {
		if r.Slug == "database-port-exposed" && (r.Violations != 1 || r.LastEvalAt == nil) {
			t.Fatalf("counter not stored: %+v", r)
		}
	}

	// The analyst triages one finding with a note and a changed severity.
	adm := got[want[0]]
	patch := map[string]json.RawMessage{"status": json.RawMessage(`"triaged"`), "note": json.RawMessage(`"znamy, VPN w drodze"`), "severity": json.RawMessage(`"low"`)}
	if _, err := st.PatchFinding(ctx, adm.ID, patch, "analityk"); err != nil {
		t.Fatal(err)
	}
	// Second scan: the panel and the database are gone, the certificate stays.
	run2 := ingest(t, st, []model.HostResult{
		{IP: "10.66.1.10", Services: []model.ServiceResult{expired}},
		{IP: "10.66.1.11", Services: []model.ServiceResult{httpSvc(80, "http", "Nowa")}},
		{IP: "10.66.1.12", Services: []model.ServiceResult{httpSvc(80, "http", "Strona")}},
	})
	rep, err = svc.Evaluate(ctx, run2)
	if err != nil {
		t.Fatal(err)
	}
	got = findings(t, st)
	if f := got[want[0]]; f.Status != model.FindingTriaged || f.Note != "znamy, VPN w drodze" || f.Severity != model.SevLow {
		t.Fatalf("analyst-owned fields changed: %+v", f)
	}
	if f := got[want[1]]; f.Status != model.FindingResolved {
		t.Fatalf("gone violation not resolved: %+v", f)
	}
	if f := got[want[3]]; f.Status != model.FindingResolved {
		t.Fatalf("gone database not resolved: %+v", f)
	}
	if f := got[want[2]]; f.Status != model.FindingNew || f.LastRunID != run2 {
		t.Fatalf("persisting violation not refreshed: %+v", f)
	}
	if rep.Resolved != 2 {
		t.Fatalf("resolved %d, want 2 (the triaged one stays)", rep.Resolved)
	}
	// Third scan: the database comes back; the resolved finding is reopened.
	run3 := ingest(t, st, []model.HostResult{{IP: "10.66.1.11", Services: []model.ServiceResult{mysql}}})
	if _, err := svc.Evaluate(ctx, run3); err != nil {
		t.Fatal(err)
	}
	if f := findings(t, st)[want[3]]; f.Status != model.FindingNew {
		t.Fatalf("returning violation not reopened: %+v", f)
	}

	// Disabling a rule resolves its open findings at the next evaluation.
	for _, r := range list {
		if r.Slug == "tls-certificate-expired" {
			off := false
			if _, _, err := svc.Update(ctx, r.ID, nil, &off); err != nil {
				t.Fatal(err)
			}
			if _, _, err := svc.Update(ctx, r.ID, ptr("id: x\nmatch: {port: 1}"), nil); err == nil {
				t.Fatal("a built-in rule must not be editable")
			}
			if err := svc.Delete(ctx, r.ID); err == nil {
				t.Fatal("a built-in rule must not be deletable")
			}
		}
	}
	if _, err := svc.Evaluate(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if f := findings(t, st)[want[2]]; f.Status != model.FindingResolved {
		t.Fatalf("finding of a disabled rule not resolved: %+v", f)
	}
}

func ptr[T any](v T) *T { return &v }

func keys(m map[string]model.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestHTTPRoutes(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := rules.New(st, nil)
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ingest(t, st, []model.HostResult{
		{IP: "10.66.2.1", Services: []model.ServiceResult{httpSvc(80, "http", "Index of /", model.ClassDirListing)}},
		{IP: "10.66.2.2", Services: []model.ServiceResult{httpSvc(80, "http", "Index of /", model.ClassDirListing)}},
	})
	var checked []model.Permission
	can := func(p model.Permission) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { checked = append(checked, p); next.ServeHTTP(w, r) })
		}
	}
	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) { r.Mount("/rules", svc.Router(can)) })
	srv := httptest.NewServer(r)
	defer srv.Close()
	do := func(method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, srv.URL+"/api/v1/rules"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	code, out := do("POST", "/dry-run", `{"yaml":"id: listing\nmatch: {title: '^Index of'}"}`)
	if code != 200 || out["total"].(float64) != 2 || !strings.Contains(out["message"].(string), "zgłosiłaby dziś 2 naruszenia") {
		t.Fatalf("dry run: %d %v", code, out)
	}
	if n := len(findings(t, st)); n != 0 {
		t.Fatalf("dry run stored %d findings", n)
	}
	code, out = do("POST", "/validate", `{"yaml":"id: x\nmatch: {port: abc}"}`)
	if code != 200 || out["ok"].(bool) {
		t.Fatalf("validate: %d %v", code, out)
	}
	code, out = do("POST", "/", `{"yaml":"id: x\nmatch: {port: abc}"}`)
	if code != 422 {
		t.Fatalf("create invalid: %d %v", code, out)
	}
	code, out = do("POST", "/", `{"yaml":"id: no-http-80\nseverity: low\nmatch: {port: 80}"}`)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id := int64(out["rule"].(map[string]any)["id"].(float64))
	if code, _ = do("POST", "/", `{"yaml":"id: no-http-80\nmatch: {port: 80}"}`); code != 409 {
		t.Fatalf("duplicate id: %d", code)
	}
	svc.Wait() // the background evaluation after the change
	code, out = do("GET", fmt.Sprintf("/%d/violations", id), "")
	if code != 200 || out["total"].(float64) != 2 {
		t.Fatalf("violations: %d %v", code, out)
	}
	code, out = do("POST", "/evaluate", "")
	if code != 200 || out["violations"].(float64) < 4 { // 2 x no-http-80, 2 x directory-listing
		t.Fatalf("evaluate: %d %v", code, out)
	}
	if code, _ = do("PATCH", fmt.Sprintf("/%d", id), `{"enabled": false}`); code != 200 {
		t.Fatalf("patch: %d", code)
	}
	if code, _ = do("DELETE", fmt.Sprintf("/%d", id), ""); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	code, out = do("GET", "/", "")
	if code != 200 || out["total"].(float64) < 14 {
		t.Fatalf("list: %d %v", code, out)
	}
	svc.Wait()
	seen := map[model.Permission]bool{}
	for _, p := range checked {
		seen[p] = true
	}
	for _, p := range []model.Permission{model.PermResultsRead, model.PermResultsUpdate, model.PermSignaturesCreate, model.PermSignaturesUpdate, model.PermSignaturesDelete} {
		if !seen[p] {
			t.Errorf("permission %s never checked", p)
		}
	}
}

// TestScale2000Hosts measures a dry run and a full evaluation on an inventory
// of 2 000 hosts with 3 services each (run with -v to see the timings).
func TestScale2000Hosts(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := rules.New(st, nil)
	svc.EvalOnChange = false
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	const n = 2000
	hosts := make([]model.HostResult, 0, n)
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.70.%d.%d", i/250, i%250+1)
		web := httpSvc(80, "http", fmt.Sprintf("Serwer %d", i))
		if i%10 == 0 {
			web.Classes = []string{model.ClassAdminPanel, model.ClassLogin}
		}
		tlsSvc := httpSvc(443, "https", "Portal")
		tlsSvc.TLS = &model.TLSInfo{SubjectCN: ip, NotAfter: time.Now().Add(time.Duration(i%60-5) * 24 * time.Hour)}
		other := model.ServiceResult{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH"}
		if i%25 == 0 {
			other = model.ServiceResult{Port: 5432, Proto: "tcp", State: "open", Name: "postgresql"}
		}
		hosts = append(hosts, model.HostResult{IP: ip, Services: []model.ServiceResult{web, tlsSvc, other}})
	}
	t0 := time.Now()
	run := ingest(t, st, hosts)
	t.Logf("ingest of %d hosts x 3 services: %s", n, time.Since(t0).Round(time.Millisecond))

	dr, err := svc.DryRun(ctx, "id: adm\nmatch: {class: admin-panel}", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dry run: %d violations, %d hosts, %d services, took %d ms; %s", dr.Total, dr.Hosts, dr.Services, dr.TookMs, dr.Message)
	if dr.Total != n/10 || dr.Hosts != n || dr.Services != 3*n {
		t.Fatalf("dry run: %+v", dr)
	}
	rep, err := svc.Evaluate(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first evaluation (all inserts): rules=%d violations=%d created=%d eval=%d ms store=%d ms total=%d ms by_rule=%v",
		rep.Rules, rep.Violations, rep.Created, rep.EvalMs, rep.StoreMs, rep.TookMs, rep.ByRule)
	rep2, err := svc.Evaluate(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("second evaluation (no change): violations=%d created=%d resolved=%d eval=%d ms store=%d ms total=%d ms",
		rep2.Violations, rep2.Created, rep2.Resolved, rep2.EvalMs, rep2.StoreMs, rep2.TookMs)
	if rep2.Created != 0 || rep2.Resolved != 0 || rep2.Violations != rep.Violations {
		t.Fatalf("second evaluation must be a no-op: %+v", rep2)
	}
}

// The reopen rule for policy findings: an analyst's "resolved" survives
// evaluations over unchanged data; a new scan that sees the cause reopens it
// once (with an audit entry); accepted and false positive are never reopened.
func TestPolicyFindingReopenRule(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	svc := rules.New(st, nil)
	svc.EvalOnChange = false
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	mysql := model.ServiceResult{Port: 3306, Proto: "tcp", State: "open", Name: "mysql", Product: "MySQL"}
	key := "policy-violation|database-port-exposed|10.66.2.11|3306/tcp"
	scan := func() {
		t.Helper()
		run := ingest(t, st, []model.HostResult{{IP: "10.66.2.11", Services: []model.ServiceResult{mysql}}})
		if _, err := svc.Evaluate(ctx, run); err != nil {
			t.Fatal(err)
		}
	}
	get := func() model.Finding {
		t.Helper()
		f, ok := findings(t, st)[key]
		if !ok {
			t.Fatalf("no finding %s", key)
		}
		return f
	}
	set := func(s model.FindingStatus) {
		t.Helper()
		if _, err := st.PatchFinding(ctx, get().ID, map[string]json.RawMessage{"status": json.RawMessage(`"` + string(s) + `"`)}, "analityk"); err != nil {
			t.Fatal(err)
		}
	}
	reopens := func() int {
		var n int
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'finding.reopen' AND entity_id = $1`, fmt.Sprint(get().ID)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	scan()
	set(model.FindingResolved)
	for i := 0; i < 3; i++ { // rule evaluations without a new observation
		if _, err := svc.Evaluate(ctx, 0); err != nil {
			t.Fatal(err)
		}
	}
	if f := get(); f.Status != model.FindingResolved || reopens() != 0 {
		t.Fatalf("an evaluation over unchanged data reopened the finding: %s, %d", f.Status, reopens())
	}
	time.Sleep(10 * time.Millisecond) // the new scan observes after the resolution
	scan()
	if f := get(); f.Status != model.FindingNew || reopens() != 1 {
		t.Fatalf("a new observation must reopen once: %s, %d", f.Status, reopens())
	}
	if _, err := svc.Evaluate(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if reopens() != 1 {
		t.Fatalf("reopened again without a resolution: %d", reopens())
	}
	for _, s := range []model.FindingStatus{model.FindingAccepted, model.FindingFalsePositive} {
		set(s)
		time.Sleep(10 * time.Millisecond)
		scan()
		if f := get(); f.Status != s {
			t.Fatalf("%s was changed by a scan to %s", s, f.Status)
		}
	}
}
