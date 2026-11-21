package reprobe

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
	"github.com/iwosmu/aghpen/internal/wire"
)

// world says what each address answers at a time: the fake engine. The
// rest of the path (ingest, histogram, analysis, changes) is the real one.
type world func(ip string, at time.Time) (up bool, svcs []model.ServiceResult)

func web() []model.ServiceResult {
	return []model.ServiceResult{
		{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6"},
		{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.26.1",
			HTTP: &model.HTTPFingerprint{Scheme: "http", Status: 200, Title: "Intranet"}},
	}
}

// runOnce stores one run of the given addresses through the real sink and analysis.
func runOnce(t *testing.T, st *store.Store, an *wire.Analysis, trigger string, at time.Time, ips []string, w world) model.ScanRun {
	t.Helper()
	ctx := context.Background()
	started := at.UTC()
	r, err := st.CreateRun(ctx, model.ScanRun{ProfileName: trigger, Status: model.RunRunning, Trigger: trigger, StartedAt: &started})
	if err != nil {
		t.Fatal(err)
	}
	var res []model.HostResult
	for _, ip := range ips {
		up, svcs := w(ip, at)
		h := model.HostResult{RunID: r.ID, IP: ip, Up: up, ObservedAt: at.UTC(), Attempts: 1, Reason: "syn-ack"}
		if up {
			h.Services = svcs
		} else {
			h.Reason, h.Attempts = "no-response", 3
		}
		res = append(res, h)
	}
	if err := st.IngestHosts(ctx, res, store.SinkOptions{Source: "scan", MarkMissing: true}); err != nil {
		t.Fatal(err)
	}
	sum, err := an.AnalyzeRun(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	fin := at.Add(time.Minute).UTC()
	r.Status, r.FinishedAt, r.Summary = model.RunCompleted, &fin, sum
	if err := st.SaveRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	return r
}

type hostState struct {
	status  string
	buckets int // sum of the histogram
	obs     int // host observations
}

func state(t *testing.T, st *store.Store, ip string) hostState {
	t.Helper()
	var s hostState
	err := st.Pool().QueryRow(context.Background(), `SELECT h.status,
		(SELECT COALESCE(sum(up + down), 0) FROM host_availability a WHERE a.host_id = h.id),
		(SELECT count(*) FROM host_observations o WHERE o.host_id = h.id) FROM hosts h WHERE h.ip = $1`, ip).Scan(&s.status, &s.buckets, &s.obs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func changesOf(t *testing.T, st *store.Store, runID int64) map[string][]string {
	t.Helper()
	rows, err := st.Pool().Query(context.Background(), `SELECT host(ip), kind, expected, summary FROM changes WHERE run_id = $1 ORDER BY id`, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var ip, kind, summary string
		var exp bool
		_ = rows.Scan(&ip, &kind, &exp, &summary)
		k := kind
		if exp {
			k += "(expected)"
		}
		out[ip] = append(out[ip], k)
		t.Logf("  run %d change %-12s %-22s %s", runID, ip, k, summary)
	}
	return out
}

func TestReprobeConfirmationRun(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	loc, _ := time.LoadLocation("Europe/Warsaw")
	an := wire.NewAnalysis(st, loc, slog.New(slog.NewTextHandler(io.Discard, nil)))

	const (
		gone   = "10.66.3.17" // server that dies after the last full scan
		back   = "10.66.3.18" // server that misses the last full scan and comes back
		office = "10.66.20.5" // workstation: up at 10:00 on weekdays, off at night
		excl   = "10.66.9.9"  // server in the exclusions of the policy
	)
	ips := []string{gone, back, office, excl}
	lastFull := time.Date(2026, 11, 14, 2, 0, 0, 0, loc) // Saturday 02:00
	w := func(ip string, at time.Time) (bool, []model.ServiceResult) {
		switch ip {
		case office:
			h, wd := at.In(loc).Hour(), at.In(loc).Weekday()
			return h >= 8 && h < 16 && wd != time.Saturday && wd != time.Sunday, []model.ServiceResult{{Port: 3389, Proto: "tcp", State: "open", Name: "ms-wbt-server"}}
		case gone:
			return at.Before(lastFull), web()
		case back:
			return !at.Equal(lastFull), web()
		default:
			return !at.Equal(lastFull), web()
		}
	}
	// 12 days of full scans: every day at 02:00, on weekdays also at 10:00.
	start := time.Date(2026, 11, 2, 2, 0, 0, 0, loc) // Monday
	for d := 0; d < 12; d++ {
		day := start.AddDate(0, 0, d)
		runOnce(t, st, an, "schedule", day, ips, w)
		if wd := day.Weekday(); wd != time.Saturday && wd != time.Sunday {
			runOnce(t, st, an, "schedule", day.Add(8*time.Hour), ips, w)
		}
	}
	last := runOnce(t, st, an, "schedule", lastFull, ips, w)
	t.Logf("last full run %d at %s:", last.ID, lastFull.Format("Mon 02.01 15:04"))
	full := changesOf(t, st, last.ID)
	if !strings.Contains(strings.Join(full[gone], ","), "host_missing") {
		t.Fatalf("the last full run must report %s as host_missing: %v", gone, full[gone])
	}
	if _, err := st.PutSafetyPolicy(ctx, func() model.SafetyPolicy {
		p, _ := st.GetSafetyPolicy(ctx)
		p.Exclusions = append(p.Exclusions, excl)
		return p
	}()); err != nil {
		t.Fatal(err)
	}

	// The Starter is the runner capability: a targeted run through the normal sink and analysis.
	var requests []Request
	starter := func(ctx context.Context, req Request) (model.ScanRun, error) {
		requests = append(requests, req)
		var tips []string
		for _, x := range req.Targets {
			tips = append(tips, x.IP)
		}
		return runOnce(t, st, an, req.Trigger, clock, tips, w), nil
	}
	b := NewStoreBackend(st, loc, starter, nil)
	if err := b.Init(ctx); err != nil {
		t.Fatal(err)
	}
	e := &Executor{B: b}
	var am, hostsAM string
	_ = st.Pool().QueryRow(ctx, `SELECT (SELECT a.amname::text FROM pg_class c JOIN pg_am a ON a.oid = c.relam WHERE c.relname = 'reprobe_log'),
		(SELECT a.amname::text FROM pg_class c JOIN pg_am a ON a.oid = c.relam WHERE c.relname = 'hosts')`).Scan(&am, &hostsAM)
	t.Logf("reprobe_log access method: %s (hosts: %s)", am, hostsAM)
	if am != hostsAM {
		t.Errorf("reprobe_log uses %s, hosts uses %s", am, hostsAM)
	}

	before := map[string]hostState{}
	for _, ip := range ips {
		before[ip] = state(t, st, ip)
		t.Logf("before: %-11s %+v", ip, before[ip])
	}

	// 11 minutes after the miss: the first confirmation is due.
	clock = lastFull.Add(11 * time.Minute)
	rep, err := e.Step(ctx, clock)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rep.Plan.Probes {
		t.Logf("plan: %-11s %-9s %s  %s", p.IP, p.Kind, p.NotBefore.In(loc).Format("Mon 02.01 15:04"), p.Reason)
	}
	for _, s := range rep.Plan.Skipped {
		t.Logf("skip: %-11s %s", s.IP, s.Reason)
	}
	if len(rep.Started) != 1 || len(requests) != 1 || len(requests[0].Targets) != 2 {
		t.Fatalf("expected one reprobe run for %s and %s, got %+v (errors %v)", gone, back, requests, rep.Errors)
	}
	for _, x := range requests[0].Targets {
		if x.IP == excl || x.IP == office || len(x.Ports) != 2 {
			t.Errorf("target %+v", x)
		}
	}
	runID := rep.Started[0]
	t.Logf("reprobe run %d:", runID)
	ch := changesOf(t, st, runID)

	after := map[string]hostState{}
	for _, ip := range ips {
		after[ip] = state(t, st, ip)
		t.Logf("after:  %-11s %+v", ip, after[ip])
	}
	// The dead server is reported inactive in minutes, not at the next full scan.
	if after[gone].status != "down" || !strings.Contains(strings.Join(ch[gone], ","), "host_gone") {
		t.Errorf("%s: status %s, changes %v; want down and host_gone", gone, after[gone].status, ch[gone])
	}
	if after[back].status != "up" {
		t.Errorf("%s: status %s, want up", back, after[back].status)
	}
	// analyze.Diff emits no host_back for unstable -> up (only after down or
	// expected-offline). Reported to the owner of internal/analyze.
	t.Logf("%s came back: status %s, changes %v", back, after[back].status, ch[back])
	// A confirmation counts as exactly one observation in the histogram.
	for _, ip := range []string{gone, back} {
		if after[ip].buckets != before[ip].buckets+1 || after[ip].obs != before[ip].obs+1 {
			t.Errorf("%s: histogram %d -> %d, observations %d -> %d; want +1", ip, before[ip].buckets, after[ip].buckets, before[ip].obs, after[ip].obs)
		}
	}
	if after[office] != before[office] || after[excl] != before[excl] {
		t.Errorf("hosts outside the plan changed: %+v %+v", after[office], after[excl])
	}
	var logged int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM reprobe_log WHERE run_id = $1`, runID).Scan(&logged)
	if logged != 2 {
		t.Errorf("reprobe_log rows = %d", logged)
	}

	// One minute later: nothing is due (gone is down, back is up).
	clock = clock.Add(time.Minute)
	rep, _ = e.Step(ctx, clock)
	if len(rep.Started) != 0 {
		t.Errorf("second step started %v", rep.Started)
	}

	// The workstation: probed at the start of its next likely-up hour.
	var officeProbe *Probe
	for i, p := range rep.Plan.Probes {
		if p.IP == office {
			officeProbe = &rep.Plan.Probes[i]
		}
	}
	if officeProbe == nil || officeProbe.Kind != KindLikelyUp {
		t.Fatalf("no likely-up probe for the workstation: %+v %+v", rep.Plan.Probes, rep.Plan.Skipped)
	}
	t.Logf("workstation probe: %s  %s", officeProbe.NotBefore.In(loc).Format("Mon 02.01 15:04"), officeProbe.Reason)
	if wd := officeProbe.NotBefore.In(loc).Weekday(); wd != time.Monday {
		t.Errorf("workstation probe on %s, want Monday", wd)
	}

	// Emergency stop: the due probe does not start.
	clock = officeProbe.NotBefore
	if _, err := st.SetEmergencyStop(ctx, true); err != nil {
		t.Fatal(err)
	}
	rep, _ = e.Step(ctx, clock)
	if len(rep.Started) != 0 || !strings.Contains(rep.Plan.Blocked, "awaryjny") {
		t.Fatalf("emergency stop: started %v blocked %q", rep.Started, rep.Plan.Blocked)
	}
	if _, err := st.SetEmergencyStop(ctx, false); err != nil {
		t.Fatal(err)
	}
	ob := state(t, st, office)
	rep, _ = e.Step(ctx, clock)
	if len(rep.Started) != 1 {
		t.Fatalf("workstation probe did not start: %+v", rep)
	}
	t.Logf("likely-up run %d:", rep.Started[0])
	ch = changesOf(t, st, rep.Started[0])
	oa := state(t, st, office)
	if oa.status != "up" || !strings.Contains(strings.Join(ch[office], ","), "host_back") || oa.buckets != ob.buckets+1 {
		t.Errorf("workstation: %+v -> %+v, changes %v; want up, host_back, +1 observation", ob, oa, ch[office])
	}

	// HTTP routes.
	r := chi.NewRouter()
	svc := &Service{B: b, Now: func() time.Time { return clock }}
	svc.Register(r, func(model.Permission) func(http.Handler) http.Handler {
		return func(h http.Handler) http.Handler { return h }
	})
	srv := httptest.NewServer(r)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/reprobe/plan")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET /reprobe/plan: %v %v", err, resp)
	}
	var plan Plan
	_ = json.NewDecoder(resp.Body).Decode(&plan)
	resp.Body.Close()
	t.Logf("GET /reprobe/plan: enabled=%v budget=%d used_last_hour=%d probes=%d skipped=%d", plan.Enabled, plan.Budget, plan.UsedLastHour, len(plan.Probes), len(plan.Skipped))
	if plan.UsedLastHour != 1 {
		t.Errorf("used last hour = %d, want 1 (the workstation probe)", plan.UsedLastHour)
	}
	put := func(body string) (int, string) {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/settings/reprobe", strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := put(`{"budget_per_hour": 50, "backoff_minutes": [5, 15]}`); code != 200 || !strings.Contains(body, `"budget_per_hour":50`) || !strings.Contains(body, `"enabled":true`) {
		t.Errorf("PUT settings: %d %s", code, body)
	}
	if code, body := put(`{"backoff_minutes": [30, 10]}`); code != 422 {
		t.Errorf("PUT invalid settings: %d %s", code, body)
	}
	if code, _ := put(`{"enabled": false}`); code != 200 {
		t.Errorf("PUT disable: %d", code)
	}
	rep, _ = e.Step(ctx, clock.Add(24*time.Hour))
	if !strings.Contains(rep.Plan.Blocked, "wyłączone") {
		t.Errorf("disabled: %q", rep.Plan.Blocked)
	}
}

// clock is the time of the fake engine in TestReprobeConfirmationRun.
var clock time.Time
