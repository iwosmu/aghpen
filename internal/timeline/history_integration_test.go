package timeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
	"github.com/iwosmu/aghpen/internal/wire"
)

// The history: 2 000 hosts, 30 daily runs at 02:00 Warsaw time.
//
//	i%20 in 0..13  server: always up; 22/ssh, 80/http (nginx), every third 443/https
//	i%20 in 14..16 workstation: up on weekdays only
//	i%20 in 17..18 flaky: up in about 60% of the runs
//	i%20 == 19     decommissioned: up in runs 0..19, silent after
//	i >= 1900      new: first answers in run 25
//	i%5 == 0       nginx 1.24.0 -> 1.26.1 from run 15
//	i%50 == 0      admin panel (Jenkins) on 8080 from run 10
//	i%40 == 1      mysql on 3306 in runs 0..17 only
const (
	histHosts = 2000
	histRuns  = 30
)

func histIP(i int) string { return fmt.Sprintf("10.70.%d.%d", i/250, i%250+1) }

func histUp(i, run int, at time.Time) bool {
	if i >= 1900 && run < 25 {
		return false
	}
	switch k := i % 20; {
	case k <= 13:
		return true
	case k <= 16:
		wd := at.Weekday()
		return wd != time.Saturday && wd != time.Sunday
	case k <= 18:
		return (i*31+run*17)%10 < 6
	default:
		return run < 20
	}
}

func httpSvc(port int, title, product, version string, tls bool) model.ServiceResult {
	s := model.ServiceResult{Port: port, Proto: "tcp", State: "open", Name: "http", Product: product, Version: version, Confidence: 0.9,
		HTTP: &model.HTTPFingerprint{Scheme: "http", URL: "http://x/", Status: 200, Title: title,
			Headers: map[string][]string{"Server": {product + "/" + version}, "Date": {"x"}, "Content-Type": {"text/html"}}},
		Technologies: []model.Technology{{Name: product, Category: model.CatWebServer, Version: version, Confidence: 0.9, Sources: []string{"nmap"}}}}
	if tls {
		s.Name, s.Tunnel, s.HTTP.Scheme = "https", "ssl", "https"
	}
	return s
}

func histServices(i, run int) []model.ServiceResult {
	k := i % 20
	ver := "1.24.0"
	if i%5 == 0 && run >= 15 {
		ver = "1.26.1"
	}
	switch {
	case k >= 14 && k <= 16:
		return []model.ServiceResult{{Port: 3389, Proto: "tcp", State: "open", Name: "ms-wbt-server", Confidence: 0.8}}
	case k == 17 || k == 18:
		return []model.ServiceResult{httpSvc(80, "Drukarka", "lighttpd", "1.4.59", false)}
	}
	out := []model.ServiceResult{
		{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "8.9p1", Confidence: 0.9},
		httpSvc(80, fmt.Sprintf("Strona %d", i%7), "nginx", ver, false),
	}
	if i%3 == 0 {
		s := httpSvc(443, fmt.Sprintf("Strona %d", i%7), "nginx", ver, true)
		sum := sha256.Sum256([]byte(histIP(i)))
		if i%9 == 0 && run >= 20 {
			sum = sha256.Sum256([]byte(histIP(i) + "/renewed")) // certificate renewed
		}
		sha := hex.EncodeToString(sum[:])
		s.TLS = &model.TLSInfo{Version: "TLS1.3", SubjectCN: histIP(i), SHA256: sha, NotAfter: time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)}
		out = append(out, s)
	}
	if i%50 == 0 && run >= 10 {
		s := httpSvc(8080, "Dashboard [Jenkins]", "Jetty", "10.0.13", false)
		s.Technologies = append(s.Technologies, model.Technology{Name: "Jenkins", Category: model.CatDevOps, Confidence: 0.95, Sources: []string{"jenkins"}})
		s.Classes = []string{model.ClassAdminPanel, model.ClassDevTool}
		out = append(out, s)
	}
	if i%40 == 1 && run < 18 {
		out = append(out, model.ServiceResult{Port: 3306, Proto: "tcp", State: "open", Name: "mysql", Product: "MySQL", Version: "8.0.36", Confidence: 0.9})
	}
	return out
}

// loadHistory writes the history through the real ingest and the real
// analysis (internal/wire.Analysis), one run at a time, as the runner does.
func loadHistory(t testing.TB, st *store.Store, loc *time.Location) []int64 {
	ctx := context.Background()
	an := wire.NewAnalysis(st, loc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	base := time.Date(2026, 10, 1, 2, 0, 0, 0, loc)
	var ids []int64
	began := time.Now()
	for run := 0; run < histRuns; run++ {
		at := base.AddDate(0, 0, run)
		started := at.UTC()
		r, err := st.CreateRun(ctx, model.ScanRun{ProfileName: "kampus", Status: model.RunRunning, Trigger: "schedule", StartedAt: &started})
		if err != nil {
			t.Fatal(err)
		}
		res := make([]model.HostResult, 0, histHosts)
		for i := 0; i < histHosts; i++ {
			if i >= 1900 && run < 25 {
				continue // not known yet: the engine reports nothing
			}
			obsAt := at.Add(time.Duration(i) * 500 * time.Millisecond).UTC()
			h := model.HostResult{RunID: r.ID, IP: histIP(i), Up: histUp(i, run, at), ObservedAt: obsAt, Attempts: 1}
			if h.Up {
				h.Reason, h.RTTMs, h.Services = "syn-ack", 1.5, histServices(i, run)
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
		fin := at.Add(20 * time.Minute).UTC()
		r.Status, r.FinishedAt, r.Summary = model.RunCompleted, &fin, sum
		if err := st.SaveRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	t.Logf("history loaded: %d runs x %d hosts in %s", histRuns, histHosts, time.Since(began).Round(time.Millisecond))
	return ids
}

func passthrough(model.Permission) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler { return h }
}

type timing struct {
	route string
	ms    []float64
	bytes int
}

func TestTimelineHistory(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	loc, _ := time.LoadLocation("Europe/Warsaw")
	runs := loadHistory(t, st, loc)

	var nHostObs, nSvcObs, nHosts, nSvcs, nChanges, nFindings int
	_ = st.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM host_observations), (SELECT count(*) FROM service_observations),
		(SELECT count(*) FROM hosts), (SELECT count(*) FROM services), (SELECT count(*) FROM changes), (SELECT count(*) FROM findings)`).
		Scan(&nHostObs, &nSvcObs, &nHosts, &nSvcs, &nChanges, &nFindings)
	t.Logf("data: %d host observations, %d service observations (%d together), %d hosts, %d services, %d changes, %d findings",
		nHostObs, nSvcObs, nHostObs+nSvcObs, nHosts, nSvcs, nChanges, nFindings)
	if nHostObs+nSvcObs < 100_000 {
		t.Fatalf("history too small: %d observations", nHostObs+nSvcObs)
	}

	tl := New(st, nil)
	r := chi.NewRouter()
	tl.Register(r, passthrough)
	srv := httptest.NewServer(r)
	defer srv.Close()

	get := func(path string, v any) (float64, int) {
		t.Helper()
		start := time.Now()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ms := float64(time.Since(start).Microseconds()) / 1000
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		if v != nil {
			if err := json.Unmarshal(body, v); err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
		}
		return ms, len(body)
	}

	mid := runs[5]   // before decommissioning, before the admin panels
	late := runs[12] // admin panels exist
	host19 := int64(0)
	_ = st.Pool().QueryRow(ctx, `SELECT id FROM hosts WHERE ip = $1`, histIP(19)).Scan(&host19)
	svcVer := int64(0) // nginx on host 0 port 80 changes version at run 15
	_ = st.Pool().QueryRow(ctx, `SELECT s.id FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.ip = $1 AND s.port = 80`, histIP(0)).Scan(&svcVer)
	svcCert := int64(0) // https on host 9: certificate renewed at run 20
	_ = st.Pool().QueryRow(ctx, `SELECT s.id FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.ip = $1 AND s.port = 443`, histIP(9)).Scan(&svcCert)
	atTime := url.QueryEscape(time.Date(2026, 10, 8, 12, 0, 0, 0, loc).Format(time.RFC3339)) // between runs 7 and 8

	routes := []string{
		"/timeline",
		fmt.Sprintf("/timeline/at?run_id=%d", mid),
		fmt.Sprintf("/timeline/at?run_id=%d&limit=50&offset=1000", late),
		"/timeline/at?at=" + atTime,
		fmt.Sprintf("/timeline/at/hosts?run_id=%d&status=up&cidr=10.70.1.0/24", mid),
		fmt.Sprintf("/timeline/at/hosts?run_id=%d&port=8080", late),
		fmt.Sprintf("/timeline/at/services?run_id=%d&tech=Jenkins", late),
		fmt.Sprintf("/timeline/at/services?run_id=%d&class=admin-panel&sort=-port", late),
		fmt.Sprintf("/timeline/at/services?run_id=%d&q=nginx&limit=200&offset=2000", mid),
		fmt.Sprintf("/timeline/at/findings?run_id=%d", late),
		fmt.Sprintf("/timeline/hosts/%d", host19),
		fmt.Sprintf("/timeline/services/%d", svcVer),
	}
	measure := func(label string) []timing {
		var out []timing
		for _, p := range routes {
			tm := timing{route: p}
			for k := 0; k < 3; k++ {
				ms, n := get(p, nil)
				tm.ms, tm.bytes = append(tm.ms, ms), n
			}
			out = append(out, tm)
		}
		for _, tm := range out {
			s := append([]float64(nil), tm.ms...)
			sort.Float64s(s)
			t.Logf("[%s] %-80s first %7.1f ms  median %7.1f ms  %7d bytes", label, tm.route, tm.ms[0], s[1], tm.bytes)
		}
		return out
	}
	tl.mu.Lock()
	tl.cache = nil
	tl.mu.Unlock()
	measure("stock indexes")
	explain(t, st, late, "stock indexes")

	if err := tl.Start(ctx); err != nil {
		t.Fatal(err)
	}
	_, _ = st.Pool().Exec(ctx, `ANALYZE`)
	tl.mu.Lock()
	tl.cache = nil
	tl.mu.Unlock()
	after := measure("with timeline indexes")
	explain(t, st, late, "with timeline indexes")
	for _, tm := range after {
		s := append([]float64(nil), tm.ms...)
		sort.Float64s(s)
		if s[1] > 1500 {
			t.Errorf("%s: median %.0f ms is too slow", tm.route, s[1])
		}
	}

	// ---- correctness on known facts of the history ----
	var sc Scrubber
	get("/timeline", &sc)
	if len(sc.Runs) != histRuns {
		t.Fatalf("scrubber runs = %d", len(sc.Runs))
	}
	first, last := sc.Runs[0], sc.Runs[histRuns-1]
	t.Logf("scrubber run 1: %+v", first)
	t.Logf("scrubber run 30: %+v", last)
	if last.HostsDown < 90 || last.HostsDown > 100 {
		t.Errorf("decommissioned hosts reported down by run 30: %d, want about 95", last.HostsDown)
	}
	if first.HostsDown != 0 || first.Probed != 1900 {
		t.Errorf("run 1: down %d probed %d", first.HostsDown, first.Probed)
	}
	// As of the last run the counts must equal the live inventory.
	var liveOpen, liveUnknown int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'open'), count(*) FILTER (WHERE state = 'unknown') FROM services`).Scan(&liveOpen, &liveUnknown)
	if last.ServicesOpen+last.ServicesUnknown != liveOpen+liveUnknown {
		t.Errorf("run 30: open %d + unknown %d, live inventory: open %d + unknown %d", last.ServicesOpen, last.ServicesUnknown, liveOpen, liveUnknown)
	}
	var n2 int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM changes WHERE run_id = $1`, runs[1]).Scan(&n2)
	if sc.Runs[1].Changes != n2 {
		t.Errorf("changes of run 2: scrubber %d, table %d", sc.Runs[1].Changes, n2)
	}
	if last.FindingsOpen == 0 || last.ChangesByKind == nil {
		t.Errorf("run 30: findings %d changes %v", last.FindingsOpen, last.ChangesByKind)
	}

	var snap Snapshot
	get(fmt.Sprintf("/timeline/at?run_id=%d&cidr=%s/32", mid, histIP(19)), &snap)
	if snap.Run.ID != mid || snap.Hosts.Total != 1 || snap.Hosts.Items[0].Status != "up" || snap.Hosts.Items[0].StatusNow != "down" {
		t.Errorf("host 19 at run 6: %+v", snap.Hosts)
	}
	t.Logf("summary at run 6: %+v", snap.Summary)
	if snap.Summary.Diff.ServicesGoneSince == 0 || snap.Summary.Diff.ServicesNewSince == 0 || snap.Summary.Diff.ServicesChanged == 0 {
		t.Errorf("diff to now at run 6: %+v", snap.Summary.Diff)
	}
	for _, s := range snap.Summary.Diff.Sentences {
		t.Logf("  zdanie: %s", s)
	}

	var jen Page[AtService]
	get(fmt.Sprintf("/timeline/at/services?run_id=%d&tech=Jenkins", mid), &jen)
	if jen.Total != 0 {
		t.Errorf("Jenkins at run 6: %d, want 0", jen.Total)
	}
	get(fmt.Sprintf("/timeline/at/services?run_id=%d&tech=Jenkins", late), &jen)
	if jen.Total != 38 { // i%50 == 0 below 1900: 38 hosts, all servers (i%20 is 0 or 10)
		t.Errorf("Jenkins at run 13: %d, want 38", jen.Total)
	}
	if jen.Total == 0 || len(jen.Items[0].Classes) == 0 {
		t.Errorf("Jenkins at run 13: %+v", jen)
	}

	// A service not probed in a run keeps its last earlier observation:
	// mysql of host 1 at run 18 shows the observation of run 18 (index 17); at run 19 it is gone.
	var my Page[AtService]
	get(fmt.Sprintf("/timeline/at/services?run_id=%d&host_id=0&port=3306&cidr=%s/32&state=all", runs[18], histIP(1)), &my)
	if my.Total != 1 || my.Items[0].State != "gone" {
		t.Errorf("mysql of host 1 at run 19: %+v", my)
	}

	// at= picks the last run at or before the time.
	get("/timeline/at?at="+atTime+"&limit=1", &snap)
	if snap.Run.ID != runs[7] {
		t.Errorf("at=2026-10-08T12:00 resolved to run %d, want %d", snap.Run.ID, runs[7])
	}

	var life HostLife
	get(fmt.Sprintf("/timeline/hosts/%d", host19), &life)
	var states []string
	for _, iv := range life.Host {
		states = append(states, iv.State+"/"+iv.Status)
	}
	t.Logf("host %s lanes: %s; services: %d", life.IP, strings.Join(states, " -> "), len(life.Services))
	if len(life.Host) < 3 || life.Host[0].State != "up" || life.Host[len(life.Host)-1].State != "down" {
		t.Errorf("host 19 lanes: %+v", life.Host)
	}
	for _, l := range life.Services {
		if len(l.Intervals) == 0 || l.Intervals[0].State != "open" {
			t.Errorf("service lane %d: %+v", l.Port, l.Intervals)
		}
	}
	var hist ServiceHistory
	get(fmt.Sprintf("/timeline/services/%d", svcVer), &hist)
	t.Logf("service history %s:%d: %d observations, changed %+v", hist.IP, hist.Port, hist.Observations, hist.Changed)
	if len(hist.Changed) == 0 || hist.Changed[0].Field != "version" || hist.Changed[0].Values[1].Value != "nginx 1.26.1" {
		t.Errorf("version history: %+v", hist.Changed)
	}
	get(fmt.Sprintf("/timeline/services/%d", svcCert), &hist)
	found := false
	for _, c := range hist.Changed {
		if c.Field == "certificate" && len(c.Values) == 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("certificate renewal not in history: %+v %+v", hist.Changed, hist.Unchanged)
	}
}

// explain prints the plan of the heaviest statement: a page of services at a run.
func explain(t *testing.T, st *store.Store, run int64, label string) {
	rows, err := st.Pool().Query(context.Background(), `EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY ON) SELECT s.id, `+svcStateThen+`, count(*) OVER () `+svcAsOf+` WHERE `+svcStateThen+` = ANY('{open,unknown}') ORDER BY s.ip, s.port LIMIT 50`, run)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for rows.Next() {
		var l string
		_ = rows.Scan(&l)
		lines = append(lines, l)
	}
	rows.Close()
	t.Logf("[%s] EXPLAIN services-at-run page:\n%s", label, strings.Join(lines, "\n"))
}
