package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/interchange"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// upload sends one file as multipart/form-data with extra form fields.
func (c *client) upload(path, name string, data []byte, fields map[string]string) (*http.Response, []byte) {
	c.e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("file", name)
	_, _ = fw.Write(data)
	mw.Close()
	return c.raw("POST", path, &buf, map[string]string{auth.CSRFHeader: c.csrf, "Content-Type": mw.FormDataContentType()})
}

func noZeroTime(t *testing.T, what string, raw []byte) {
	t.Helper()
	if bytes.Contains(raw, []byte("0001-01-01")) {
		t.Errorf("%s: a zero time leaked into the JSON: %s", what, raw)
	}
}

func TestManualEntryFindingsRunNotesAndAdHoc(t *testing.T) {
	e := setup(t, func(d *Deps) { d.Importer = testImporter{} })
	admin := e.login("admin@example.org", adminPW)
	u := e.users(admin)

	// ---- manual entry: a host with services ----
	var got ManualEntryResult
	admin.want(201, "POST", "/api/v1/hosts", map[string]any{"ip": "10.70.0.9", "hostnames": []string{"Panel.Lab"},
		"services": []map[string]any{{"port": 8080, "name": "http", "title": "Panel administracyjny", "product": "Jetty"}}}, &got)
	if got.Run.Trigger != runner.TriggerManualEntry || got.Run.Status != model.RunCompleted || got.Host.IP != "10.70.0.9" || got.Host.Status != model.HostUp {
		t.Fatalf("manual host: %+v", got)
	}
	if len(got.Host.Hostnames) != 1 || got.Host.Hostnames[0] != "panel.lab" {
		t.Errorf("hostnames: %v", got.Host.Hostnames)
	}
	hostID := got.Host.ID
	// A service added later: the earlier one stays open (manual entry is partial data).
	admin.want(201, "POST", fmt.Sprintf("/api/v1/hosts/%d/services", hostID), map[string]any{"port": 22, "name": "ssh", "product": "OpenSSH"}, nil)
	var svcs []model.Service
	resp, raw := admin.raw("GET", fmt.Sprintf("/api/v1/hosts/%d/services", hostID), nil, nil)
	if err := json.Unmarshal(raw, &svcs); err != nil {
		var page model.Page[model.Service]
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatalf("services: %d %s", resp.StatusCode, raw)
		}
		svcs = page.Items
	}
	open := map[int]model.ServiceState{}
	for _, s := range svcs {
		open[s.Port] = s.State
	}
	if open[22] != model.ServiceOpen || open[8080] != model.ServiceOpen {
		t.Fatalf("services after a second manual entry: %v (%s)", open, raw)
	}
	noZeroTime(t, "services", raw)
	// Validation.
	admin.want(422, "POST", "/api/v1/hosts", map[string]any{"ip": "nie-adres"}, nil)
	admin.want(422, "POST", "/api/v1/hosts", map[string]any{"ip": "10.70.0.10", "up": false, "services": []map[string]any{{"port": 80}}}, nil)
	admin.want(422, "POST", "/api/v1/hosts", map[string]any{"ip": "10.70.0.10", "services": []map[string]any{{"port": 70000}}}, nil)
	admin.want(422, "POST", fmt.Sprintf("/api/v1/hosts/%d/services", hostID), map[string]any{}, nil)
	// RBAC: results:create.
	if c := u[model.RoleViewer]; c != nil {
		c.want(403, "POST", "/api/v1/hosts", map[string]any{"ip": "10.70.0.11"}, nil)
	}

	// ---- run note and label ----
	var run model.ScanRun
	admin.want(200, "PATCH", fmt.Sprintf("/api/v1/runs/%d", got.Run.ID), map[string]any{"note": "wpis z inwentaryzacji", "label": "inwentaryzacja-2026"}, &run)
	if run.Note != "wpis z inwentaryzacji" || run.Label != "inwentaryzacja-2026" {
		t.Fatalf("patched run: %+v", run)
	}
	var runs model.Page[model.ScanRun]
	admin.want(200, "GET", "/api/v1/runs?q=inwentaryzacja-2026", nil, &runs)
	if runs.Total != 1 || runs.Items[0].ID != got.Run.ID {
		t.Fatalf("runs by label: %+v", runs)
	}
	admin.want(422, "PATCH", fmt.Sprintf("/api/v1/runs/%d", got.Run.ID), map[string]any{"label": "dwie\nlinie"}, nil)

	// ---- findings import: DefectDojo Generic JSON ----
	dd := map[string]any{"findings": []map[string]any{
		{"title": "Panel administracyjny bez MFA", "severity": "High", "description": "z audytu", "active": true,
			"endpoints": []map[string]any{{"host": "10.70.0.9", "port": 8080}}},
		{"title": "Stary serwer FTP", "severity": "Medium", "description": "z audytu", "active": true,
			"endpoints": []map[string]any{{"host": "10.70.0.77", "port": 21}}},
		{"title": "Bez hosta", "severity": "Low", "description": "brak adresu"},
	}}
	data, _ := json.Marshal(dd)
	resp, raw = admin.upload("/api/v1/import/findings", "dojo.json", data, nil)
	var fr FindingsImportResult
	if err := json.Unmarshal(raw, &fr); err != nil || resp.StatusCode != 201 {
		t.Fatalf("findings import: %d %s", resp.StatusCode, raw)
	}
	t.Logf("findings import: %s", raw)
	if fr.Created != 2 || fr.HostsCreated != 1 || fr.RunID == nil || fr.Skipped < 1 {
		t.Fatalf("findings import report: %+v", fr)
	}
	var hosts model.Page[model.Host]
	admin.want(200, "GET", "/api/v1/hosts?q=10.70.0.77", nil, &hosts)
	if hosts.Total != 1 {
		t.Fatalf("the unknown host of the file was not entered: %+v", hosts)
	}
	// Export in DefectDojo Generic formats and import the export again: updates, no duplicates.
	resp, raw = admin.raw("GET", "/api/v1/export/findings.dojo.json", nil, nil)
	var exp struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(raw, &exp); err != nil || resp.StatusCode != 200 || len(exp.Findings) < 2 {
		t.Fatalf("dojo json export: %d %s", resp.StatusCode, raw)
	}
	resp, raw2 := admin.upload("/api/v1/import/findings", "export.dojo.json", raw, nil)
	var fr2 FindingsImportResult
	_ = json.Unmarshal(raw2, &fr2)
	if resp.StatusCode != 201 || fr2.Created != 0 || fr2.Updated < 2 {
		t.Fatalf("re-import of the own export: %d %s", resp.StatusCode, raw2)
	}
	resp, raw = admin.raw("GET", "/api/v1/export/findings.dojo.csv", nil, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") || !bytes.Contains(raw, []byte("Panel administracyjny bez MFA")) {
		t.Fatalf("dojo csv export: %d %s", resp.StatusCode, raw)
	}
	resp, raw2 = admin.upload("/api/v1/import/findings", "export.dojo.csv", raw, nil)
	if resp.StatusCode != 201 || !bytes.Contains(raw2, []byte(`"created":0`)) {
		t.Fatalf("re-import of the CSV export: %d %s", resp.StatusCode, raw2)
	}
	if resp, raw := admin.upload("/api/v1/import/findings", "x.txt", []byte("to nie jest plik obserwacji"), nil); resp.StatusCode != 422 {
		t.Fatalf("unknown findings file: %d %s", resp.StatusCode, raw)
	}

	// ---- DefectDojo pull without configuration ----
	if resp, raw := admin.raw("POST", "/api/v1/defectdojo/pull", nil, map[string]string{auth.CSRFHeader: admin.csrf}); resp.StatusCode != 501 && resp.StatusCode != 409 {
		t.Fatalf("pull without DefectDojo: %d %s", resp.StatusCode, raw)
	}

	// ---- allowed networks ----
	admin.want(422, "PUT", "/api/v1/settings/safety", map[string]any{"allowed_networks": []string{"nie-siec"}}, nil)
	var pol model.SafetyPolicy
	admin.want(200, "PUT", "/api/v1/settings/safety", map[string]any{"allowed_networks": []string{"10.70.0.0/16"}}, &pol)
	if len(pol.AllowedNetworks) != 1 || pol.AllowedNetworks[0] != "10.70.0.0/16" {
		t.Fatalf("allowed networks: %+v", pol.AllowedNetworks)
	}
	var scope model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Lab"}, &scope)
	var added struct {
		Added   []model.Target      `json:"added"`
		Invalid []model.InvalidLine `json:"invalid"`
	}
	resp, raw = admin.raw("POST", fmt.Sprintf("/api/v1/scopes/%d/targets", scope.ID), map[string]string{"text": "10.70.0.0/24\n192.0.2.0/24"},
		map[string]string{auth.CSRFHeader: admin.csrf, "Content-Type": "application/json"})
	_ = json.Unmarshal(raw, &added)
	if !bytes.Contains(raw, []byte("192.0.2.0/24")) || !bytes.Contains(raw, []byte("dozwolon")) {
		t.Fatalf("a target outside the allowed networks must be refused with a reason: %d %s", resp.StatusCode, raw)
	}
	var tl model.Page[model.Target]
	admin.want(200, "GET", fmt.Sprintf("/api/v1/scopes/%d/targets", scope.ID), nil, &tl)
	for _, x := range tl.Items {
		if strings.HasPrefix(x.Value, "192.0.2.") {
			t.Fatalf("a refused target was stored: %+v", x)
		}
	}

	// ---- ad-hoc run (re-probe) ----
	var p model.ScanProfile
	admin.want(201, "POST", "/api/v1/profiles", map[string]any{"name": "Lab", "scope_ids": []int64{scope.ID}}, &p)
	var ah model.ScanRun
	admin.want(201, "POST", "/api/v1/runs/adhoc", map[string]any{"profile_id": p.ID, "addresses": []string{"10.70.0.1", "10.70.0.2"}, "ports": "80,443", "reason": "sprawdzenie zmiany"}, &ah)
	if ah.Trigger != runner.TriggerReprobe || ah.AdHoc == nil || len(ah.AdHoc.Addresses) != 2 || ah.ProfileID != nil {
		t.Fatalf("ad-hoc run: %+v", ah)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		admin.want(200, "GET", fmt.Sprintf("/api/v1/runs/%d", ah.ID), nil, &ah)
		if ah.Status == model.RunCompleted || ah.Status == model.RunFailed {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ah.Status != model.RunCompleted {
		t.Fatalf("ad-hoc run did not complete: %+v", ah)
	}
	resp, raw = admin.raw("POST", "/api/v1/runs/adhoc", map[string]any{"profile_id": p.ID, "addresses": []string{"192.0.2.10"}, "ports": "80"},
		map[string]string{auth.CSRFHeader: admin.csrf, "Content-Type": "application/json"})
	if resp.StatusCode != 422 {
		t.Fatalf("ad-hoc run outside the allowed networks: %d %s", resp.StatusCode, raw)
	}
	admin.want(422, "POST", "/api/v1/runs/adhoc", map[string]any{"profile_id": p.ID, "addresses": []string{"10.70.0.1"}, "ports": "80;id"}, nil)
	admin.want(422, "POST", "/api/v1/runs/adhoc", map[string]any{"profile_id": p.ID, "addresses": []string{}}, nil)

	// ---- import into a scope ----
	var scope2 model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Import"}, &scope2)
	xml := `<?xml version="1.0"?><nmaprun scanner="nmap" start="1700000000"><host><status state="up" reason="syn-ack"/><address addr="10.70.5.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port></ports></host><runstats><finished time="1700000100"/></runstats></nmaprun>`
	resp, raw = admin.upload("/api/v1/import/results", "scan.xml", []byte(xml), map[string]string{"scope_id": fmt.Sprint(scope2.ID)})
	var rep model.ImportReport
	if err := json.Unmarshal(raw, &rep); err != nil || resp.StatusCode != 201 || rep.Targets != 1 || rep.Hosts != 1 {
		t.Fatalf("import into a scope: %d %s", resp.StatusCode, raw)
	}
	admin.want(200, "GET", fmt.Sprintf("/api/v1/hosts?scope_id=%d", scope2.ID), nil, &hosts)
	if hosts.Total != 1 || hosts.Items[0].IP != "10.70.5.5" {
		t.Fatalf("hosts of the import scope: %+v", hosts)
	}
	if resp, raw := admin.upload("/api/v1/import/results", "scan.xml", []byte(xml), map[string]string{"scope_id": "999999"}); resp.StatusCode != 422 {
		t.Fatalf("import into a missing scope: %d %s", resp.StatusCode, raw)
	}

	// ---- the JSON layer: no zero times, no null lists ----
	for _, path := range []string{"/api/v1/hosts", fmt.Sprintf("/api/v1/hosts/%d", hostID), "/api/v1/runs", "/api/v1/findings", "/api/v1/dashboard", "/api/v1/settings/safety", "/api/v1/settings/defectdojo"} {
		resp, raw := admin.raw("GET", path, nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, raw)
		}
		noZeroTime(t, path, raw)
		var v any
		_ = json.Unmarshal(raw, &v)
		if p := nullList(v, ""); p != "" {
			t.Errorf("GET %s: a list field is null at %s", path, p)
		}
	}
}

// nullList returns the path of a null value whose key names a list (plural
// keys that Czujka always sends as arrays), or "".
func nullList(v any, path string) string {
	listKeys := map[string]bool{"items": true, "hostnames": true, "tags": true, "services": true, "technologies": true, "classes": true, "open_ports": true,
		"exclusions": true, "allowed_networks": true, "scope_mappings": true, "invalid": true, "errors": true}
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if c == nil && listKeys[k] {
				return path + "." + k
			}
			if p := nullList(c, path+"."+k); p != "" {
				return p
			}
		}
	case []any:
		for i, c := range x {
			if p := nullList(c, fmt.Sprintf("%s[%d]", path, i)); p != "" {
				return p
			}
		}
	}
	return ""
}

// pausingEngine runs until its context ends and then reports a paused run.
type pausingEngine struct{ quickEngine }

func (pausingEngine) Run(ctx context.Context, plan model.ScanPlan, sink model.ResultSink) model.RunOutcome {
	c := model.Chunk{RunID: plan.RunID, Seq: 0, Spec: []string{"10.70.0.0/24"}, Size: 256, Status: model.ChunkRunning}
	_ = sink.OnPlan(ctx, plan.RunID, []model.Chunk{c})
	<-ctx.Done()
	return model.RunOutcome{Status: model.RunPaused}
}

func TestPausedRunSendsPausedEvent(t *testing.T) {
	st := storetest.New(t)
	a := auth.New(st, auth.Config{PerMinute: 10000, MaxFails: 3})
	if _, err := a.Seed(context.Background(), "admin@example.org", adminPW); err != nil {
		t.Fatal(err)
	}
	bus := runner.NewBus()
	mgr := runner.New(st, runner.Options{Engine: pausingEngine{}, Bus: bus})
	srv := newTestServer(t, Deps{Store: st, Auth: a, Runner: mgr, Bus: bus, Version: "test", CookieSecure: "false"}, mgr)
	e := &env{t: t, st: st, srv: srv, mgr: mgr}
	admin := e.login("admin@example.org", adminPW)
	var scope model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Lab"}, &scope)
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", scope.ID), map[string]string{"text": "10.70.0.0/24"}, nil)
	var p model.ScanProfile
	admin.want(201, "POST", "/api/v1/profiles", map[string]any{"name": "Lab", "scope_ids": []int64{scope.ID}}, &p)
	var run model.ScanRun
	admin.want(201, "POST", "/api/v1/runs", map[string]any{"profile_id": p.ID}, &run)

	events := func() map[string]int {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/runs/%d/events", srv.URL, run.ID), nil)
		req.AddCookie(admin.cookie)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := http.DefaultClient.Do(req.WithContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got := map[string]int{}
		paused := run.Status == model.RunPaused
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if ev, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
				got[ev]++
				if ev == "paused" || ev == "done" {
					break
				}
				if !paused {
					paused = true
					go admin.raw("POST", fmt.Sprintf("/api/v1/runs/%d/pause", run.ID), nil, map[string]string{auth.CSRFHeader: admin.csrf})
				}
			}
		}
		return got
	}
	time.Sleep(100 * time.Millisecond)
	live := events()
	admin.want(200, "GET", fmt.Sprintf("/api/v1/runs/%d", run.ID), nil, &run)
	if live["paused"] != 1 || live["done"] != 0 {
		t.Fatalf("live stream of a run that is paused: %v", live)
	}
	// A client that connects to a paused run gets "paused" at once, not "done".
	if again := events(); again["paused"] != 1 || again["done"] != 0 {
		t.Fatalf("stream of a paused run: %v", again)
	}
	admin.want(200, "GET", fmt.Sprintf("/api/v1/runs/%d", run.ID), nil, &run)
	if run.Status != model.RunPaused {
		t.Fatalf("run status %s, want paused", run.Status)
	}
	// A second start of the same profile collides with the paused run: 409 run_active with its id.
	resp, raw := admin.raw("POST", "/api/v1/runs", map[string]any{"profile_id": p.ID}, map[string]string{auth.CSRFHeader: admin.csrf, "Content-Type": "application/json"})
	var ae struct {
		Error struct {
			Code    string           `json:"code"`
			Message string           `json:"message"`
			Details map[string]int64 `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &ae)
	if resp.StatusCode != 409 || ae.Error.Code != "run_active" || ae.Error.Details["run_id"] != run.ID {
		t.Fatalf("start during an active run: %d %s", resp.StatusCode, raw)
	}
}

// testImporter is the import seam without the inventory check of internal/wire.
type testImporter struct{}

func (testImporter) ParseResults(_ context.Context, _ string, data []byte) ([]model.HostResult, model.ImportReport, error) {
	return interchange.Import(bytes.NewReader(data), interchange.Options{})
}

// A route registered through Deps.Routes next to /signatures/{id} is reached
// (chi prefers the static segment), and goes through the permission guard.
func TestRoutesHookSignatureSuggestNotShadowed(t *testing.T) {
	e := setup(t, func(d *Deps) {
		d.Routes = append(d.Routes, func(r chi.Router, can Guard) {
			r.With(can(model.PermSignaturesRead)).Post("/signatures/suggest", func(w http.ResponseWriter, _ *http.Request) {
				WriteJSON(w, http.StatusOK, map[string]bool{"suggested": true})
			})
		})
	})
	admin := e.login("admin@example.org", adminPW)
	var out map[string]bool
	admin.want(200, "POST", "/api/v1/signatures/suggest", map[string]any{"service_id": 1}, &out)
	if !out["suggested"] {
		t.Fatalf("suggest: %v", out)
	}
	resp, _ := (&client{e: e}).raw("POST", "/api/v1/signatures/suggest", map[string]any{}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d", resp.StatusCode)
	}
}
