package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// quickEngine reports two hosts and completes.
type quickEngine struct{}

func (quickEngine) Estimate(p model.ScanPlan) model.ScanEstimate {
	return model.ScanEstimate{Addresses: 256, Chunks: 1, EffectivePPS: min(p.Profile.Rate.MaxPPS, p.Policy.MaxPPS), FitsWindow: true}
}

func (quickEngine) Run(ctx context.Context, plan model.ScanPlan, sink model.ResultSink) model.RunOutcome {
	c := model.Chunk{RunID: plan.RunID, Seq: 0, Spec: []string{"10.70.0.0/24"}, Size: 256, Status: model.ChunkRunning}
	_ = sink.OnPlan(ctx, plan.RunID, []model.Chunk{c})
	time.Sleep(150 * time.Millisecond) // let the SSE client connect
	for i := 1; i <= 2; i++ {
		_ = sink.OnHost(ctx, model.HostResult{RunID: plan.RunID, IP: fmt.Sprintf("10.70.0.%d", i), Up: true, Services: []model.ServiceResult{{Port: 80, State: "open", Name: "http"}}})
	}
	c.Status, c.HostsUp = model.ChunkDone, 2
	_ = sink.OnChunk(ctx, c)
	st := model.RunStats{HostsUp: 2, ServicesOpen: 2, ChunksTotal: 1, ChunksDone: 1, AddressesTotal: 256, AddressesDone: 256, AvgPPS: 250}
	_ = sink.OnProgress(ctx, plan.RunID, st)
	return model.RunOutcome{Status: model.RunCompleted, Stats: st}
}

type env struct {
	t   *testing.T
	st  *store.Store
	srv *httptest.Server
	mgr *runner.Manager
}

const adminPW = "haslo-administratora-1"

func setup(t *testing.T, mutate func(*Deps)) *env {
	t.Helper()
	st := storetest.New(t)
	a := auth.New(st, auth.Config{PerMinute: 10000, MaxFails: 3})
	if _, err := a.Seed(context.Background(), "admin@example.org", adminPW); err != nil {
		t.Fatal(err)
	}
	bus := runner.NewBus()
	mgr := runner.New(st, runner.Options{Engine: quickEngine{}, Bus: bus})
	d := Deps{Store: st, Auth: a, Runner: mgr, Bus: bus, Version: "test", CookieSecure: "false"}
	if mutate != nil {
		mutate(&d)
	}
	srv := httptest.NewServer(New(d).Handler())
	t.Cleanup(func() { srv.Close(); mgr.Shutdown(context.Background()); mgr.Wait() })
	return &env{t: t, st: st, srv: srv, mgr: mgr}
}

// client is one signed-in user.
type client struct {
	e      *env
	cookie *http.Cookie
	csrf   string
}

func (e *env) login(email, password string) *client {
	e.t.Helper()
	c := &client{e: e}
	resp, body := c.raw("POST", "/api/v1/auth/login", map[string]string{"email": email, "password": password}, nil)
	if resp.StatusCode != 200 {
		e.t.Fatalf("login %s: %d %s", email, resp.StatusCode, body)
	}
	var s model.Session
	_ = json.Unmarshal(body, &s)
	for _, ck := range resp.Cookies() {
		if ck.Name == auth.CookieName {
			c.cookie = ck
		}
	}
	if c.cookie == nil || s.CSRFToken == "" {
		e.t.Fatalf("login gave no cookie or CSRF token: %s", body)
	}
	c.csrf = s.CSRFToken
	return c
}

func (c *client) raw(method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
	c.e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case io.Reader:
		rd = b
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+path, rd)
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// do sends a request with the CSRF token and decodes a JSON answer into out.
func (c *client) do(method, path string, body, out any) int {
	c.e.t.Helper()
	resp, raw := c.raw(method, path, body, map[string]string{auth.CSRFHeader: c.csrf, "Content-Type": "application/json"})
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.e.t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
	return resp.StatusCode
}

func (c *client) want(status int, method, path string, body, out any) {
	c.e.t.Helper()
	resp, raw := c.raw(method, path, body, map[string]string{auth.CSRFHeader: c.csrf, "Content-Type": "application/json"})
	if resp.StatusCode != status {
		c.e.t.Fatalf("%s %s: got %d, want %d: %s", method, path, resp.StatusCode, status, raw)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.e.t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
		}
	}
}

func errCode(raw []byte) string {
	var e struct {
		Error apiError `json:"error"`
	}
	_ = json.Unmarshal(raw, &e)
	return e.Error.Code
}

func (e *env) users(admin *client) map[string]*client {
	e.t.Helper()
	var roles []model.Role
	admin.want(200, "GET", "/api/v1/roles", nil, &roles)
	out := map[string]*client{"admin": admin}
	for _, r := range roles {
		if r.Slug == model.RoleAdmin {
			continue
		}
		email, pw := r.Slug+"@example.org", "haslo-"+r.Slug+"-12345"
		admin.want(201, "POST", "/api/v1/users", map[string]any{"email": email, "name": r.Name, "password": pw, "role_id": r.ID}, nil)
		out[r.Slug] = e.login(email, pw)
	}
	return out
}

func TestRBACMatrixCSRFAndAudit(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	u := e.users(admin)

	var scope model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Kampus", "criticality": 4}, &scope)
	var prev model.TargetPreview
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", scope.ID), map[string]string{"text": "10.70.0.0/24\n10.70.1.5\n10.70.0.0/24\nzle"}, &prev)
	if len(prev.Valid) != 2 || prev.Duplicates != 1 || len(prev.Invalid) != 1 || prev.AddressCount != 257 {
		t.Fatalf("target preview: %+v", prev)
	}
	target := prev.Valid[1]
	sp := fmt.Sprintf("/api/v1/scopes/%d", scope.ID)

	type req struct {
		method, path string
		body         any
	}
	newScope := func(name string) req { return req{"POST", "/api/v1/scopes", map[string]any{"name": name}} }
	matrix := []struct {
		name string
		r    func(role string) req
		want map[string]int // role → status
	}{
		{"read scopes", func(string) req { return req{"GET", "/api/v1/scopes", nil} }, map[string]int{"viewer": 200, "analyst": 200, "editor": 200, "admin": 200}},
		{"read hosts", func(string) req { return req{"GET", "/api/v1/hosts", nil} }, map[string]int{"viewer": 200, "analyst": 200, "editor": 200, "admin": 200}},
		{"read dashboard", func(string) req { return req{"GET", "/api/v1/dashboard", nil} }, map[string]int{"viewer": 200, "analyst": 200, "editor": 200, "admin": 200}},
		{"PATCH scope", func(string) req { return req{"PATCH", sp, map[string]any{"owner": "DSI"}} }, map[string]int{"viewer": 403, "analyst": 200, "editor": 200, "admin": 200}},
		{"PATCH target", func(string) req {
			return req{"PATCH", fmt.Sprintf("/api/v1/targets/%d", target.ID), map[string]any{"note": "n"}}
		}, map[string]int{"viewer": 403, "analyst": 200, "editor": 200, "admin": 200}},
		{"POST scope", func(role string) req { return newScope("Nowy " + role) }, map[string]int{"viewer": 403, "analyst": 403, "editor": 201, "admin": 201}},
		{"POST targets", func(role string) req {
			return req{"POST", sp + "/targets", map[string]string{"text": "10.99.0." + fmt.Sprint(len(role))}}
		}, map[string]int{"viewer": 403, "analyst": 403, "editor": 201, "admin": 201}},
		{"DELETE target", func(string) req { return req{"DELETE", "/api/v1/targets/999999", nil} }, map[string]int{"viewer": 403, "analyst": 403, "editor": 404, "admin": 404}},
		{"POST profile", func(role string) req {
			return req{"POST", "/api/v1/profiles", map[string]any{"name": "P " + role, "scope_ids": []int64{scope.ID}}}
		}, map[string]int{"viewer": 403, "analyst": 403, "editor": 201, "admin": 201}},
		{"POST run", func(string) req { return req{"POST", "/api/v1/runs", map[string]any{"profile_id": 999999}} }, map[string]int{"viewer": 403, "analyst": 404, "editor": 404, "admin": 404}},
		{"PATCH finding", func(string) req { return req{"PATCH", "/api/v1/findings/999999", map[string]any{"status": "triaged"}} }, map[string]int{"viewer": 403, "analyst": 404, "editor": 404, "admin": 404}},
		{"DELETE host", func(string) req { return req{"DELETE", "/api/v1/hosts/999999", nil} }, map[string]int{"viewer": 403, "analyst": 403, "editor": 404, "admin": 404}},
		{"export hosts", func(string) req { return req{"GET", "/api/v1/export/hosts.csv", nil} }, map[string]int{"viewer": 403, "analyst": 200, "editor": 200, "admin": 200}},
		{"GET users", func(string) req { return req{"GET", "/api/v1/users", nil} }, map[string]int{"viewer": 403, "analyst": 403, "editor": 403, "admin": 200}},
		{"POST users", func(role string) req {
			return req{"POST", "/api/v1/users", map[string]any{"email": "x-" + role + "@example.org", "password": "haslo-haslo-123", "role_id": 1}}
		}, map[string]int{"viewer": 403, "analyst": 403, "editor": 403, "admin": 201}},
		{"POST roles", func(role string) req {
			return req{"POST", "/api/v1/roles", map[string]any{"name": "Rola " + role, "permissions": []string{"results:read"}}}
		}, map[string]int{"viewer": 403, "analyst": 403, "editor": 403, "admin": 201}},
		{"GET audit", func(string) req { return req{"GET", "/api/v1/audit", nil} }, map[string]int{"viewer": 403, "analyst": 403, "editor": 403, "admin": 200}},
		{"PUT safety", func(string) req { return req{"PUT", "/api/v1/settings/safety", map[string]any{"max_pps": 800}} }, map[string]int{"viewer": 403, "analyst": 403, "editor": 403, "admin": 200}},
		{"emergency stop", func(string) req { return req{"POST", "/api/v1/emergency-stop/release", nil} }, map[string]int{"viewer": 403, "analyst": 403, "editor": 403, "admin": 200}},
		{"PUT defectdojo", func(string) req {
			return req{"PUT", "/api/v1/settings/defectdojo", map[string]any{"url": "https://dojo.example.org", "api_key": "TAJNY-KLUCZ-DOJO"}}
		}, map[string]int{"viewer": 403, "analyst": 403, "editor": 403, "admin": 200}},
	}
	for _, m := range matrix {
		for _, role := range []string{"viewer", "analyst", "editor", "admin"} {
			rq := m.r(role)
			if got := u[role].do(rq.method, rq.path, rq.body, nil); got != m.want[role] {
				t.Errorf("%-16s %-8s %s %s: got %d, want %d", m.name, role, rq.method, rq.path, got, m.want[role])
			}
		}
	}

	// No session: 401. Session without CSRF token on a mutation: 403. Wrong token: 403.
	anon := &client{e: e}
	if resp, raw := anon.raw("GET", "/api/v1/hosts", nil, nil); resp.StatusCode != 401 || errCode(raw) != "unauthorized" {
		t.Errorf("anonymous read: %d %s", resp.StatusCode, raw)
	}
	if resp, raw := anon.raw("POST", "/api/v1/scopes", map[string]any{"name": "x"}, nil); resp.StatusCode != 401 {
		t.Errorf("anonymous write: %d %s", resp.StatusCode, raw)
	}
	if resp, raw := admin.raw("POST", "/api/v1/scopes", map[string]any{"name": "Bez CSRF"}, nil); resp.StatusCode != 403 || !strings.Contains(string(raw), "CSRF") {
		t.Errorf("mutation without CSRF token: %d %s", resp.StatusCode, raw)
	}
	if resp, _ := admin.raw("POST", "/api/v1/scopes", map[string]any{"name": "Zły CSRF"}, map[string]string{auth.CSRFHeader: "zly-token"}); resp.StatusCode != 403 {
		t.Errorf("mutation with a wrong CSRF token: %d", resp.StatusCode)
	}
	if resp, _ := admin.raw("GET", "/api/v1/scopes", nil, nil); resp.StatusCode != 200 {
		t.Errorf("a read needs no CSRF token: %d", resp.StatusCode)
	}
	if c := admin.cookie; !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("session cookie flags: %+v", c)
	}
	// A failed login.
	if resp, raw := anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": "admin@example.org", "password": "zle"}, nil); resp.StatusCode != 401 || errCode(raw) != "unauthorized" {
		t.Errorf("failed login: %d %s", resp.StatusCode, raw)
	}

	// The DefectDojo key is write-only and encrypted in the database.
	var dd model.DefectDojoSettings
	admin.want(200, "GET", "/api/v1/settings/defectdojo", nil, &dd)
	if dd.APIKey != "" || !dd.APIKeySet {
		t.Errorf("GET must hide the API key: %+v", dd)
	}
	var rawSettings string
	_ = e.st.Pool().QueryRow(context.Background(), `SELECT value::text || ' ' || secret FROM settings WHERE key = 'defectdojo'`).Scan(&rawSettings)
	if strings.Contains(rawSettings, "TAJNY-KLUCZ-DOJO") || !strings.Contains(rawSettings, "czk1.") {
		t.Errorf("the API key must be stored as ciphertext: %s", rawSettings)
	}

	// Audit log: logins, the failed login, mutations, denied mutations and the CSRF rejection, never a password or key.
	var audit model.Page[model.AuditEntry]
	admin.want(200, "GET", "/api/v1/audit?limit=1000", nil, &audit)
	seen := map[string]int{}
	for _, a := range audit.Items {
		key := a.Action
		if st, _ := a.Detail["status"].(float64); st == 403 {
			key += " 403"
		}
		seen[key]++
		if raw, _ := json.Marshal(a); bytes.Contains(raw, []byte("haslo-")) || bytes.Contains(raw, []byte("TAJNY-KLUCZ")) {
			t.Errorf("secret in the audit log: %s", raw)
		}
	}
	for _, want := range []string{"auth.login", "auth.login_failed", "scope.create", "scope.create 403", "scope.update", "scope.target.create", "user.create",
		"user.create 403", "role.create", "safety.update", "integration.defectdojo.update", "export.hosts", "profile.create", "host.delete 403", "run.start 403"} {
		if seen[want] == 0 {
			t.Errorf("audit log has no %q entry; it has %v", want, seen)
		}
	}
	if seen["auth.login"] != 4 {
		t.Errorf("want 4 successful logins in the audit log, got %d", seen["auth.login"])
	}
	var csrfDenied model.Page[model.AuditEntry]
	admin.want(200, "GET", "/api/v1/audit?action=scope.create&limit=100", nil, &csrfDenied)
	found := false
	for _, a := range csrfDenied.Items {
		if a.Detail["reason"] == "csrf" && a.UserEmail == "admin@example.org" {
			found = true
		}
	}
	if !found {
		t.Error("the CSRF rejection must be in the audit log with the user")
	}

	// Logout ends the session.
	u["viewer"].want(204, "POST", "/api/v1/auth/logout", nil, nil)
	if resp, _ := u["viewer"].raw("GET", "/api/v1/me", nil, nil); resp.StatusCode != 401 {
		t.Errorf("after logout: %d", resp.StatusCode)
	}
}

func TestNotWiredRoutesAnswer501(t *testing.T) {
	e := setup(t, func(d *Deps) { d.Runner = runner.New(d.Store, runner.Options{}) })
	admin := e.login("admin@example.org", adminPW)
	var scope model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "S"}, &scope)
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", scope.ID), map[string]string{"text": "10.0.0.0/24"}, nil)
	var p model.ScanProfile
	admin.want(201, "POST", "/api/v1/profiles", map[string]any{"name": "P", "scope_ids": []int64{scope.ID}}, &p)
	r1, _ := e.st.CreateRun(context.Background(), model.ScanRun{Status: model.RunCompleted})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "scan.xml")
	_, _ = fw.Write([]byte("<nmaprun/>"))
	mw.Close()
	cases := []struct {
		method, path string
		body         any
		ctype        string
	}{
		{"POST", "/api/v1/signatures", map[string]any{"yaml": "id: x"}, ""},
		{"POST", "/api/v1/signatures/validate", map[string]any{"yaml": "id: x"}, ""},
		{"POST", "/api/v1/signatures/retrohunt", map[string]any{"yaml": "id: x"}, ""},
		{"GET", fmt.Sprintf("/api/v1/diff?from=%d&to=%d", r1.ID, r1.ID), nil, ""},
		{"POST", fmt.Sprintf("/api/v1/profiles/%d/estimate", p.ID), nil, ""},
		{"POST", "/api/v1/runs", map[string]any{"profile_id": p.ID}, ""},
		{"POST", "/api/v1/settings/defectdojo/test", map[string]any{"url": "https://dojo.example.org"}, ""},
		{"GET", fmt.Sprintf("/api/v1/export/runs/%d.xml", r1.ID), nil, ""},
		{"POST", "/api/v1/import/results", &buf, mw.FormDataContentType()},
	}
	for _, c := range cases {
		hdr := map[string]string{auth.CSRFHeader: admin.csrf}
		if c.ctype != "" {
			hdr["Content-Type"] = c.ctype
		}
		resp, raw := admin.raw(c.method, c.path, c.body, hdr)
		if resp.StatusCode != 501 || errCode(raw) != "not_wired" {
			t.Errorf("%s %s: got %d %s, want 501 not_wired", c.method, c.path, resp.StatusCode, raw)
		}
	}
	var h map[string]any
	admin.want(200, "GET", "/api/v1/healthz", nil, &h)
	if h["status"] != "ok" || h["db"] != "ok" || h["engine"] != false || h["version"] != "test" {
		t.Errorf("healthz: %v", h)
	}
	if _, ok := h["tde"].(bool); !ok {
		t.Errorf("healthz.tde must be a boolean: %v", h["tde"])
	}
}

func TestProfilesSafetyAndValidation(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	var p model.ScanProfile
	admin.want(201, "POST", "/api/v1/profiles", map[string]any{"name": "Domyślny"}, &p)
	if p.Ports != "top-1000" || p.Rate.MaxPPS != 500 || !p.Chunking.Adaptive || !p.Discovery.ICMPEcho || p.Schedule.Timezone != "Europe/Warsaw" || !p.HTTP.Enabled {
		t.Fatalf("profile defaults: %+v", p)
	}
	// A profile can only be stricter than the safety policy.
	if resp, raw := admin.raw("PATCH", fmt.Sprintf("/api/v1/profiles/%d", p.ID), map[string]any{"rate": map[string]any{"max_pps": 50000, "max_parallel_chunks": 4, "max_parallel_hosts": 16}},
		map[string]string{auth.CSRFHeader: admin.csrf}); resp.StatusCode != 422 || !strings.Contains(string(raw), "safety policy") {
		t.Errorf("profile above the policy cap: %d %s", resp.StatusCode, raw)
	}
	admin.want(422, "PATCH", fmt.Sprintf("/api/v1/profiles/%d", p.ID), map[string]any{"ports": "80; rm -rf /"}, nil)
	admin.want(409, "POST", "/api/v1/profiles", map[string]any{"name": "Domyślny"}, nil)
	// Safe detection: the policy accepts GET and HEAD only.
	if resp, raw := admin.raw("PUT", "/api/v1/settings/safety", map[string]any{"allowed_methods": []string{"GET", "POST"}}, map[string]string{auth.CSRFHeader: admin.csrf}); resp.StatusCode != 422 || !strings.Contains(string(raw), "GET and HEAD") {
		t.Errorf("POST in allowed_methods: %d %s", resp.StatusCode, raw)
	}
	var pol model.SafetyPolicy
	admin.want(200, "PUT", "/api/v1/settings/safety", map[string]any{"max_pps": 300, "exclusions": []string{"10.70.0.128/25", "skarbiec.example.org"}, "emergency_stop": true}, &pol)
	if pol.MaxPPS != 300 || len(pol.Exclusions) != 2 || pol.EmergencyStop {
		t.Fatalf("policy: %+v (PUT must not set the emergency stop)", pol)
	}
	var prev model.TargetPreview
	admin.want(200, "POST", "/api/v1/targets/preview", map[string]string{"text": "10.70.0.0/24"}, &prev)
	if prev.Excluded != 128 || prev.AddressCount != 256 {
		t.Fatalf("preview with exclusions: %+v", prev)
	}
	// Emergency stop blocks new runs with its own error code.
	admin.want(200, "POST", "/api/v1/emergency-stop", nil, &pol)
	if !pol.EmergencyStop {
		t.Fatal("emergency stop flag not set")
	}
	var scope model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "S"}, &scope)
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", scope.ID), map[string]string{"text": "10.70.0.0/24"}, nil)
	admin.want(200, "PATCH", fmt.Sprintf("/api/v1/profiles/%d", p.ID), map[string]any{"scope_ids": []int64{scope.ID}, "rate": map[string]any{"max_pps": 200, "max_parallel_chunks": 2, "max_parallel_hosts": 8}}, &p)
	if resp, raw := admin.raw("POST", "/api/v1/runs", map[string]any{"profile_id": p.ID}, map[string]string{auth.CSRFHeader: admin.csrf}); resp.StatusCode != 409 || errCode(raw) != "emergency_stop" {
		t.Errorf("run during emergency stop: %d %s", resp.StatusCode, raw)
	}
	admin.want(200, "POST", "/api/v1/emergency-stop/release", nil, &pol)
	var est model.ScanEstimate
	admin.want(200, "POST", fmt.Sprintf("/api/v1/profiles/%d/estimate", p.ID), nil, &est)
	if est.EffectivePPS != 200 {
		t.Errorf("estimate: %+v", est)
	}
	// Bad input.
	admin.want(400, "GET", "/api/v1/hosts?port=abc", nil, nil)
	admin.want(400, "GET", "/api/v1/hosts?cidr=nope", nil, nil)
	admin.want(400, "GET", "/api/v1/hosts/abc", nil, nil)
	admin.want(404, "GET", "/api/v1/hosts/424242", nil, nil)
	admin.want(404, "GET", "/api/v1/nope", nil, nil)
	if resp, raw := admin.raw("POST", "/api/v1/scopes", "{broken", map[string]string{auth.CSRFHeader: admin.csrf}); resp.StatusCode != 400 || errCode(raw) != "bad_request" {
		t.Errorf("broken JSON: %d %s", resp.StatusCode, raw)
	}
}

func TestRunOverAPIWithSSE(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	var scope model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Lab"}, &scope)
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", scope.ID), map[string]string{"text": "10.70.0.0/24"}, nil)
	var p model.ScanProfile
	admin.want(201, "POST", "/api/v1/profiles", map[string]any{"name": "Lab", "scope_ids": []int64{scope.ID}}, &p)
	var run model.ScanRun
	admin.want(201, "POST", "/api/v1/runs", map[string]any{"profile_id": p.ID}, &run)

	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/runs/%d/events", e.srv.URL, run.ID), nil)
	req.AddCookie(admin.cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type %q", ct)
	}
	events := map[string]int{}
	var last model.ScanRun
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	cur := ""
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: ") {
			cur = strings.TrimPrefix(line, "event: ")
			events[cur]++
		}
		if strings.HasPrefix(line, "data: ") && cur == "done" {
			_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &last)
		}
	}
	if events["progress"] == 0 || events["done"] != 1 || last.Status != model.RunCompleted || last.Stats.HostsUp != 2 {
		t.Fatalf("SSE events: %v last=%+v", events, last)
	}
	t.Logf("SSE events of run %d: %v", run.ID, events)
	e.mgr.Wait()

	var chunks []model.Chunk
	admin.want(200, "GET", fmt.Sprintf("/api/v1/runs/%d/chunks", run.ID), nil, &chunks)
	var mp struct {
		Blocks []mapBlock `json:"blocks"`
	}
	admin.want(200, "GET", fmt.Sprintf("/api/v1/runs/%d/map", run.ID), nil, &mp)
	if len(chunks) != 1 || len(mp.Blocks) != 1 || mp.Blocks[0].CIDR != "10.70.0.0/24" || mp.Blocks[0].HostsUp != 2 || mp.Blocks[0].Status != "done" {
		t.Fatalf("chunks=%+v map=%+v", chunks, mp)
	}
	var hosts model.Page[model.Host]
	admin.want(200, "GET", "/api/v1/hosts?scope_id="+fmt.Sprint(scope.ID)+"&port=80&sort=ip", nil, &hosts)
	if hosts.Total != 2 || hosts.Items[0].IP != "10.70.0.1" || hosts.Limit != 50 {
		t.Fatalf("hosts after the run: %+v", hosts)
	}
	admin.want(409, "POST", fmt.Sprintf("/api/v1/runs/%d/pause", run.ID), nil, nil)
	var runs model.Page[model.ScanRun]
	admin.want(200, "GET", "/api/v1/runs?status=completed&profile_id="+fmt.Sprint(p.ID), nil, &runs)
	if runs.Total != 1 {
		t.Fatalf("runs: %+v", runs)
	}
	// Run export: JSON and CSV work without other workers.
	resp2, raw := admin.raw("GET", fmt.Sprintf("/api/v1/export/runs/%d.json", run.ID), nil, nil)
	var results []model.HostResult
	if err := json.Unmarshal(raw, &results); err != nil || resp2.StatusCode != 200 || len(results) != 2 || len(results[0].Services) != 1 {
		t.Fatalf("run export: %d %s", resp2.StatusCode, raw)
	}
}

func TestInventoryEditsCookiesAndExport(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	u := e.users(admin)
	ctx := context.Background()
	run, _ := e.st.CreateRun(ctx, model.ScanRun{Status: model.RunCompleted})
	var batch []model.HostResult
	for i := 0; i < 1200; i++ {
		h := model.HostResult{RunID: run.ID, IP: fmt.Sprintf("10.80.%d.%d", i/250, i%250+1), Up: true, Services: []model.ServiceResult{{Port: 22, State: "open", Name: "ssh", Product: "=OpenSSH"}}}
		if i == 0 {
			h.Services = append(h.Services, model.ServiceResult{Port: 443, State: "open", Name: "https", Classes: []string{model.ClassLogin},
				HTTP: &model.HTTPFingerprint{Status: 200, Title: "Logowanie", Cookies: []model.Cookie{{Name: "sid", Value: "SUROWA-WARTOSC-COOKIE", ValueLen: 21, ValueHash: "ab12"}}}})
		}
		batch = append(batch, h)
	}
	if err := e.st.IngestHosts(ctx, batch, store.SinkOptions{}); err != nil {
		t.Fatal(err)
	}
	var svcs model.Page[model.Service]
	admin.want(200, "GET", "/api/v1/services?class=login", nil, &svcs)
	if svcs.Total != 1 {
		t.Fatalf("services: %+v", svcs)
	}
	sid := svcs.Items[0].ID

	// Role rule: raw cookie values only for users with results:update.
	cookieOf := func(c *client) string {
		var v model.Service
		c.want(200, "GET", fmt.Sprintf("/api/v1/services/%d", sid), nil, &v)
		if v.Latest == nil || v.Latest.Result.HTTP == nil || len(v.Latest.Result.HTTP.Cookies) != 1 || v.Latest.Result.HTTP.Cookies[0].ValueHash != "ab12" {
			t.Fatalf("latest observation: %+v", v.Latest)
		}
		return v.Latest.Result.HTTP.Cookies[0].Value
	}
	if got := cookieOf(u["viewer"]); got != "" {
		t.Errorf("a viewer must not get the raw cookie value, got %q", got)
	}
	if got := cookieOf(u["analyst"]); got != "SUROWA-WARTOSC-COOKIE" {
		t.Errorf("an analyst must get the raw cookie value, got %q", got)
	}
	var obs model.Page[model.ServiceObservation]
	u["viewer"].want(200, "GET", fmt.Sprintf("/api/v1/services/%d/observations", sid), nil, &obs)
	if obs.Total != 1 || obs.Items[0].Result.HTTP.Cookies[0].Value != "" {
		t.Errorf("observations for a viewer: %+v", obs)
	}

	// Analyst edits; the override keeps the observed value.
	var svc model.Service
	u["analyst"].want(200, "PATCH", fmt.Sprintf("/api/v1/services/%d", sid), map[string]any{"product": "Keycloak", "note": "SSO uczelni", "tags": []string{"sso"}}, &svc)
	if svc.Product != "Keycloak" || svc.Note != "SSO uczelni" || svc.Overrides["product"].By != "analyst@example.org" {
		t.Fatalf("service patch: %+v", svc)
	}
	u["analyst"].want(422, "PATCH", fmt.Sprintf("/api/v1/services/%d", sid), map[string]any{"interest": 99}, nil)
	u["viewer"].want(403, "PATCH", fmt.Sprintf("/api/v1/services/%d", sid), map[string]any{"product": "x"}, nil)
	var host model.Host
	u["analyst"].want(200, "PATCH", fmt.Sprintf("/api/v1/hosts/%d", svc.HostID), map[string]any{"label": "SSO", "criticality": 5, "note": "TAJNA-NOTATKA-HOSTA"}, &host)
	var noteEnc string
	_ = e.st.Pool().QueryRow(ctx, `SELECT note_enc FROM hosts WHERE id = $1`, svc.HostID).Scan(&noteEnc)
	if host.Note != "TAJNA-NOTATKA-HOSTA" || !strings.HasPrefix(noteEnc, "czk1.") || strings.Contains(noteEnc, "TAJNA") {
		t.Fatalf("host note: api=%q db=%q", host.Note, noteEnc)
	}
	// Manual finding, then triage.
	var f model.Finding
	u["analyst"].want(403, "POST", "/api/v1/findings", map[string]any{"title": "x", "host_id": svc.HostID}, nil)
	u["editor"].want(201, "POST", "/api/v1/findings", map[string]any{"title": "Panel logowania bez MFA", "ip": svc.IP, "service_id": sid, "severity": "medium", "note": "do weryfikacji"}, &f)
	if !f.Manual || f.Port != 443 || f.Note != "do weryfikacji" || f.Status != model.FindingNew {
		t.Fatalf("manual finding: %+v", f)
	}
	u["analyst"].want(200, "PATCH", fmt.Sprintf("/api/v1/findings/%d", f.ID), map[string]any{"status": "triaged", "assignee": "ola"}, &f)
	if f.Status != model.FindingTriaged {
		t.Fatalf("finding patch: %+v", f)
	}
	var dash model.Dashboard
	u["viewer"].want(200, "GET", "/api/v1/dashboard", nil, &dash)
	if dash.Headline.HostsUp != 1200 || dash.Headline.ServicesOpen != 1201 || dash.Headline.FindingsOpen != 1 || len(dash.TopFindings) != 1 {
		t.Fatalf("dashboard: %+v", dash.Headline)
	}

	// Streaming export with filters; formula cells are neutralised.
	resp, raw := u["analyst"].raw("GET", "/api/v1/export/services.csv?port=22", nil, nil)
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil || resp.StatusCode != 200 || len(rows) != 1201 || rows[0][0] != "id" {
		t.Fatalf("services.csv: status=%d rows=%d err=%v", resp.StatusCode, len(rows), err)
	}
	if rows[1][8] != "'=OpenSSH" {
		t.Errorf("CSV formula cell must be quoted: %q", rows[1][8])
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "czujka-services-") {
		t.Errorf("Content-Disposition: %q", cd)
	}
	resp, raw = u["analyst"].raw("GET", "/api/v1/export/hosts.json?cidr=10.80.0.0/24", nil, nil)
	var hosts []model.Host
	if err := json.Unmarshal(raw, &hosts); err != nil || len(hosts) != 250 {
		t.Fatalf("hosts.json: %d hosts, err %v", len(hosts), err)
	}
	for _, kind := range []string{"findings", "changes", "signatures"} {
		if resp, _ := u["analyst"].raw("GET", "/api/v1/export/"+kind+".json", nil, nil); resp.StatusCode != 200 {
			t.Errorf("export %s: %d", kind, resp.StatusCode)
		}
	}
	if resp, _ := u["analyst"].raw("GET", "/api/v1/export/hosts.xlsx", nil, nil); resp.StatusCode != 400 {
		t.Errorf("unknown format: %d", resp.StatusCode)
	}
	// Target file import with a dry run.
	var scope model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Import"}, &scope)
	upload := func(dry string) (int, model.TargetPreview) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "cele.csv")
		_, _ = fw.Write([]byte("value,note\n10.90.0.0/24,serwery\n10.90.1.7,\nzly wpis,\n"))
		_ = mw.WriteField("dry_run", dry)
		mw.Close()
		resp, raw := admin.raw("POST", fmt.Sprintf("/api/v1/scopes/%d/targets/import", scope.ID), &buf, map[string]string{auth.CSRFHeader: admin.csrf, "Content-Type": mw.FormDataContentType()})
		var p model.TargetPreview
		_ = json.Unmarshal(raw, &p)
		return resp.StatusCode, p
	}
	if code, p := upload("true"); code != 200 || len(p.Valid) != 2 || len(p.Invalid) != 1 || p.Valid[0].ID != 0 {
		t.Fatalf("dry run: %d %+v", code, p)
	}
	if code, p := upload("false"); code != 201 || len(p.Valid) != 2 || p.Valid[0].ID == 0 || p.AddressCount != 257 {
		t.Fatalf("import: %d %+v", code, p)
	}
	admin.want(200, "GET", "/api/v1/scopes/"+fmt.Sprint(scope.ID), nil, &scope)
	if scope.TargetCount != 2 || scope.AddressCount != 257 {
		t.Fatalf("scope counters: %+v", scope)
	}
}

func TestSecurityHeadersAndUI(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>CZUJKA-UI</html>"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "assets"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console.log(1)"), 0o644)
	e := setup(t, func(d *Deps) { d.WebDir = dir })
	anon := &client{e: e}
	resp, body := anon.raw("GET", "/", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "CZUJKA-UI") {
		t.Fatalf("index: %d %s", resp.StatusCode, body)
	}
	for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if got := resp.Header.Get(h); got != want {
			t.Errorf("%s = %q", h, got)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP: %q", csp)
	}
	if resp, body := anon.raw("GET", "/hosts/15", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), "CZUJKA-UI") {
		t.Errorf("SPA fallback: %d", resp.StatusCode)
	}
	if resp, body := anon.raw("GET", "/assets/app.js", nil, nil); resp.StatusCode != 200 || string(body) != "console.log(1)" || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("asset: %d %q", resp.StatusCode, body)
	}
	if resp, _ := anon.raw("GET", "/assets/missing.js", nil, nil); resp.StatusCode != 404 {
		t.Errorf("missing asset: %d", resp.StatusCode)
	}
	if resp, body := anon.raw("GET", "/../../etc/passwd", nil, nil); resp.StatusCode == 200 && strings.Contains(string(body), "root:") {
		t.Errorf("path traversal: %d", resp.StatusCode)
	}
	resp, body = anon.raw("GET", "/api/v1/healthz", nil, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("healthz: %d cache=%q %s", resp.StatusCode, resp.Header.Get("Cache-Control"), body)
	}
	// Without a built UI the server says so; it does not pretend.
	e2 := setup(t, nil)
	if resp, body := (&client{e: e2}).raw("GET", "/", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), "nie jest zbudowany") {
		t.Errorf("no UI page: %d %s", resp.StatusCode, body)
	}
}

// TestHTTPBenchmark measures the API over real HTTP after an ingest of 10 000 hosts with 3 services each.
// Run it with CZUJKA_BENCH=1 (make bench).
func TestHTTPBenchmark(t *testing.T) {
	if os.Getenv("CZUJKA_BENCH") == "" {
		t.Skip("set CZUJKA_BENCH=1 to run the benchmark")
	}
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	ctx := context.Background()
	run, err := e.st.CreateRun(ctx, model.ScanRun{Status: model.RunCompleted})
	if err != nil {
		t.Fatal(err)
	}
	const n = 10000
	hosts := make([]model.HostResult, 0, n)
	for i := 0; i < n; i++ {
		hosts = append(hosts, model.HostResult{RunID: run.ID, IP: fmt.Sprintf("10.100.%d.%d", i/250, i%250+1), Up: true, Reason: "syn-ack", Services: []model.ServiceResult{
			{Port: 22, Proto: "tcp", State: "open", Name: "ssh", Product: "OpenSSH", Version: "9.6"},
			{Port: 80, Proto: "tcp", State: "open", Name: "http", Product: "nginx", Version: "1.26.2", HTTP: &model.HTTPFingerprint{Status: 200, Title: fmt.Sprintf("Serwis %d", i)}},
			{Port: 443, Proto: "tcp", State: "open", Name: "https", Product: "nginx", Version: "1.26.2", Tunnel: "ssl"},
		}})
	}
	start := time.Now()
	if err := e.st.IngestHosts(ctx, hosts, store.SinkOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Logf("ingest: %d hosts x 3 services in %s", n, time.Since(start).Round(time.Millisecond))
	for _, path := range []string{"/api/v1/hosts", "/api/v1/hosts?limit=200&sort=-interest", "/api/v1/hosts?port=443&cidr=10.100.8.0/22&sort=ip", "/api/v1/hosts?q=10.100.39",
		"/api/v1/services?limit=50", "/api/v1/services?port=443&name=https&limit=100", "/api/v1/dashboard", "/api/v1/export/hosts.csv", "/api/v1/export/services.json"} {
		var times []time.Duration
		size := 0
		for i := 0; i < 11; i++ {
			t0 := time.Now()
			resp, raw := admin.raw("GET", path, nil, nil)
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d %s", path, resp.StatusCode, raw)
			}
			if i > 0 { // the first request warms the connection
				times = append(times, time.Since(t0))
			}
			size = len(raw)
		}
		slices.Sort(times)
		t.Logf("GET %-52s median %7.1f ms  min %7.1f  max %7.1f  body %d bytes", path, float64(times[len(times)/2].Microseconds())/1000,
			float64(times[0].Microseconds())/1000, float64(times[len(times)-1].Microseconds())/1000, size)
	}
	var page model.Page[model.Host]
	admin.want(200, "GET", "/api/v1/hosts", nil, &page)
	var dash model.Dashboard
	admin.want(200, "GET", "/api/v1/dashboard", nil, &dash)
	if page.Total != n || dash.Headline.HostsUp != n || dash.Headline.ServicesOpen != 3*n {
		t.Fatalf("totals: hosts=%d dashboard=%+v", page.Total, dash.Headline)
	}
}
