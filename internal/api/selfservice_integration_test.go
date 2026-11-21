package api

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// L6 of the security review: /healthz without a session tells only status
// and version (no key id, no gateway, no prober details).
func TestHealthzWithoutSessionIsMinimal(t *testing.T) {
	e := setup(t, nil)
	anon := &client{e: e}
	for _, path := range []string{"/healthz", "/api/v1/healthz"} {
		resp, raw := anon.raw("GET", path, nil, nil)
		var h map[string]any
		if err := json.Unmarshal(raw, &h); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, raw)
		}
		keys := make([]string, 0, len(h))
		for k := range h {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != "status,version" {
			t.Fatalf("%s without a session must hold only status and version: %s", path, raw)
		}
	}
	admin := e.login("admin@example.org", adminPW)
	for _, path := range []string{"/healthz", "/api/v1/healthz"} {
		var h map[string]any
		admin.want(200, "GET", path, nil, &h)
		if h["db"] != "ok" || h["field_encryption"] == nil {
			t.Fatalf("%s with a session keeps the details: %v", path, h)
		}
	}
}

// L6: a signed-in user changes the own password (POST /auth/password).
func TestSelfServicePasswordChange(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	admin.want(201, "POST", "/api/v1/users", map[string]any{"email": "ola@example.org", "name": "Ola", "password": "haslo-analityka-1", "role_id": roleIDOf(t, admin, model.RoleViewer)}, nil)
	ola := e.login("ola@example.org", "haslo-analityka-1")
	other := e.login("ola@example.org", "haslo-analityka-1") // a second session, e.g. a stolen cookie

	ola.want(422, "POST", "/api/v1/auth/password", map[string]any{"current_password": "zle-haslo", "new_password": "nowe-haslo-oli-1"}, nil)
	ola.want(422, "POST", "/api/v1/auth/password", map[string]any{"current_password": "haslo-analityka-1", "new_password": "krotkie"}, nil)
	ola.want(204, "POST", "/api/v1/auth/password", map[string]any{"current_password": "haslo-analityka-1", "new_password": "nowe-haslo-oli-1"}, nil)
	// The session that changed it stays; the other sessions end.
	ola.want(200, "GET", "/api/v1/me", nil, nil)
	other.want(401, "GET", "/api/v1/me", nil, nil)
	e.login("ola@example.org", "nowe-haslo-oli-1")
	// Without a session or a CSRF token: refused.
	(&client{e: e}).want(401, "POST", "/api/v1/auth/password", map[string]any{"current_password": "x", "new_password": "nowe-haslo-oli-2"}, nil)
	page, _ := e.st.ListAudit(context.Background(), store.AuditFilter{Action: "auth.password_change"})
	if page.Total < 1 {
		t.Fatal("a password change must be audited")
	}
	for _, a := range page.Items {
		b, _ := json.Marshal(a.Detail)
		if strings.Contains(string(b), "nowe-haslo") || strings.Contains(string(b), "haslo-analityka") {
			t.Fatalf("a password reached the audit log: %s", b)
		}
	}
}
