package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// M4 of the security review: login hardening.
func TestLoginGivesNoAccountOracle(t *testing.T) {
	e := setup(t, nil) // MaxFails 3
	admin := e.login("admin@example.org", adminPW)
	admin.want(201, "POST", "/api/v1/users", map[string]any{"email": "ola@example.org", "name": "Ola", "password": "haslo-analityka-1", "role_id": roleIDOf(t, admin, model.RoleAnalyst)}, nil)
	anon := &client{e: e}
	for i := 0; i < 3; i++ {
		anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": "ola@example.org", "password": "zle-haslo"}, nil)
	}
	r1, b1 := anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": "ola@example.org", "password": "zle-haslo-2"}, nil)
	r2, b2 := anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": "nikt@example.org", "password": "zle-haslo-2"}, nil)
	if r1.StatusCode != r2.StatusCode || string(b1) != string(b2) || r1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a locked and an unknown account must answer the same: %d %s / %d %s", r1.StatusCode, b1, r2.StatusCode, b2)
	}
	// The audit log still tells the operator why.
	page, _ := e.st.ListAudit(context.Background(), store.AuditFilter{Action: "auth.login_failed", ListOpts: store.ListOpts{Limit: 50}})
	locked := false
	for _, a := range page.Items {
		if a.Detail["reason"] == "locked" {
			locked = true
		}
	}
	if !locked {
		t.Fatal("the audit entry of a locked account must say locked")
	}
}

func TestLoginAuditIsBounded(t *testing.T) {
	e := setup(t, nil)
	anon := &client{e: e}
	long := strings.Repeat("a", 5000) + "@example.org"
	anon.raw("POST", "/api/v1/auth/login", map[string]string{"email": long, "password": "x"}, nil)
	page, _ := e.st.ListAudit(context.Background(), store.AuditFilter{Action: "auth.login_failed"})
	if page.Total != 1 {
		t.Fatalf("audit entries: %d", page.Total)
	}
	if em, _ := page.Items[0].Detail["email"].(string); len(em) > 254 || em == "" {
		t.Fatalf("the audited e-mail must be clipped to 254 characters: %d", len(em))
	}
	// A login body is small: a large one is refused before it is parsed.
	big := map[string]string{"email": "a@example.org", "password": strings.Repeat("x", 128<<10)}
	if resp, _ := anon.raw("POST", "/api/v1/auth/login", big, nil); resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 128 KiB login body: %d", resp.StatusCode)
	}

	// Requests without a session cannot flood the audit log.
	before, _ := e.st.ListAudit(context.Background(), store.AuditFilter{})
	for i := 0; i < 400; i++ {
		anon.raw("POST", "/api/v1/scopes", map[string]string{"name": fmt.Sprint(i)}, nil)
	}
	after, _ := e.st.ListAudit(context.Background(), store.AuditFilter{})
	if n := after.Total - before.Total; n > 120 {
		t.Fatalf("400 requests without a session wrote %d audit entries", n)
	}
	// A signed-in user is still audited in full.
	admin := e.login("admin@example.org", adminPW)
	for i := 0; i < 3; i++ {
		admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": fmt.Sprint("s", i)}, nil)
	}
	scopes, _ := e.st.ListAudit(context.Background(), store.AuditFilter{Action: "scope.create"})
	ok := 0
	for _, a := range scopes.Items {
		if a.UserEmail == "admin@example.org" {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("signed-in requests must all be audited: %d", ok)
	}
}

func roleIDOf(t *testing.T, admin *client, slug string) int64 {
	t.Helper()
	var roles []model.Role
	admin.want(200, "GET", "/api/v1/roles", nil, &roles)
	for _, r := range roles {
		if r.Slug == slug {
			return r.ID
		}
	}
	t.Fatalf("no role %s", slug)
	return 0
}
