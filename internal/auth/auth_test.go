package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("Bardzo-tajne-haslo-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=32768,t=2,p=1$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if !VerifyPassword(h, "Bardzo-tajne-haslo-1") || VerifyPassword(h, "bardzo-tajne-haslo-1") {
		t.Fatal("verify is wrong")
	}
	h2, _ := HashPassword("Bardzo-tajne-haslo-1")
	if h == h2 {
		t.Fatal("two hashes of one password must differ (random salt)")
	}
	for _, bad := range []string{"", "plain", "$argon2id$v=19$m=0,t=2,p=1$YQ$YQ", "$bcrypt$x$y$z$w"} {
		if VerifyPassword(bad, "x") {
			t.Errorf("hash %q must not verify", bad)
		}
	}
	if ValidatePassword("short") == nil || ValidatePassword("dlugie-haslo-ok") != nil {
		t.Fatal("password policy is wrong")
	}
}

func TestTokens(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil || len(tok) != 43 || len(hash) != 32 {
		t.Fatalf("token %q hash %d err %v", tok, len(hash), err)
	}
	if !reflect.DeepEqual(HashToken(tok), hash) {
		t.Fatal("HashToken must be deterministic")
	}
	tok2, _, _ := NewToken()
	if tok == tok2 {
		t.Fatal("tokens must be random")
	}
}

func TestBuiltinRolesMatchTheArchitecture(t *testing.T) {
	roles := map[string]map[model.Permission]bool{}
	for _, r := range BuiltinRoles() {
		if !r.Builtin {
			t.Errorf("%s must be built-in", r.Slug)
		}
		roles[r.Slug] = map[model.Permission]bool{}
		for _, p := range r.Permissions {
			roles[r.Slug][p] = true
		}
	}
	if len(roles) != 4 || len(roles[model.RoleAdmin]) != len(model.AllPermissions) {
		t.Fatalf("admin must hold every permission: %d of %d", len(roles[model.RoleAdmin]), len(model.AllPermissions))
	}
	// viewer: read only
	for p := range roles[model.RoleViewer] {
		if !strings.HasSuffix(string(p), ":read") {
			t.Errorf("viewer holds %s", p)
		}
	}
	if len(roles[model.RoleViewer]) != 4 || roles[model.RoleViewer][model.PermAuditRead] || roles[model.RoleViewer][model.PermEmergencyStop] {
		t.Errorf("viewer permissions: %v", roles[model.RoleViewer])
	}
	// analyst: read + update, run scans, export; no create or delete
	a := roles[model.RoleAnalyst]
	for _, p := range []model.Permission{model.PermTargetsUpdate, model.PermResultsUpdate, model.PermSignaturesUpdate, model.PermScansRun, model.PermExportRun, model.PermEmergencyStop} {
		if !a[p] {
			t.Errorf("analyst lacks %s", p)
		}
	}
	for p := range a {
		if strings.HasSuffix(string(p), ":create") || strings.HasSuffix(string(p), ":delete") || strings.HasSuffix(string(p), ":manage") || p == model.PermScansConfigure {
			t.Errorf("analyst holds %s", p)
		}
	}
	// editor: create and delete too, configure scans; no administration
	e := roles[model.RoleEditor]
	for _, p := range []model.Permission{model.PermTargetsCreate, model.PermTargetsDelete, model.PermResultsCreate, model.PermResultsDelete, model.PermSignaturesCreate, model.PermSignaturesDelete, model.PermScansConfigure, model.PermEmergencyStop} {
		if !e[p] {
			t.Errorf("editor lacks %s", p)
		}
	}
	for _, p := range []model.Permission{model.PermUsersManage, model.PermRolesManage, model.PermAuditRead, model.PermSafetyManage, model.PermIntegrations} {
		if e[p] {
			t.Errorf("editor holds %s", p)
		}
	}
	if len(PermissionCatalog()) != len(model.AllPermissions) {
		t.Fatal("the permission catalog must cover every permission")
	}
	for _, pi := range PermissionCatalog() {
		if pi.Group == "" || pi.LabelPL == "" || pi.LabelEN == "" {
			t.Errorf("permission %s has no labels", pi.Permission)
		}
	}
}

func TestPrincipalAndCSRF(t *testing.T) {
	p := NewPrincipal(model.User{ID: 1}, []model.Permission{model.PermResultsRead}, "csrf-abc")
	if !p.Can(model.PermResultsRead) || p.Can(model.PermResultsUpdate) || (*Principal)(nil).Can(model.PermResultsRead) {
		t.Fatal("Can is wrong")
	}
	if !p.CheckCSRF("csrf-abc") || p.CheckCSRF("") || p.CheckCSRF("csrf-abd") {
		t.Fatal("CheckCSRF is wrong")
	}
	if slugify("  Zespół SOC / Noc ") != "zespol-soc-noc" {
		t.Fatalf("slugify: %q", slugify("  Zespół SOC / Noc "))
	}
	if got := slugify("Dyżurny zmian"); got != "dyzurny-zmian" {
		t.Fatalf("slugify transliterates Polish letters: %q", got)
	}
}

func TestRequireMiddleware(t *testing.T) {
	var gotCode string
	fail := func(w http.ResponseWriter, _ *http.Request, status int, code, _ string) {
		gotCode = code
		w.WriteHeader(status)
	}
	h := Require(model.PermTargetsDelete, fail)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	do := func(p *Principal) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/x", nil)
		if p != nil {
			req = req.WithContext(WithPrincipal(req.Context(), p))
		}
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if do(nil) != 401 || gotCode != "unauthorized" {
		t.Fatal("no session must be 401")
	}
	if do(NewPrincipal(model.User{}, []model.Permission{model.PermTargetsRead}, "")) != 403 || gotCode != "forbidden" {
		t.Fatal("missing permission must be 403")
	}
	if do(NewPrincipal(model.User{}, []model.Permission{model.PermTargetsDelete}, "")) != 204 {
		t.Fatal("holder must pass")
	}
}

// ---------- integration tests (real PostgreSQL) ----------

func setup(t *testing.T, cfg Config) (*Service, *store.Store, *Principal) {
	t.Helper()
	st := storetest.New(t)
	svc := New(st, cfg)
	gen, err := svc.Seed(context.Background(), "Admin@Example.org", "")
	if err != nil || gen == "" {
		t.Fatalf("seed: gen=%q err=%v", gen, err)
	}
	if again, err := svc.Seed(context.Background(), "admin@example.org", "inne-haslo-12345"); err != nil || again != "" {
		t.Fatalf("second seed must not touch the admin: %q %v", again, err)
	}
	admin, _, err := svc.Login(context.Background(), "admin@example.org", gen, "198.51.100.1", "test")
	if err != nil {
		t.Fatalf("admin login with the generated password: %v", err)
	}
	return svc, st, admin
}

func roleID(t *testing.T, st *store.Store, slug string) int64 {
	t.Helper()
	r, err := st.GetRoleBySlug(context.Background(), slug)
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestLoginSessionAndLockout(t *testing.T) {
	ctx := context.Background()
	svc, st, admin := setup(t, Config{MaxFails: 3, Lockout: time.Hour, PerMinute: 1000})
	if _, err := svc.CreateUser(ctx, admin, "ola@example.org", "Ola", "haslo-analityka-1", roleID(t, st, model.RoleAnalyst)); err != nil {
		t.Fatal(err)
	}
	p, token, err := svc.Login(ctx, " OLA@example.org ", "haslo-analityka-1", "198.51.100.2", "ua")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Can(model.PermResultsUpdate) || p.Can(model.PermTargetsCreate) || p.CSRFToken == "" || p.User.RoleSlug != model.RoleAnalyst {
		t.Fatalf("principal: %+v", p)
	}
	// Only the hash of the token is stored.
	var stored int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE encode(token_hash, 'escape') LIKE '%' || $1 || '%' OR csrf_token = $1`, token).Scan(&stored)
	if stored != 0 {
		t.Fatal("the raw session token must not be in the database")
	}
	p2, err := svc.AuthenticateToken(ctx, token)
	if err != nil || p2.User.Email != "ola@example.org" || p2.CSRFToken != p.CSRFToken {
		t.Fatalf("authenticate: %+v %v", p2, err)
	}
	if _, err := svc.AuthenticateToken(ctx, token+"x"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("wrong token: %v", err)
	}
	if err := svc.Logout(ctx, p2); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateToken(ctx, token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("after logout: %v", err)
	}
	// Unknown user and wrong password give the same error.
	if _, _, err := svc.Login(ctx, "nikt@example.org", "x", "198.51.100.2", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	for i := 1; i <= 3; i++ {
		_, _, err := svc.Login(ctx, "ola@example.org", "zle-haslo", "198.51.100.2", "")
		want := ErrInvalidCredentials
		if i == 3 {
			want = ErrLocked
		}
		if !errors.Is(err, want) {
			t.Fatalf("failure %d: got %v want %v", i, err, want)
		}
	}
	if _, _, err := svc.Login(ctx, "ola@example.org", "haslo-analityka-1", "198.51.100.2", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("a locked account must reject the right password too: %v", err)
	}
	// An administrator unlocks by setting a new password.
	u, _ := st.GetUserAuthByEmail(ctx, "ola@example.org")
	np := "nowe-haslo-analityka"
	if _, err := svc.UpdateUser(ctx, admin, u.ID, UserPatch{Password: &np}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Login(ctx, "ola@example.org", np, "198.51.100.2", ""); err != nil {
		t.Fatalf("login after reset: %v", err)
	}
}

func TestLoginRateLimitPerAddress(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setup(t, Config{PerMinute: 3, MaxFails: 100})
	var limited bool
	for i := 0; i < 5; i++ {
		_, _, err := svc.Login(ctx, "nikt@example.org", "x", "203.0.113.50", "")
		if errors.Is(err, ErrRateLimited) {
			limited = true
		}
	}
	if !limited {
		t.Fatal("the 4th and 5th attempt from one address must be rate limited")
	}
	if _, _, err := svc.Login(ctx, "nikt@example.org", "x", "203.0.113.51", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("another address must not be limited: %v", err)
	}
}

func TestRBACRules(t *testing.T) {
	ctx := context.Background()
	svc, st, admin := setup(t, Config{PerMinute: 1000})
	adminRole, editorRole, viewerRole := roleID(t, st, model.RoleAdmin), roleID(t, st, model.RoleEditor), roleID(t, st, model.RoleViewer)

	// Last admin: cannot be deleted, disabled or demoted.
	if err := svc.DeleteUser(ctx, admin, admin.User.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
	yes := true
	if _, err := svc.UpdateUser(ctx, admin, admin.User.ID, UserPatch{Disabled: &yes}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin: %v", err)
	}
	if _, err := svc.UpdateUser(ctx, admin, admin.User.ID, UserPatch{RoleID: &viewerRole}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	// With a second admin the first can be demoted.
	second, err := svc.CreateUser(ctx, admin, "admin2@example.org", "Drugi", "haslo-admina-222", adminRole)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateUser(ctx, admin, second.ID, UserPatch{RoleID: &editorRole}); err != nil {
		t.Fatalf("demote one of two admins: %v", err)
	}

	// A custom role "user manager" without admin permissions.
	mgrRole, err := svc.CreateRole(ctx, admin, model.Role{Name: "Kierownik zespołu", Permissions: []model.Permission{model.PermUsersManage, model.PermRolesManage, model.PermResultsRead}})
	if err != nil || mgrRole.Slug != "kierownik-zespolu" || mgrRole.Builtin {
		t.Fatalf("custom role: %+v %v", mgrRole, err)
	}
	if _, err := svc.CreateUser(ctx, admin, "kier@example.org", "Kier", "haslo-kierownika", mgrRole.ID); err != nil {
		t.Fatal(err)
	}
	mgr, _, err := svc.Login(ctx, "kier@example.org", "haslo-kierownika", "198.51.100.3", "")
	if err != nil {
		t.Fatal(err)
	}
	// The manager cannot grant what the manager does not hold.
	if _, err := svc.CreateUser(ctx, mgr, "x@example.org", "", "haslo-haslo-haslo", adminRole); !errors.Is(err, ErrForbidden) {
		t.Fatalf("grant admin role: %v", err)
	}
	if _, err := svc.CreateRole(ctx, mgr, model.Role{Name: "Eskalacja", Permissions: []model.Permission{model.PermSafetyManage}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("role with a permission the actor lacks: %v", err)
	}
	if _, err := svc.UpdateUser(ctx, mgr, mgr.User.ID, UserPatch{RoleID: &adminRole}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("self promotion: %v", err)
	}
	// ... and cannot take over an admin account by resetting its password.
	pw := "przejete-haslo-123"
	if _, err := svc.UpdateUser(ctx, mgr, admin.User.ID, UserPatch{Password: &pw}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("password reset of a stronger account: %v", err)
	}
	if err := svc.DeleteUser(ctx, mgr, admin.User.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("delete of a stronger account: %v", err)
	}
	// But the manager can create a user with a role inside the manager's own permissions.
	sub, err := svc.CreateRole(ctx, mgr, model.Role{Name: "Podgląd wyników", Permissions: []model.Permission{model.PermResultsRead}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser(ctx, mgr, "nowy@example.org", "Nowy", "haslo-nowego-123", sub.ID); err != nil {
		t.Fatalf("allowed grant: %v", err)
	}

	// Built-in roles are read only; a role in use cannot be deleted; unknown permissions are rejected.
	n := "Inna nazwa"
	if _, err := svc.UpdateRole(ctx, admin, viewerRole, RolePatch{Name: &n}); !errors.Is(err, ErrBuiltinRole) {
		t.Fatalf("edit built-in role: %v", err)
	}
	if err := svc.DeleteRole(ctx, admin, adminRole); !errors.Is(err, ErrBuiltinRole) {
		t.Fatalf("delete built-in role: %v", err)
	}
	if err := svc.DeleteRole(ctx, admin, sub.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete role in use: %v", err)
	}
	if _, err := svc.CreateRole(ctx, admin, model.Role{Name: "Zła", Permissions: []model.Permission{"hosts:hack"}}); !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown permission: %v", err)
	}
	perms := []model.Permission{model.PermResultsRead, model.PermTargetsRead}
	up, err := svc.UpdateRole(ctx, admin, sub.ID, RolePatch{Permissions: &perms})
	if err != nil || len(up.Permissions) != 2 || up.UserCount != 1 {
		t.Fatalf("update custom role: %+v %v", up, err)
	}
	// A role change works at once for a live session: permissions are read per request.
	if _, err := svc.CreateUser(ctx, admin, "live@example.org", "", "haslo-live-12345", editorRole); err != nil {
		t.Fatal(err)
	}
	_, tok, err := svc.Login(ctx, "live@example.org", "haslo-live-12345", "198.51.100.9", "")
	if err != nil {
		t.Fatal(err)
	}
	lu, _ := st.GetUserAuthByEmail(ctx, "live@example.org")
	if _, err := svc.UpdateUser(ctx, admin, lu.ID, UserPatch{RoleID: &viewerRole}); err != nil {
		t.Fatal(err)
	}
	live, err := svc.AuthenticateToken(ctx, tok)
	if err != nil || live.Can(model.PermTargetsCreate) || !live.Can(model.PermTargetsRead) {
		t.Fatalf("the demoted session must lose its permissions at once: %v", err)
	}
	if _, err := svc.UpdateUser(ctx, admin, lu.ID, UserPatch{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateToken(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("a disabled user must lose the session: %v", err)
	}
}
