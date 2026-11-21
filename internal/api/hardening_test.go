package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/crypto"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

func TestClientIPTakesTheProxyEntry(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.18.0.2:41000"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if got := (&Server{d: Deps{TrustProxy: true}}).clientIP(r); got != "203.0.113.9" {
		t.Errorf("behind the proxy: %q, want the entry the proxy appended", got)
	}
	if got := (&Server{d: Deps{}}).clientIP(r); got != "172.18.0.2" {
		t.Errorf("without a trusted proxy the header is ignored: %q", got)
	}
	r.Header.Set("X-Forwarded-For", "nonsense")
	if got := (&Server{d: Deps{TrustProxy: true}}).clientIP(r); got != "172.18.0.2" {
		t.Errorf("a broken header falls back to the peer: %q", got)
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s := &Server{d: Deps{CookieSecure: "true"}}
	h := s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	for _, path := range []string{"/", "/api/v1/nope", "/assets/x.js"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "script-src") && strings.Contains(csp, "'unsafe-inline'") {
			t.Errorf("%s: CSP %q", path, csp)
		}
		if strings.Contains(csp, "'unsafe-eval'") {
			t.Errorf("%s: CSP allows eval", path)
		}
		for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"} {
			if w.Header().Get(k) != v {
				t.Errorf("%s: %s = %q", path, k, w.Header().Get(k))
			}
		}
		if w.Header().Get("Strict-Transport-Security") == "" {
			t.Errorf("%s: HSTS missing on a secure deployment", path)
		}
	}
}

// The operator lock (CZUJKA_ALLOWED_NETWORKS) bounds what an administrator
// can enter: targets, the allowed networks of the policy and ad-hoc runs.
func TestOperatorLockThroughTheAPI(t *testing.T) {
	_, dbURL := storetest.NewWithURL(t)
	kr, _ := crypto.NewKeyring(storetest.Key)
	ctx := context.Background()
	st, err := store.Open(ctx, dbURL, store.Options{Keyring: kr, Location: time.UTC, OperatorNetworks: []string{"10.66.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	a := auth.New(st, auth.Config{PerMinute: 10000, MaxFails: 3})
	if _, err := a.Seed(ctx, "admin@example.org", adminPW); err != nil {
		t.Fatal(err)
	}
	bus := runner.NewBus()
	mgr := runner.New(st, runner.Options{Engine: quickEngine{}, Bus: bus})
	e := &env{t: t, st: st, mgr: mgr, srv: newTestServer(t, Deps{Store: st, Auth: a, Runner: mgr, Bus: bus, Version: "test", CookieSecure: "false"}, mgr)}
	admin := e.login("admin@example.org", adminPW)

	var pol model.SafetyPolicy
	admin.want(200, "GET", "/api/v1/settings/safety", nil, &pol)
	if len(pol.OperatorNetworks) != 1 || pol.OperatorNetworks[0] != "10.66.0.0/16" {
		t.Fatalf("the policy shows the lock: %+v", pol.OperatorNetworks)
	}
	// The administrator cannot widen it, nor remove it by sending the field.
	pol.AllowedNetworks = []string{"0.0.0.0/0"}
	admin.want(422, "PUT", "/api/v1/settings/safety", pol, nil)
	pol.AllowedNetworks, pol.OperatorNetworks = []string{"10.66.1.0/24"}, []string{}
	admin.want(200, "PUT", "/api/v1/settings/safety", pol, &pol)
	if len(pol.OperatorNetworks) != 1 || len(pol.AllowedNetworks) != 1 {
		t.Fatalf("narrowing inside the lock works and the lock stays: %+v", pol)
	}
	pol.AllowedNetworks = []string{}
	admin.want(200, "PUT", "/api/v1/settings/safety", pol, &pol)

	// A scope target outside the lock is refused at entry.
	var sc model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]string{"name": "Poza blokadą"}, &sc)
	var prev model.TargetPreview
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", sc.ID), map[string]string{"text": "8.8.8.0/24\n10.66.3.0/24\n0.0.0.0/0"}, &prev)
	if len(prev.Valid) != 1 || prev.Valid[0].Value != "10.66.3.0/24" || len(prev.Invalid) != 2 || !strings.Contains(prev.Invalid[0].Reason, "CZUJKA_ALLOWED_NETWORKS") {
		b, _ := json.Marshal(prev)
		t.Fatalf("targets outside the lock: %s", b)
	}
	// An ad-hoc run outside the lock does not start.
	var prof model.ScanProfile
	admin.want(201, "POST", "/api/v1/profiles", map[string]any{"name": "W blokadzie", "scope_ids": []int64{sc.ID}, "ports": "80", "enabled": true}, &prof)
	resp, raw := admin.raw("POST", "/api/v1/runs/adhoc", map[string]any{"profile_id": prof.ID, "addresses": []string{"1.1.1.1"}, "ports": "80"}, map[string]string{auth.CSRFHeader: admin.csrf, "Content-Type": "application/json"})
	if resp.StatusCode != 422 || !strings.Contains(string(raw), "CZUJKA_ALLOWED_NETWORKS") {
		t.Fatalf("ad-hoc run outside the lock: %d %s", resp.StatusCode, raw)
	}
}
