package api

import (
	"context"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/kcap"
	"github.com/iwosmu/aghpen/internal/model"
)

// nftFake answers like nft: an install succeeds, the counter reads 3.
type nftFake struct{ applied []string }

func (f *nftFake) Run(_ context.Context, stdin string, args ...string) ([]byte, error) {
	if strings.Join(args, " ") == "-f -" {
		f.applied = append(f.applied, stdin)
	}
	return []byte(`{"nftables":[{"counter":{"packets":3}}]}`), nil
}

// kernel_cap is in /healthz (both paths) only for a session with
// safety:manage, and in /settings/safety; a PUT of max_pps replaces the rule.
func TestKernelCapThroughTheAPI(t *testing.T) {
	nft := &nftFake{}
	kc := kcap.New(kcap.Options{Mode: kcap.ModeAuto, Runner: nft})
	kc.Sync(context.Background(), 1000)
	e := setup(t, func(d *Deps) { d.KernelCap = kc })
	admin := e.login("admin@example.org", adminPW)
	admin.want(201, "POST", "/api/v1/users", map[string]any{"email": "widz@example.org", "name": "Widz", "password": "haslo-widza-123", "role_id": roleIDOf(t, admin, model.RoleViewer)}, nil)
	viewer := e.login("widz@example.org", "haslo-widza-123")
	anon := &client{e: e}

	for _, path := range []string{"/healthz", "/api/v1/healthz"} {
		var h map[string]any
		admin.want(200, "GET", path, nil, &h)
		kcm, ok := h["kernel_cap"].(map[string]any)
		if !ok || kcm["active"] != true || kcm["pps"] != float64(1100) || kcm["dropped"] != float64(3) {
			t.Fatalf("%s as admin: kernel_cap %v", path, h["kernel_cap"])
		}
		h = nil
		viewer.want(200, "GET", path, nil, &h)
		if _, ok := h["kernel_cap"]; ok || h["db"] != "ok" {
			t.Fatalf("%s as viewer: %v", path, h)
		}
		_, raw := anon.raw("GET", path, nil, nil)
		if strings.Contains(string(raw), "kernel_cap") {
			t.Fatalf("%s without a session: %s", path, raw)
		}
	}

	var v struct {
		MaxPPS    int          `json:"max_pps"`
		KernelCap *kcap.Status `json:"kernel_cap"`
	}
	admin.want(200, "GET", "/api/v1/settings/safety", nil, &v)
	if v.KernelCap == nil || v.KernelCap.PolicyPPS != 1000 || v.KernelCap.Mode != kcap.ModeAuto {
		t.Fatalf("GET /settings/safety: %+v", v)
	}
	admin.want(200, "PUT", "/api/v1/settings/safety", map[string]any{"max_pps": 500}, &v)
	if v.MaxPPS != 500 || v.KernelCap == nil || v.KernelCap.PPS != 550 || v.KernelCap.Burst != 55 {
		t.Fatalf("PUT max_pps=500: %+v %+v", v, v.KernelCap)
	}
	if len(nft.applied) != 2 || !strings.Contains(nft.applied[1], "rate over 550/second burst 55 packets") {
		t.Fatalf("the rule was not replaced: %d installs", len(nft.applied))
	}
}
