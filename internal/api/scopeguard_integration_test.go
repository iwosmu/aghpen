package api

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/targets"
)

// H1 of the security review: a user with scans:run only (the analyst role)
// must not scan an address outside the enabled targets through an ad-hoc run.
func TestAdHocRunStaysInsideEnabledTargets(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	analyst := e.users(admin)[model.RoleAnalyst]
	if analyst == nil {
		t.Fatal("no analyst role")
	}
	var sc model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Lab"}, &sc)
	var prev model.TargetPreview
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", sc.ID), map[string]string{"text": "10.70.0.0/24\n10.71.0.5"}, &prev)
	if len(prev.Valid) != 2 {
		t.Fatalf("targets: %+v", prev)
	}
	// The second target is switched off: its address is out of scope now.
	for _, tg := range prev.Valid {
		if tg.Value == "10.71.0.5" {
			admin.want(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", tg.ID), map[string]any{"enabled": false}, nil)
		}
	}
	var prof model.ScanProfile
	admin.want(201, "POST", "/api/v1/profiles", map[string]any{"name": "Lab", "scope_ids": []int64{sc.ID}, "ports": "80"}, &prof)

	adhoc := func(c *client, addrs ...string) (int, string) {
		resp, raw := c.raw("POST", "/api/v1/runs/adhoc", map[string]any{"profile_id": prof.ID, "addresses": addrs, "ports": "80"},
			map[string]string{auth.CSRFHeader: c.csrf, "Content-Type": "application/json"})
		return resp.StatusCode, string(raw)
	}
	for _, refused := range [][]string{
		{"8.8.8.8"},                // no target at all
		{"10.70.0.9", "192.0.2.1"}, // one of the list outside
		{"10.70.0.0/23"},           // wider than the target
		{"10.71.0.5"},              // a disabled target
	} {
		for _, c := range []*client{analyst, admin} {
			if code, raw := adhoc(c, refused...); code != 422 || !strings.Contains(raw, "włączonym celu") {
				t.Fatalf("ad-hoc run on %v must be refused with 422: %d %s", refused, code, raw)
			}
		}
	}
	if code, raw := adhoc(analyst, "10.70.0.9", "10.70.0.128/25"); code != 201 {
		t.Fatalf("ad-hoc run inside the target: %d %s", code, raw)
	}

	// The loopback mapping: 127.0.0.1 is scanned as the docker host, so it is
	// in scope only when the docker host address is.
	t.Cleanup(func() { targets.SetHostGateway(netip.Addr{}) })
	targets.SetHostGateway(netip.MustParseAddr("192.0.2.1"))
	if code, raw := adhoc(analyst, "127.0.0.1"); code != 422 {
		t.Fatalf("loopback mapped outside the targets: %d %s", code, raw)
	}
	targets.SetHostGateway(netip.MustParseAddr("10.70.0.1"))
	if code, raw := adhoc(analyst, "127.0.0.1"); code != 201 {
		t.Fatalf("loopback mapped inside a target: %d %s", code, raw)
	}
}

// H1: PATCH /targets/{id} runs the same allowed-networks check as creation.
func TestTargetUpdateRunsTheAllowedNetworksCheck(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	analyst := e.users(admin)[model.RoleAnalyst]
	admin.want(200, "PUT", "/api/v1/settings/safety", map[string]any{"allowed_networks": []string{"10.70.0.0/16"}}, nil)
	var sc model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Lab"}, &sc)
	var prev model.TargetPreview
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", sc.ID), map[string]string{"text": "10.70.1.0/24"}, &prev)
	id := prev.Valid[0].ID
	for _, c := range []*client{analyst, admin} {
		resp, raw := c.raw("PATCH", fmt.Sprintf("/api/v1/targets/%d", id), map[string]any{"value": "8.8.8.0/24"},
			map[string]string{auth.CSRFHeader: c.csrf, "Content-Type": "application/json"})
		if resp.StatusCode != 422 || !strings.Contains(string(raw), "dozwolon") {
			t.Fatalf("PATCH to a value outside the allowed networks: %d %s", resp.StatusCode, raw)
		}
	}
	got, err := e.st.GetTarget(context.Background(), id)
	if err != nil || got.Value != "10.70.1.0/24" {
		t.Fatalf("the refused value was stored: %+v %v", got, err)
	}
	analyst.want(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", id), map[string]any{"value": "10.70.2.0/24"}, nil)

	// A target stored before the policy narrowed cannot be switched on again.
	old, _, err := e.st.AddTargets(context.Background(), sc.ID, []model.Target{{Kind: model.TargetCIDR, Value: "192.0.2.0/24", Addresses: 256, Enabled: false, Tags: []string{}, Source: "api"}}, nil)
	if err != nil || len(old) != 1 {
		t.Fatalf("seed: %v", err)
	}
	resp, raw := analyst.raw("PATCH", fmt.Sprintf("/api/v1/targets/%d", old[0].ID), map[string]any{"enabled": true},
		map[string]string{auth.CSRFHeader: analyst.csrf, "Content-Type": "application/json"})
	if resp.StatusCode != 422 {
		t.Fatalf("switching on a target outside the allowed networks: %d %s", resp.StatusCode, raw)
	}
	// A note on it can still be edited (no address change).
	analyst.want(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", old[0].ID), map[string]any{"note": "stary cel"}, nil)
}

// L6 + H1: POST /import/results with a scope adds targets, so it needs
// targets:create besides results:create.
func TestImportIntoScopeNeedsTargetsCreate(t *testing.T) {
	e := setup(t, func(d *Deps) { d.Importer = testImporter{} })
	admin := e.login("admin@example.org", adminPW)
	var role model.Role
	admin.want(201, "POST", "/api/v1/roles", map[string]any{"name": "Import wyników", "permissions": []string{"results:read", "results:create"}}, &role)
	admin.want(201, "POST", "/api/v1/users", map[string]any{"email": "imp@example.org", "name": "Imp", "password": "haslo-importu-12345", "role_id": role.ID}, nil)
	imp := e.login("imp@example.org", "haslo-importu-12345")
	var sc model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Import"}, &sc)
	xml := `<?xml version="1.0"?><nmaprun scanner="nmap" start="1700000000"><host><status state="up" reason="syn-ack"/><address addr="8.8.4.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port></ports></host><runstats><finished time="1700000100"/></runstats></nmaprun>`
	resp, raw := imp.upload("/api/v1/import/results", "scan.xml", []byte(xml), map[string]string{"scope_id": fmt.Sprint(sc.ID)})
	if resp.StatusCode != 403 {
		t.Fatalf("import into a scope without targets:create: %d %s", resp.StatusCode, raw)
	}
	ts, err := e.st.EnabledTargets(context.Background(), []int64{sc.ID})
	if err != nil || len(ts) != 0 {
		t.Fatalf("the import added targets: %+v %v", ts, err)
	}
	// Without a scope the import stores results and adds no target.
	resp, raw = imp.upload("/api/v1/import/results", "scan.xml", []byte(xml), nil)
	if resp.StatusCode != 201 {
		t.Fatalf("import without a scope: %d %s", resp.StatusCode, raw)
	}
}
