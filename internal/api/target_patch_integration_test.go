package api

import (
	"context"
	"fmt"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// PATCH /targets/{id}: an absent field means "unchanged". Switching a
// target off, on, editing its value, or all three at once works for every
// kind of target; the allowed-networks check still runs for a new value or
// a target switched on (TestTargetUpdateRunsTheAllowedNetworksCheck).
func TestTargetPatchAbsentFieldsMeanUnchanged(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	var sc model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Lab"}, &sc)
	var prev model.TargetPreview
	admin.want(201, "POST", fmt.Sprintf("/api/v1/scopes/%d/targets", sc.ID),
		map[string]string{"text": "10.70.0.5\n10.70.1.0/24\n10.70.2.1-10.70.2.9\nlab.example.org\n127.0.0.1"}, &prev)
	if len(prev.Valid) != 5 {
		t.Fatalf("targets: %+v", prev)
	}
	// A stored value that the single-value parser does not accept, such as the
	// "Ten komputer" target 'localhost' (the UI's one-click scan): switching it
	// off answered 422 "value: not an IP address ..." although no value was sent.
	seeded, _, err := e.st.AddTargets(context.Background(), sc.ID, []model.Target{{Kind: model.TargetDomain, Value: "localhost", Addresses: 1, Enabled: true, Tags: []string{}, Source: "api"}}, nil)
	if err != nil || len(seeded) != 1 {
		t.Fatalf("seed: %v", err)
	}
	var off model.Target
	admin.want(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", seeded[0].ID), map[string]any{"enabled": false}, &off)
	if off.Enabled || off.Value != "localhost" {
		t.Errorf("localhost switched off: %+v", off)
	}
	admin.want(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", seeded[0].ID), map[string]any{"note": "ten komputer"}, nil)
	admin.want(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", seeded[0].ID), map[string]any{"enabled": true}, &off)
	if !off.Enabled {
		t.Errorf("localhost switched on again: %+v", off)
	}
	for _, tg := range prev.Valid {
		path := fmt.Sprintf("/api/v1/targets/%d", tg.ID)
		var got model.Target
		admin.want(200, "PATCH", path, map[string]any{"enabled": false}, &got)
		if got.Enabled || got.Value != tg.Value {
			t.Errorf("%s switched off: %+v", tg.Value, got)
		}
		admin.want(200, "PATCH", path, map[string]any{"enabled": true}, &got)
		if !got.Enabled || got.Value != tg.Value {
			t.Errorf("%s switched on: %+v", tg.Value, got)
		}
		admin.want(200, "PATCH", path, map[string]any{"note": "n", "tags": []string{"x"}}, &got)
		if got.Note != "n" || got.Value != tg.Value {
			t.Errorf("%s note: %+v", tg.Value, got)
		}
	}
	// a new value, and all three fields together
	id := prev.Valid[0].ID
	var got model.Target
	admin.want(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", id), map[string]any{"value": "10.70.3.7"}, &got)
	if got.Value != "10.70.3.7" {
		t.Errorf("value change: %+v", got)
	}
	admin.want(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", id), map[string]any{"value": "10.70.3.0/28", "enabled": false, "note": "razem"}, &got)
	if got.Value != "10.70.3.0/28" || got.Enabled || got.Note != "razem" || got.Addresses != 16 {
		t.Errorf("all three: %+v", got)
	}
}
