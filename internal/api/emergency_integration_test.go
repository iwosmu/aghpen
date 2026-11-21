package api

import (
	"context"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// M3: PUT /settings/safety never clears the emergency stop, also when its
// body carries "emergency_stop": false; a release always leaves an audit entry.
func TestSafetyEditKeepsTheEmergencyStop(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	var stale model.SafetyPolicy
	admin.want(200, "GET", "/api/v1/settings/safety", nil, &stale)
	admin.want(200, "POST", "/api/v1/emergency-stop", nil, nil)
	stale.MaxPPS = 800
	var got model.SafetyPolicy
	admin.want(200, "PUT", "/api/v1/settings/safety", stale, &got)
	if !got.EmergencyStop || got.MaxPPS != 800 {
		t.Fatalf("a policy edit cleared the emergency stop: %+v", got)
	}
	admin.want(200, "POST", "/api/v1/emergency-stop/release", nil, &got)
	if got.EmergencyStop {
		t.Fatalf("release: %+v", got)
	}
	page, err := e.st.ListAudit(context.Background(), store.AuditFilter{Action: "safety.emergency_stop_release"})
	if err != nil || page.Total != 1 || page.Items[0].UserEmail != "admin@example.org" {
		t.Fatalf("release audit: %+v %v", page, err)
	}
}
