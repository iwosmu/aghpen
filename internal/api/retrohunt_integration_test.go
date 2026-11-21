package api

import (
	"context"
	"sync"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// recordingHunter remembers the cookieValues flag of each call.
type recordingHunter struct {
	mu    sync.Mutex
	flags []bool
}

func (h *recordingHunter) RetroHunt(_ context.Context, _ string, _ bool, cookieValues bool) (model.RetroHuntResult, error) {
	h.mu.Lock()
	h.flags = append(h.flags, cookieValues)
	h.mu.Unlock()
	return model.RetroHuntResult{}, nil
}

// M1: only a caller with results:update gets cookie values matched.
func TestRetroHuntPassesCookieVisibility(t *testing.T) {
	h := &recordingHunter{}
	e := setup(t, func(d *Deps) { d.RetroHunter = h })
	admin := e.login("admin@example.org", adminPW)
	u := e.users(admin)
	body := map[string]any{"yaml": "id: p\nname: P\nmatch:\n  rules:\n    - {type: cookie, name: S, regex: '^a'}\n"}
	u[model.RoleViewer].want(200, "POST", "/api/v1/signatures/retrohunt", body, nil)
	u[model.RoleAnalyst].want(200, "POST", "/api/v1/signatures/retrohunt", body, nil)
	if len(h.flags) != 2 || h.flags[0] || !h.flags[1] {
		t.Fatalf("cookieValues per caller (viewer, analyst): %v", h.flags)
	}
}
