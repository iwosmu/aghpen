package api

import (
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// A duplicate name answers 409 with a sentence the UI shows as it is, not
// "conflict: scopes_name_key".
func TestUniqueConflictsAreSentences(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	var sc model.Scope
	admin.want(201, "POST", "/api/v1/scopes", map[string]any{"name": "Lab"}, &sc)
	admin.want(201, "POST", "/api/v1/profiles", map[string]any{"name": "P", "scope_ids": []int64{sc.ID}}, nil)
	admin.want(201, "POST", "/api/v1/users", map[string]any{"email": "ola@example.org", "name": "Ola", "password": "haslo-haslo-123", "role_id": 1}, nil)
	for _, c := range []struct {
		path string
		body map[string]any
		want string
	}{
		{"/api/v1/scopes", map[string]any{"name": "Lab"}, "Zakres o tej nazwie już istnieje."},
		{"/api/v1/profiles", map[string]any{"name": "P", "scope_ids": []int64{sc.ID}}, "Profil o tej nazwie już istnieje."},
		{"/api/v1/users", map[string]any{"email": "ola@example.org", "name": "Ola", "password": "haslo-haslo-123", "role_id": 1}, "Użytkownik z tym adresem e-mail już istnieje."},
	} {
		var out struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		admin.want(409, "POST", c.path, c.body, &out)
		if out.Error.Code != "conflict" || out.Error.Message != c.want || strings.Contains(out.Error.Message, "_key") {
			t.Errorf("%s: %+v, want %q", c.path, out.Error, c.want)
		}
	}
}
