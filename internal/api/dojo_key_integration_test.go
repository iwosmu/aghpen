package api

import (
	"context"
	"sync"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
)

// keyRecorder is a DojoClient whose Test records the URL and key it got.
type keyRecorder struct {
	DojoClient
	mu   sync.Mutex
	seen []model.DefectDojoSettings
}

func (k *keyRecorder) Test(_ context.Context, s model.DefectDojoSettings) (bool, string, string) {
	k.mu.Lock()
	k.seen = append(k.seen, s)
	k.mu.Unlock()
	return true, "ok", "2.0"
}

// L1 of the security review: the DefectDojo test must not send the stored
// API key to a host other than the stored one; the same holds for a saved
// URL change without a new key.
func TestDojoStoredKeyStaysWithItsHost(t *testing.T) {
	rec := &keyRecorder{}
	e := setup(t, func(d *Deps) { d.Dojo = rec })
	admin := e.login("admin@example.org", adminPW)
	admin.want(200, "PUT", "/api/v1/settings/defectdojo", map[string]any{"url": "https://dojo.example.org", "api_key": "stored-secret-key"}, nil)

	admin.want(422, "POST", "/api/v1/settings/defectdojo/test", map[string]any{"url": "https://evil.example.net"}, nil)
	admin.want(422, "POST", "/api/v1/settings/defectdojo/test", map[string]any{"url": "https://dojo.example.org:8443"}, nil)
	for _, s := range rec.seen {
		if s.APIKey == "stored-secret-key" {
			t.Fatalf("the stored key went to %s", s.URL)
		}
	}
	// The stored host with the stored key, and another host with its own key, are fine.
	admin.want(200, "POST", "/api/v1/settings/defectdojo/test", map[string]any{"url": "https://dojo.example.org/"}, nil)
	admin.want(200, "POST", "/api/v1/settings/defectdojo/test", map[string]any{"url": "https://other.example.net", "api_key": "other-key"}, nil)
	if len(rec.seen) != 2 || rec.seen[0].APIKey != "stored-secret-key" || rec.seen[1].APIKey != "other-key" {
		t.Fatalf("tests sent: %+v", rec.seen)
	}
	// Saving a new host without a new key would hand the stored key to it at the next export.
	admin.want(422, "PUT", "/api/v1/settings/defectdojo", map[string]any{"url": "https://evil.example.net"}, nil)
	admin.want(200, "PUT", "/api/v1/settings/defectdojo", map[string]any{"url": "https://new.example.net", "api_key": "new-key"}, nil)
	admin.want(200, "PUT", "/api/v1/settings/defectdojo", map[string]any{"min_interest": 10}, nil)
}
