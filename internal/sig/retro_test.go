package sig

import (
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func observations() []model.ServiceObservation {
	at := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	page := func(url, body string, paths ...model.PathProbe) model.ServiceResult {
		return model.ServiceResult{Port: 80, Name: "http", HTTP: &model.HTTPFingerprint{URL: url, FinalURL: url, Status: 200, BodyExcerpt: body, Paths: paths,
			Headers: map[string][]string{"Server": {"Apache/2.4.57"}}}}
	}
	return []model.ServiceObservation{
		{ID: 1, ServiceID: 11, RunID: 7, At: at, Result: page("http://10.1.0.5:80/", `<link href="/wp-content/themes/a.css">`,
			model.PathProbe{Path: "/wp-login.php", Status: 200, Excerpt: `<input id="user_login">`})},
		{ID: 2, ServiceID: 12, RunID: 7, At: at, Result: page("http://10.1.0.6:80/", `<link href="/wp-content/themes/b.css">`)},
		{ID: 3, ServiceID: 13, RunID: 7, At: at, Result: page("http://10.1.0.7:80/", "<h1>It works!</h1>")},
		{ID: 4, ServiceID: 14, RunID: 7, At: at, Result: page("http://wiki.example.edu/", "plain page",
			model.PathProbe{Path: "/wp-login.php", Status: 404})},
		{ID: 5, ServiceID: 15, RunID: 7, At: at, Result: model.ServiceResult{Port: 22, Name: "ssh", Banner: "SSH-2.0-OpenSSH_9.6"}},
	}
}

func TestRetroHunt(t *testing.T) {
	res := RetroHunt(briefExample, observations())
	if res.Scanned != 5 || res.PacketsSent != 0 {
		t.Fatalf("scanned = %d, packets = %d", res.Scanned, res.PacketsSent)
	}
	if len(res.Hits) != 2 {
		t.Fatalf("hits = %+v", res.Hits)
	}
	// Service 11: body 0.5 and path 0.9 → 0.95. The stored path probe is used.
	h := res.Hits[0]
	if h.ServiceID != 11 || h.IP != "10.1.0.5" || h.Port != 80 || h.URL != "http://10.1.0.5:80/" || h.RunID != 7 || h.At.IsZero() || h.Match.Confidence != 0.95 || len(h.Match.Evidence) != 2 {
		t.Errorf("hit 0 = %+v", h)
	}
	// Service 12: only the body rule (0.5), which is exactly min_confidence. The path was never fetched there.
	if h := res.Hits[1]; h.ServiceID != 12 || h.Match.Confidence != 0.5 {
		t.Errorf("hit 1 = %+v", h)
	}
	// /wp-login.php is missing for the HTTP observations 12 and 13. The SSH observation is not counted: it has no HTTP data at all.
	if len(res.MissingPaths) != 1 || res.MissingPaths[0] != "/wp-login.php" || res.Incomplete != 2 {
		t.Errorf("missing = %v, incomplete = %d", res.MissingPaths, res.Incomplete)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "/wp-login.php") || !strings.Contains(res.Notes[0], "2 z 5") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestRetroHuntNotes(t *testing.T) {
	obs := observations()
	// A signature without extra paths needs no note.
	res := RetroHunt("id: apache\nname: Apache\nheader: {name: Server, regex: '^Apache/([0-9.]+)', version_group: 1}\n", obs)
	if len(res.Hits) != 4 || len(res.Notes) != 0 || len(res.MissingPaths) != 0 || res.Incomplete != 0 {
		t.Errorf("hits = %d, notes = %v, missing = %v", len(res.Hits), res.Notes, res.MissingPaths)
	}
	if res.Hits[0].Match.Version != "2.4.57" {
		t.Errorf("version = %q", res.Hits[0].Match.Version)
	}
	// A stored URL with a host name gives no IP: retro-hunt never resolves names.
	if res.Hits[3].ServiceID != 14 || res.Hits[3].IP != "" {
		t.Errorf("hit for a host name URL = %+v", res.Hits[3])
	}
	// Every observation has the path: the note says so.
	res = RetroHunt(briefExample, obs[:1])
	if len(res.MissingPaths) != 0 || len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "Wszystkie ścieżki") {
		t.Errorf("notes = %v", res.Notes)
	}
	// Non-HTTP signature against a non-HTTP observation.
	res = RetroHunt("id: openssh\nname: OpenSSH\nbanner: {regex: 'OpenSSH_([0-9.]+)', version_group: 1}\n", obs)
	if len(res.Hits) != 1 || res.Hits[0].ServiceID != 15 || res.Hits[0].Port != 22 || res.Hits[0].Match.Version != "9.6" || res.Hits[0].URL != "" {
		t.Errorf("hits = %+v", res.Hits)
	}
	// No observations.
	res = RetroHunt(briefExample, nil)
	if res.Scanned != 0 || res.Hits == nil || res.MissingPaths == nil || res.Notes == nil {
		t.Errorf("empty input must give empty, non-nil lists: %+v", res)
	}
}

func TestRetroHuntRejectsUnsafeSignature(t *testing.T) {
	res := RetroHunt("id: evil\nname: Evil\nrequests:\n  - {path: /login, method: POST}\nbody: x\n", observations())
	if len(res.Hits) != 0 || res.Scanned != 0 || len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "Sygnatura odrzucona") || !strings.Contains(res.Notes[0], "POST") {
		t.Errorf("result = %+v", res)
	}
}

func TestRetroHuntDoesNotChangeObservations(t *testing.T) {
	obs := observations()
	RetroHunt(briefExample, obs)
	for _, o := range obs {
		if o.Result.Matches != nil || o.Result.Technologies != nil || o.Result.Classes != nil {
			t.Fatal("retro-hunt must not write to the stored observations")
		}
	}
}
