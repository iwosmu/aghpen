package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/crypto"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// upgradeWant is the summary of each change of testdata/changes_before_0007.json
// (in id order) after the upgrade, in Polish and in English.
var upgradeWant = [][2]string{
	{"Zmiana wersji 10.66.0.10:80: nginx 1.24.0 → nginx 1.26.1", "Version changed 10.66.0.10:80: nginx 1.24.0 → nginx 1.26.1"},
	{"Zmiana wersji WordPress, 10.66.0.10:80: 6.4 → 6.5", "Version changed WordPress, 10.66.0.10:80: 6.4 → 6.5"},
	{"Zmiana klas usługi 10.66.0.10:80: dodano panel administracyjny", "Service classes changed 10.66.0.10:80: added admin panel"},
	{"Zmiana kodu HTTP 10.66.0.10:80: 200 → 503", "HTTP status changed 10.66.0.10:80: 200 → 503"},
	{"Zmiana tytułu strony 10.66.0.10:80: „Shop” → „Shop v2”", "Page title changed 10.66.0.10:80: “Shop” → “Shop v2”"},
	{"Zmiana nagłówków 10.66.0.10:80: dodano X-Powered-By; usunięto Content-Type; Server: nginx → Apache",
		"Headers changed 10.66.0.10:80: added X-Powered-By; removed Content-Type; Server: nginx → Apache"},
	{"Zmiana ciasteczek 10.66.0.10:80: PHPSESSID: Secure+HttpOnly → HttpOnly", "Cookies changed 10.66.0.10:80: PHPSESSID: Secure+HttpOnly → HttpOnly"},
	{"Nowa usługa 10.66.0.10:8080 (Jetty 10.0.20)", "New service 10.66.0.10:8080 (Jetty 10.0.20)"},
	{"Host 10.66.0.20 nie odpowiada (niepotwierdzone), miał 2 otwarte usługi", "Host 10.66.0.20 not responding (unconfirmed), had 2 open services"},
	{"Usługa 10.66.0.20:22 (ssh OpenSSH) nie odpowiada (niepotwierdzone), host nie odpowiada",
		"Service 10.66.0.20:22 (ssh OpenSSH) not responding (unconfirmed), host not responding"},
	{"Usługa 10.66.0.20:5432 (postgresql) nie odpowiada (niepotwierdzone), host nie odpowiada",
		"Service 10.66.0.20:5432 (postgresql) not responding (unconfirmed), host not responding"},
	{"Nowy host 10.66.0.30 (otwarte porty: 22)", "New host 10.66.0.30 (open ports: 22)"},
	{"Nowa usługa 10.66.0.30:22 (OpenSSH 8.9)", "New service 10.66.0.30:22 (OpenSSH 8.9)"},
	{"Usługa 10.66.0.10:8080 zniknęła (Jetty 10.0.20)", "Service 10.66.0.10:8080 gone (Jetty 10.0.20)"},
	{"Usługa 10.66.0.10:8080 wróciła po 2 h (Jetty 10.0.20)", "Service 10.66.0.10:8080 back after 2 h (Jetty 10.0.20)"},
	{"Host 10.66.0.20 znów aktywny", "Host 10.66.0.20 up again"},
}

// loadOldChanges writes the changes of testdata/changes_before_0007.json,
// as the analysis of the build before migration 0007 stored them (summary
// text, no detail), into a fresh database.
func loadOldChanges(t *testing.T, url string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/changes_before_0007.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		IP, Kind, Severity, Field, Summary string
		Port                               int
		Expected                           bool
		Before, After                      json.RawMessage
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	at := time.Now().UTC().Add(-time.Hour)
	for _, r := range rows {
		var hostID int64
		if err := conn.QueryRow(ctx, `INSERT INTO hosts (ip) VALUES ($1::inet) ON CONFLICT (ip) DO UPDATE SET ip = EXCLUDED.ip RETURNING id`, r.IP).Scan(&hostID); err != nil {
			t.Fatal(err)
		}
		jsonOrNull := func(m json.RawMessage) any {
			if len(m) == 0 || string(m) == "null" {
				return nil
			}
			return string(m)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO changes (run_id, at, kind, severity, host_id, ip, port, summary, field, before, after, expected)
			VALUES (1, $1, $2, $3, $4, $5::inet, $6, $7, $8, $9::jsonb, $10::jsonb, $11)`,
			at, r.Kind, r.Severity, hostID, r.IP, r.Port, r.Summary, r.Field, jsonOrNull(r.Before), jsonOrNull(r.After), r.Expected); err != nil {
			t.Fatal(err)
		}
	}
}

// A database written by the build before this change holds change summaries
// in the old wording (stored text, no detail). After the upgrade the API
// returns the current wording for them, in Polish and in English.
//
// CZUJKA_UPGRADE_DB_URL names such a database written by the old build
// itself; the test migrates it in place. Without it the test loads the same
// rows, captured from that build, into a fresh database.
func TestUpgradeOldSummariesGetNewWording(t *testing.T) {
	storetest.URL(t) // skip without a test database server
	ctx := context.Background()
	var st *store.Store
	if u := os.Getenv("CZUJKA_UPGRADE_DB_URL"); u != "" {
		kr, err := crypto.NewKeyring(storetest.Key)
		if err != nil {
			t.Fatal(err)
		}
		loc, _ := time.LoadLocation("Europe/Warsaw")
		if st, err = store.Open(ctx, u, store.Options{Keyring: kr, Location: loc}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.Close)
		if err := st.Migrate(ctx); err != nil {
			t.Fatalf("upgrade: %v", err)
		}
	} else {
		var u string
		st, u = storetest.NewWithURL(t)
		loadOldChanges(t, u)
	}

	a := auth.New(st, auth.Config{PerMinute: 10000, MaxFails: 3})
	if _, err := a.Seed(ctx, "admin@example.org", adminPW); err != nil {
		t.Fatal(err)
	}
	bus := runner.NewBus()
	mgr := runner.New(st, runner.Options{Engine: quickEngine{}, Bus: bus})
	e := &env{t: t, st: st, mgr: mgr}
	e.srv = newTestServer(t, Deps{Store: st, Auth: a, Runner: mgr, Bus: bus, Version: "test", CookieSecure: "false"}, mgr)
	admin := e.login("admin@example.org", adminPW)

	list := func(path string, hdr map[string]string) []model.Change {
		t.Helper()
		resp, raw := admin.raw("GET", path, nil, hdr)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, raw)
		}
		var page model.Page[model.Change]
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatal(err)
		}
		return page.Items
	}
	pl := list("/api/v1/changes?sort=id&limit=200", nil)
	en := list("/api/v1/changes?sort=id&limit=200&lang=en", nil)
	hdr := list("/api/v1/changes?sort=id&limit=200", map[string]string{"Accept-Language": "en-US,en;q=0.9"})
	if len(pl) != len(upgradeWant) || len(en) != len(pl) || len(hdr) != len(pl) {
		t.Fatalf("changes: %d pl, %d en, %d by header, want %d", len(pl), len(en), len(hdr), len(upgradeWant))
	}
	for i, w := range upgradeWant {
		if pl[i].Summary != w[0] {
			t.Errorf("%d %s pl:\n got %q\nwant %q", i, pl[i].Kind, pl[i].Summary, w[0])
		}
		if en[i].Summary != w[1] || hdr[i].Summary != w[1] {
			t.Errorf("%d %s en:\n got %q / %q\nwant %q", i, en[i].Kind, en[i].Summary, hdr[i].Summary, w[1])
		}
	}
	// Detail of one change, and the export, follow the same rules.
	var one model.Change
	admin.want(200, "GET", fmt.Sprintf("/api/v1/changes/%d?lang=en", en[8].ID), nil, &one)
	if one.Summary != upgradeWant[8][1] {
		t.Errorf("detail en: %q", one.Summary)
	}
	resp, raw := admin.raw("GET", "/api/v1/export/changes.csv?lang=en", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(raw), upgradeWant[8][1]) || strings.Contains(string(raw), "przebieg") {
		t.Errorf("export: %d %s", resp.StatusCode, raw)
	}
}
