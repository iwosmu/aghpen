package analyze

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// stored round-trips a change through JSON, as the store returns it:
// numbers become float64, lists []any.
func stored(t *testing.T, c model.Change) model.Change {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out model.Change
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

type kindCase struct {
	c      model.Change
	pl, en string
}

func allKindCases() []kindCase {
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	ch := func(k model.ChangeKind, port int, field string, before, after any, expected bool, d map[string]any) model.Change {
		return model.Change{Kind: k, IP: "10.0.0.5", Port: port, At: at, Field: field, Before: before, After: after, Expected: expected, Detail: d,
			Summary: "stary tekst"}
	}
	cert := map[string]any{"subject_cn": "portal.example", "issuer": "R3", "not_after": "2028-02-03T00:00:00Z", "sha256": "bb"}
	return []kindCase{
		{ch(model.ChangeHostNew, 0, "status", nil, "up", false, map[string]any{DetailPorts: []int{80, 22}}),
			"Nowy host 10.0.0.5 (otwarte porty: 22, 80)", "New host 10.0.0.5 (open ports: 22, 80)"},
		{ch(model.ChangeHostGone, 0, "status", StatusMissing, "down", false, map[string]any{DetailRule: 3, DetailPAlive: 0.12}),
			"Host 10.0.0.5 nieaktywny, nie odpowiada od 3 skanów", "Host 10.0.0.5 down, not responding for 3 scans"},
		{ch(model.ChangeHostBack, 0, "status", "down", "up", false, nil),
			"Host 10.0.0.5 znów aktywny (był nieaktywny)", "Host 10.0.0.5 up again (was down)"},
		{ch(model.ChangeHostUnstable, 0, "status", "up", "unstable", true, map[string]any{DetailStabilityPct: 55}),
			"Host 10.0.0.5 niestabilny (aktywny w ok. 55% skanów)", "Host 10.0.0.5 unstable (up in about 55% of scans)"},
		{ch(model.ChangeHostMissing, 0, "status", "up", StatusMissing, false, map[string]any{DetailOpenServices: 2, DetailPAlive: 0.6}),
			"Host 10.0.0.5 nie odpowiada (niepotwierdzone), miał 2 otwarte usługi", "Host 10.0.0.5 not responding (unconfirmed), had 2 open services"},
		{ch(model.ChangeServiceUnreachable, 22, "state", "open", "unknown", false, map[string]any{DetailName: "ssh OpenSSH"}),
			"Usługa 10.0.0.5:22 (ssh OpenSSH) nie odpowiada (niepotwierdzone), host nie odpowiada",
			"Service 10.0.0.5:22 (ssh OpenSSH) not responding (unconfirmed), host not responding"},
		{ch(model.ChangeServiceNew, 8080, "state", nil, "open", false, map[string]any{DetailProduct: "Jenkins 2.440"}),
			"Nowa usługa 10.0.0.5:8080 (Jenkins 2.440)", "New service 10.0.0.5:8080 (Jenkins 2.440)"},
		{ch(model.ChangeServiceGone, 80, "state", "open", "host-down", false, map[string]any{DetailProduct: "nginx"}),
			"Usługa 10.0.0.5:80 zniknęła (nginx), host nieaktywny", "Service 10.0.0.5:80 gone (nginx), host down"},
		{ch(model.ChangeServiceChanged, 443, "version", "1.24.0", "1.26.1", false, map[string]any{DetailProduct: "nginx"}),
			"Zmiana wersji 10.0.0.5:443: nginx 1.24.0 → nginx 1.26.1", "Version changed 10.0.0.5:443: nginx 1.24.0 → nginx 1.26.1"},
		{ch(model.ChangeTechNew, 443, "technologies", nil, "PHP 8.2", false, nil),
			"Nowa technologia PHP 8.2 na 10.0.0.5:443", "New technology PHP 8.2 on 10.0.0.5:443"},
		{ch(model.ChangeTechGone, 443, "technologies", "WordPress 6.4", nil, false, nil),
			"Technologia WordPress 6.4 zniknęła z 10.0.0.5:443", "Technology WordPress 6.4 gone from 10.0.0.5:443"},
		{ch(model.ChangeTechVersion, 443, "technologies.WordPress", "6.4", "6.5", false, nil),
			"Zmiana wersji WordPress, 10.0.0.5:443: 6.4 → 6.5", "Version changed WordPress, 10.0.0.5:443: 6.4 → 6.5"},
		{ch(model.ChangeTitle, 443, "http.title", "Portal", "", false, nil),
			"Zmiana tytułu strony 10.0.0.5:443: „Portal” → (brak)", "Page title changed 10.0.0.5:443: “Portal” → (none)"},
		{ch(model.ChangeHTTPStatus, 443, "http.status", 200, 503, false, nil),
			"Zmiana kodu HTTP 10.0.0.5:443: 200 → 503", "HTTP status changed 10.0.0.5:443: 200 → 503"},
		{ch(model.ChangeCert, 443, "tls.sha256", cert, cert, false, map[string]any{DetailSelfSigned: true}),
			"Nowy certyfikat TLS 10.0.0.5:443: portal.example, ważny do 2028-02-03, samopodpisany",
			"New TLS certificate 10.0.0.5:443: portal.example, valid until 2028-02-03, self-signed"},
		{ch(model.ChangeHeaders, 443, "http.headers", []string{"Content-Type", "Server"}, []string{"Server", "X-Powered-By"}, false,
			map[string]any{DetailValues: []string{"Server: nginx → Apache"}}),
			"Zmiana nagłówków 10.0.0.5:443: dodano X-Powered-By; usunięto Content-Type; Server: nginx → Apache",
			"Headers changed 10.0.0.5:443: added X-Powered-By; removed Content-Type; Server: nginx → Apache"},
		{ch(model.ChangeCookies, 443, "http.cookies", []string{"PHPSESSID"}, []string{"PHPSESSID"}, false,
			map[string]any{DetailFlags: []string{"PHPSESSID: Secure+HttpOnly → bez flag"}}),
			"Zmiana ciasteczek 10.0.0.5:443: PHPSESSID: Secure+HttpOnly → bez flag", "Cookies changed 10.0.0.5:443: PHPSESSID: Secure+HttpOnly → no flags"},
		{ch(model.ChangeContent, 443, "http.body_simhash", "ffff0000ffff0000", "0000ffff0000ffff", false, map[string]any{DetailDistance: 64}),
			"Zmiana treści strony 10.0.0.5:443", "Page content changed 10.0.0.5:443"},
		{ch(model.ChangeRedirect, 443, "http.final_url", "", "https://sso.example/login", false, nil),
			"Zmiana przekierowania 10.0.0.5:443: (brak) → https://sso.example/login", "Redirect changed 10.0.0.5:443: (none) → https://sso.example/login"},
		{ch(model.ChangeClass, 443, "classes", []string{"login"}, []string{"admin-panel"}, false, nil),
			"Zmiana klas usługi 10.0.0.5:443: dodano panel administracyjny; usunięto strona logowania",
			"Service classes changed 10.0.0.5:443: added admin panel; removed login page"},
		{ch(model.ChangeServiceReturned, 8787, "state", map[string]any{"state": "gone", "away_seconds": 7200, "runs_away": 1}, "open", false,
			map[string]any{DetailProduct: "http"}),
			"Usługa 10.0.0.5:8787 wróciła po 2 h (http)", "Service 10.0.0.5:8787 back after 2 h (http)"},
		{ch(model.ChangeResponseSlower, 80, "http.response_ms", map[string]any{"baseline_ms": 40, "ms": 41}, map[string]any{"ms": 900}, false, nil),
			"Usługa 10.0.0.5:80 odpowiada wolniej: 900 ms (zwykle 40 ms)", "Service 10.0.0.5:80 responds slower: 900 ms (usually 40 ms)"},
		{ch(model.ChangeResponseRecovered, 80, "http.response_ms", map[string]any{"baseline_ms": 40, "ms": 900}, map[string]any{"ms": 42}, false, nil),
			"Usługa 10.0.0.5:80 znów szybka: 42 ms (zwykle 40 ms)", "Service 10.0.0.5:80 fast again: 42 ms (usually 40 ms)"},
	}
}

// Every change kind renders in both languages from a stored row; none falls
// back to the stored text.
func TestRenderSummaryAllKindsBothLanguages(t *testing.T) {
	cases := allKindCases()
	seen := map[model.ChangeKind]bool{}
	for _, k := range cases {
		seen[k.c.Kind] = true
		for _, c := range []model.Change{k.c, stored(t, k.c)} {
			if got := RenderSummary(c, "pl"); got != k.pl {
				t.Errorf("%s pl:\n got %q\nwant %q", c.Kind, got, k.pl)
			}
			if got := RenderSummary(c, "en"); got != k.en {
				t.Errorf("%s en:\n got %q\nwant %q", c.Kind, got, k.en)
			}
		}
		if strings.ContainsAny(k.en, "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ") {
			t.Errorf("%s: Polish letters in the English text %q", k.c.Kind, k.en)
		}
	}
	if len(seen) != 23 {
		t.Errorf("cases cover %d kinds, want all 23", len(seen))
	}
	if got := RenderSummary(model.Change{Kind: "future_kind", Summary: "zapisany tekst"}, "en"); got != "zapisany tekst" {
		t.Errorf("unknown kind: %q", got)
	}
}

// Rows written before Change.Detail existed: their Polish summaries as the
// analysis wrote them (copied from the build before this change). Each one
// renders in the current wording, in both languages.
func TestRenderSummaryOldRows(t *testing.T) {
	cert := map[string]any{"subject_cn": "portal.example", "not_after": "2025-02-03T00:00:00Z"}
	old := []kindCase{
		{model.Change{Kind: model.ChangeHostNew, IP: "10.66.3.17", Field: "status", After: "up", Summary: "Nowy host 10.66.3.17 (otwarte porty: 22, 8080)"},
			"Nowy host 10.66.3.17 (otwarte porty: 22, 8080)", "New host 10.66.3.17 (open ports: 22, 8080)"},
		{model.Change{Kind: model.ChangeHostGone, IP: "10.66.3.17", Field: "status", Before: "unstable", After: "down",
			Summary: "Host 10.66.3.17 zgłoszony jako nieaktywny: brak odpowiedzi w 2 przebiegach z rzędu (reguła profilu: zgłoszenie po 2 brakach)"},
			"Host 10.66.3.17 nieaktywny, nie odpowiada od 2 skanów", "Host 10.66.3.17 down, not responding for 2 scans"},
		{model.Change{Kind: model.ChangeHostGone, IP: "10.66.3.17", Field: "status", Before: "unstable", After: "down",
			Summary: "Host 10.66.3.17 zgłoszony jako nieaktywny: nie odpowiada w godzinach, w których zwykle odpowiadał; model: p_alive 0,15"},
			"Host 10.66.3.17 nieaktywny, nie odpowiada w zwykłych godzinach", "Host 10.66.3.17 down, not responding in its usual hours"},
		{model.Change{Kind: model.ChangeHostGone, IP: "10.0.0.2", Field: "status", Before: "up", After: "expected-offline", Expected: true,
			Summary: "Host 10.0.0.2 nie odpowiada, zgodnie z profilem dostępności (zwykle aktywny w godz. 08–16)"},
			"Host 10.0.0.2 poza godzinami (zwykle aktywny 08–16)", "Host 10.0.0.2 outside usual hours (usually up 08–16)"},
		{model.Change{Kind: model.ChangeHostBack, IP: "10.0.0.2", Field: "status", Before: "expected-offline", After: "up", Expected: true,
			Summary: "Host 10.0.0.2 znów odpowiada, zgodnie z profilem dostępności (zwykle aktywny pn–pt 08–16)"},
			"Host 10.0.0.2 znów aktywny (zwykle aktywny pn–pt 08–16)", "Host 10.0.0.2 up again (usually up Mon–Fri 08–16)"},
		{model.Change{Kind: model.ChangeHostBack, IP: "10.0.0.2", Field: "status", Before: "unstable", After: "up",
			Summary: "Host 10.0.0.2 znów odpowiada po chwilowym braku odpowiedzi"},
			"Host 10.0.0.2 znów aktywny", "Host 10.0.0.2 up again"},
		{model.Change{Kind: model.ChangeHostUnstable, IP: "10.0.0.2", Field: "status", Before: "up", After: "unstable", Expected: true,
			Summary: "Host 10.0.0.2 nie odpowiedział; odpowiada nieregularnie (w ok. 50% skanów) (odpowiada w ok. 50% skanów (zegar laboratoryjny: 5m0s × 12), zwykle nieaktywny w kubełkach 3,4,5)"},
			"Host 10.0.0.2 niestabilny (aktywny w ok. 50% skanów)", "Host 10.0.0.2 unstable (up in about 50% of scans)"},
		{model.Change{Kind: model.ChangeHostUnstable, IP: "10.0.0.2", Field: "status", Before: "expected-offline", After: "unstable",
			Summary: "Host 10.0.0.2 nie odpowiedział w porze, w której zwykle odpowiada; jeszcze nie jest zgłoszony jako nieaktywny"},
			"Host 10.0.0.2 nie odpowiada w zwykłych godzinach (niepotwierdzone)", "Host 10.0.0.2 not responding in its usual hours (unconfirmed)"},
		{model.Change{Kind: model.ChangeHostMissing, IP: "10.66.1.80", Field: "status", Before: "up", After: "missing",
			Summary: "Host 10.66.1.80 nie odpowiada (niepotwierdzone): w poprzednim przebiegu odpowiadał i miał 2 otwarte usługi: 22/tcp ssh OpenSSH, 80/tcp http nginx; model: p_alive 0,62, zgłoszenie nieaktywności po 2 kolejnych brakach"},
			"Host 10.66.1.80 nie odpowiada (niepotwierdzone), miał 2 otwarte usługi", "Host 10.66.1.80 not responding (unconfirmed), had 2 open services"},
		{model.Change{Kind: model.ChangeServiceUnreachable, IP: "10.66.1.80", Port: 22, Field: "state", Before: "open", After: "unknown",
			Summary: "Usługa 10.66.1.80:22 (ssh OpenSSH) nie odpowiada (niepotwierdzone): host nie odpowiedział w tym przebiegu"},
			"Usługa 10.66.1.80:22 (ssh OpenSSH) nie odpowiada (niepotwierdzone), host nie odpowiada",
			"Service 10.66.1.80:22 (ssh OpenSSH) not responding (unconfirmed), host not responding"},
		{model.Change{Kind: model.ChangeServiceNew, IP: "10.66.3.17", Port: 8080, Field: "state", After: "open", Summary: "Nowa usługa 10.66.3.17:8080 (Jetty 10.0.20)"},
			"Nowa usługa 10.66.3.17:8080 (Jetty 10.0.20)", "New service 10.66.3.17:8080 (Jetty 10.0.20)"},
		{model.Change{Kind: model.ChangeServiceGone, IP: "10.66.2.5", Port: 80, Field: "state", Before: "open", After: "host-down",
			Summary: "Usługa 10.66.2.5:80 zniknęła (nginx 1.24.0): host zgłoszony jako nieaktywny"},
			"Usługa 10.66.2.5:80 zniknęła (nginx 1.24.0), host nieaktywny", "Service 10.66.2.5:80 gone (nginx 1.24.0), host down"},
		{model.Change{Kind: model.ChangeServiceReturned, IP: "192.168.65.254", Port: 8787, Field: "state",
			Before: map[string]any{"away_seconds": float64(7200), "runs_away": float64(1)}, After: "open",
			Summary: "Usługa 192.168.65.254:8787 wróciła po 2 h (nie było jej w 1 skanie) (http)"},
			"Usługa 192.168.65.254:8787 wróciła po 2 h (http)", "Service 192.168.65.254:8787 back after 2 h (http)"},
		{model.Change{Kind: model.ChangeServiceChanged, IP: "10.0.0.9", Port: 443, Field: "version", Before: "1.24.0", After: "1.26.1",
			Summary: "Zmiana wersji 10.0.0.9:443: nginx 1.24.0 → nginx 1.26.1"},
			"Zmiana wersji 10.0.0.9:443: nginx 1.24.0 → nginx 1.26.1", "Version changed 10.0.0.9:443: nginx 1.24.0 → nginx 1.26.1"},
		{model.Change{Kind: model.ChangeServiceChanged, IP: "10.0.0.9", Port: 22, Field: "name", Before: "ssh", After: "telnet",
			Summary: "Zmiana usługi 10.0.0.9:22: ssh → telnet"},
			"Zmiana nazwy usługi 10.0.0.9:22: ssh → telnet", "Service name changed 10.0.0.9:22: ssh → telnet"},
		{model.Change{Kind: model.ChangeTechGone, IP: "10.0.0.9", Port: 443, Field: "technologies", Before: "WordPress 6.4",
			Summary: "Technologia WordPress 6.4 nie jest już widoczna na 10.0.0.9:443"},
			"Technologia WordPress 6.4 zniknęła z 10.0.0.9:443", "Technology WordPress 6.4 gone from 10.0.0.9:443"},
		{model.Change{Kind: model.ChangeCert, IP: "10.0.0.9", Port: 443, At: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), Field: "tls.sha256", After: cert,
			Summary: "Nowy certyfikat TLS 10.0.0.9:443: portal.example, ważny do 2025-02-03, nowy certyfikat jest przeterminowany"},
			"Nowy certyfikat TLS 10.0.0.9:443: portal.example, ważny do 2025-02-03, przeterminowany",
			"New TLS certificate 10.0.0.9:443: portal.example, valid until 2025-02-03, expired"},
		{model.Change{Kind: model.ChangeHeaders, IP: "10.0.0.9", Port: 443, Field: "http.headers", Before: []any{"Server"}, After: []any{"Server"},
			Summary: "Zmiana nagłówków 10.0.0.9:443: Server: nginx → Apache"},
			"Zmiana nagłówków 10.0.0.9:443: Server: nginx → Apache", "Headers changed 10.0.0.9:443: Server: nginx → Apache"},
		{model.Change{Kind: model.ChangeContent, IP: "10.0.0.9", Port: 443, Field: "http.body_simhash", Before: "ffff", After: "0000",
			Summary: "Treść strony 10.0.0.9:443 zmieniła się wyraźnie (odległość simhash 64/64)"},
			"Zmiana treści strony 10.0.0.9:443", "Page content changed 10.0.0.9:443"},
		{model.Change{Kind: model.ChangeClass, IP: "10.0.0.9", Port: 443, Field: "classes", Before: []any{}, After: []any{"admin-panel"},
			Summary: "Zmiana klasy usługi 10.0.0.9:443 (teraz: panel administracyjny)"},
			"Zmiana klas usługi 10.0.0.9:443: dodano panel administracyjny", "Service classes changed 10.0.0.9:443: added admin panel"},
		{model.Change{Kind: model.ChangeResponseSlower, IP: "10.0.0.9", Port: 80, Field: "http.response_ms",
			Before: map[string]any{"baseline_ms": float64(0), "ms": float64(1)}, After: map[string]any{"ms": nil, "error": "no_answer"},
			Summary: "Usługa 10.0.0.9:80: port otwarty, ale HTTP nie odpowiedział w czasie (zwykle poniżej 1 ms)"},
			"Usługa 10.0.0.9:80 nie odpowiada na HTTP, port otwarty (zwykle poniżej 1 ms)",
			"Service 10.0.0.9:80 not responding to HTTP, port open (usually under 1 ms)"},
	}
	for _, k := range old {
		if got := RenderSummary(k.c, "pl"); got != k.pl {
			t.Errorf("%s pl:\n got %q\nwant %q", k.c.Kind, got, k.pl)
		}
		if got := RenderSummary(k.c, "en"); got != k.en {
			t.Errorf("%s en:\n got %q\nwant %q", k.c.Kind, got, k.en)
		}
	}
}

func TestPatternText(t *testing.T) {
	for _, c := range []struct{ in, pl, en string }{
		{"zwykle aktywny pn–pt 08–16", "zwykle aktywny pn–pt 08–16", "usually up Mon–Fri 08–16"},
		{"zwykle aktywny pn, śr, pt", "zwykle aktywny pn, śr, pt", "usually up Mon, Wed, Fri"},
		{"zwykle aktywny codziennie 22–06", "zwykle aktywny codziennie 22–06", "usually up daily 22–06"},
		{"odpowiada stale (100% skanów)", "aktywny stale (100% skanów)", "always up (100% of scans)"},
		{"odpowiada w ok. 50% skanów, bez wzorca dobowego", "aktywny w ok. 50% skanów, bez wzorca", "up in about 50% of scans, no pattern"},
		{"odpowiada w ok. 40% skanów (zegar laboratoryjny: 5m0s × 12), zwykle nieaktywny w kubełkach 3,4", "aktywny w ok. 40% skanów", "up in about 40% of scans"},
	} {
		if got := PatternText(c.in, "pl"); got != c.pl {
			t.Errorf("pl %q: %q", c.in, got)
		}
		if got := PatternText(c.in, "en"); got != c.en {
			t.Errorf("en %q: %q", c.in, got)
		}
	}
}

// A change of a service that the deep pass scanned says so in one short addition.
func TestSummaryNamesTheDeepPass(t *testing.T) {
	c := model.Change{Kind: model.ChangeServiceNew, IP: "10.0.0.5", Port: 40000, Field: "state", After: "open", DeepPass: true,
		Detail: map[string]any{DetailProduct: "nginx"}}
	if got := RenderSummary(c, "pl"); got != "Nowa usługa 10.0.0.5:40000 (nginx) (głębszy przebieg)" {
		t.Errorf("pl = %q", got)
	}
	if got := RenderSummary(c, "en"); !strings.HasSuffix(got, " (deeper pass)") {
		t.Errorf("en = %q", got)
	}
	c.DeepPass = false
	if got := RenderSummary(c, "pl"); strings.Contains(got, "głębszy") {
		t.Errorf("without the flag: %q", got)
	}
}
