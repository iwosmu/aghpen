package sigsuggest

import (
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/sig"
)

const kioskBody = `<!doctype html>
<html lang="pl"><head><meta charset="utf-8"><title>Informator — kiosk k-7f3a</title>
<link href="/static/ik/kiosk.css" rel="stylesheet"><script src="/static/js/jquery-3.6.0.min.js"></script>
<script src="/static/app.3f9a1c2b7d4e5f60.js"></script></head><body>
<!-- InfoKiosk build 4.2.1 -->
<main class="ik-screen container"><h1>Plan zajęć</h1></main>
<footer class="ik-footer">InfoKiosk v4.2.1 &middot; węzeł k-7f3a 2026-11-21 10:00:01</footer></body></html>`

func kiosk() *model.ServiceResult {
	fav := int32(-1234567)
	return &model.ServiceResult{Port: 80, Name: "http", HTTP: &model.HTTPFingerprint{Scheme: "http", Status: 200,
		Title: "Informator — kiosk k-7f3a", FaviconMMH3: &fav, BodyExcerpt: kioskBody,
		Headers: map[string][]string{"Server": {"ik-httpd/2.1"}, "X-Infokiosk-Node": {"k-7f3a"}, "Date": {"Sat, 21 Nov 2026 10:00:00 GMT"},
			"X-Request-Id": {"9f2c1d7a5b3e48609f2c"}, "Content-Type": {"text/html"}},
		Cookies: []model.Cookie{{Name: "infokiosk_sid"}, {Name: "PHPSESSID"}, {Name: "tok_8f3a9c2e1d4b5a6f"}}}}
}

func keysOf(fs []Feature) map[string]Feature {
	m := map[string]Feature{}
	for _, f := range fs {
		m[f.Key] = f
	}
	return m
}

func TestExtract(t *testing.T) {
	fs, rej := Extract(kiosk())
	m := keysOf(fs)
	for _, k := range []string{"hname:x-infokiosk-node", "hval:server:ik-httpd", "cookie:infokiosk_sid", "favicon:-1234567",
		"title^informator — kiosk", "asset:/static/ik/kiosk.css", "css:ik-screen", "css:ik-footer", "comment:infokiosk build", "vtext:infokiosk"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing feature %s; have %v", k, keys(m))
		}
	}
	for _, k := range []string{"hname:date", "hname:x-request-id", "hname:content-type", "css:container", "asset:/static/js/jquery-3.6.0.min.js"} {
		if _, ok := m[k]; ok {
			t.Errorf("feature %s must not be a candidate", k)
		}
	}
	if m["cookie:phpsessid"].Strength >= 0.5 {
		t.Errorf("generic cookie must be weak")
	}
	var why []string
	for _, r := range rej {
		why = append(why, r.Value+" => "+r.Reason)
	}
	joined := strings.Join(why, "\n")
	for _, v := range []string{"tok_8f3a9c2e1d4b5a6f", "/static/app.3f9a1c2b7d4e5f60.js"} {
		if !strings.Contains(joined, v) {
			t.Errorf("%s must be rejected as volatile; rejected: %s", v, joined)
		}
	}
	if f := m["vtext:infokiosk"]; f.Product != "InfoKiosk" || !strings.Contains(f.Version, "InfoKiosk") {
		t.Errorf("version text: %+v", f)
	}
	if f := m["hval:server:ik-httpd"]; f.Version == "" {
		t.Errorf("server header version rule missing: %+v", f)
	}
}

func keys(m map[string]Feature) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Every rule the extractor emits is valid DSL and matches the example.
func TestEmittedRulesMatchTheExample(t *testing.T) {
	fs, _ := Extract(kiosk())
	for _, f := range fs {
		y := "id: t\nname: T\nmatch:\n  min_confidence: 0.1\n  rules:\n    - " + strings.TrimSuffix(f.Rule, "}") + ", weight: 0.9}\n"
		if f.Version != "" {
			y += "version:\n  - " + f.Version + "\n"
		}
		val := sig.Validate(y)
		if !val.OK {
			t.Errorf("%s: invalid rule %s: %+v", f.Key, f.Rule, val.Issues)
			continue
		}
		res := sig.RetroHunt(y, []model.ServiceObservation{{ServiceID: 1, Result: *kiosk()}})
		if res.TotalHits != 1 {
			t.Errorf("%s: rule %s does not match the example", f.Key, f.Rule)
			continue
		}
		if f.Version != "" && res.Hits[0].Match.Version == "" {
			t.Errorf("%s: version rule %s extracts nothing", f.Key, f.Version)
		}
	}
}

func TestTitlePrefixAndVolatile(t *testing.T) {
	for in, want := range map[string]string{"Informator — kiosk k-7f3a": "Informator — kiosk", "Printer 42": "Printer", "12 Monkeys": "", "Ab 1": ""} {
		if got := titlePrefix(in); got != want {
			t.Errorf("titlePrefix(%q) = %q, want %q", in, got, want)
		}
	}
	for _, v := range []string{"2026-11-21", "9f2c1d7a5b3e4860", "550e8400-e29b-41d4-a716-446655440000", "1700000000", "eyJhbGciOiJIUzI1NiJ9abcdef12"} {
		if !volatile(v) {
			t.Errorf("%s must be volatile", v)
		}
	}
	for _, v := range []string{"ik-httpd", "X-InfoKiosk-Node", "/static/ik/kiosk.css", "k-7f3a"} {
		if volatile(v) {
			t.Errorf("%s must not be volatile", v)
		}
	}
}
