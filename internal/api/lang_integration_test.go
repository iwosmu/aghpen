package api

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/rules"
	"github.com/iwosmu/aghpen/internal/store"
)

// Findings written by the current build (Polish text in the database) come
// out unchanged in Polish and in English with ?lang=en or Accept-Language.
// The stored rows are not touched.
func TestFindingsInBothLanguages(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	ctx := context.Background()
	run, _ := e.st.CreateRun(ctx, model.ScanRun{Status: model.RunCompleted})
	svc := model.ServiceResult{Port: 8080, Proto: "tcp", State: "open", Name: "http",
		HTTP:    &model.HTTPFingerprint{Scheme: "http", URL: "http://10.90.0.1:8080/", Status: 200, Title: "Adminer", Headers: map[string][]string{"X-Powered-By": {"PHP/8.2.1"}}},
		Matches: []model.SigMatch{{Signature: "adminer", Name: "Adminer", Confidence: 0.95, Interest: 40, Classes: []string{model.ClassAdminPanel}}}}
	if err := e.st.IngestHosts(ctx, []model.HostResult{{RunID: run.ID, IP: "10.90.0.1", Up: true, Services: []model.ServiceResult{svc}}}, store.SinkOptions{}); err != nil {
		t.Fatal(err)
	}
	hosts, err := e.st.ListHosts(ctx, store.HostFilter{})
	if err != nil || len(hosts.Items) != 1 {
		t.Fatalf("hosts: %v %+v", err, hosts)
	}
	hid := hosts.Items[0].ID
	at := time.Now().UTC()
	fs := analyze.DeriveFindings(analyze.FindingInput{HostID: hid, IP: "10.90.0.1", RunID: run.ID, At: at,
		Services: []analyze.FindingService{{Result: svc}}})
	builtin, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range builtin {
		if r.ID == "default-server-page" {
			v := rules.Violation{Rule: r.ID, Subject: rules.SubjectService, Key: rules.KeyPrefix(r.ID) + "10.90.0.1/tcp-8080", HostID: hid, IP: "10.90.0.1", Port: 8080,
				Evidence: []model.Evidence{{Matcher: "policy", Where: "rule", Snippet: r.ID}}}
			fs = append(fs, v.Finding(r, run.ID, at))
		}
	}
	if _, err := e.st.UpsertFindings(ctx, fs); err != nil {
		t.Fatal(err)
	}

	titles := func(path string, hdr map[string]string) map[string]model.Finding {
		resp, raw := admin.raw("GET", path, nil, hdr)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, raw)
		}
		var page model.Page[model.Finding]
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatal(err)
		}
		out := map[string]model.Finding{}
		for _, f := range page.Items {
			out[f.Type] = f
		}
		return out
	}
	pl := titles("/api/v1/findings", nil)
	for _, f := range fs {
		got, ok := pl[f.Type]
		if !ok || got.Title != f.Title || got.Description != f.Description {
			t.Errorf("Polish %s: got %q / %q, stored %q / %q", f.Type, got.Title, got.Description, f.Title, f.Description)
		}
	}
	for _, en := range []map[string]model.Finding{
		titles("/api/v1/findings?lang=en", nil),
		titles("/api/v1/findings", map[string]string{"Accept-Language": "en-GB,en;q=0.9"}),
	} {
		if got := en[analyze.FindingAdminPanel].Title; got != "Admin panel: Adminer (10.90.0.1:8080)" {
			t.Errorf("admin panel title = %q", got)
		}
		if got := en[analyze.FindingHeader].Title; got != "HTTP headers: X-Powered-By (10.90.0.1:8080)" {
			t.Errorf("header title = %q", got)
		}
		p := en[analyze.PolicyFindingType]
		if p.Title != "Default server page — 10.90.0.1:8080" || !strings.Contains(p.Description, "Exposure rule “default-server-page” violated. Condition: class default-page.") ||
			!strings.Contains(p.Description, "Remediation: Turn off the unused server") {
			t.Errorf("rule finding = %q / %q", p.Title, p.Description)
		}
	}
	// The database keeps the Polish text.
	stored, err := e.st.GetFinding(ctx, pl[analyze.FindingAdminPanel].ID)
	if err != nil || stored.Title != "Panel administracyjny: Adminer (10.90.0.1:8080)" {
		t.Errorf("stored title = %q (%v)", stored.Title, err)
	}
	// One finding and the dashboard follow the language too.
	var one model.Finding
	resp, raw := admin.raw("GET", "/api/v1/findings/"+i64s(stored.ID)+"?lang=en", nil, nil)
	_ = json.Unmarshal(raw, &one)
	if resp.StatusCode != 200 || one.Title != "Admin panel: Adminer (10.90.0.1:8080)" || resp.Header.Get("Content-Language") != "en" {
		t.Errorf("GET /findings/{id}: %d %q %q", resp.StatusCode, one.Title, resp.Header.Get("Content-Language"))
	}
	var d model.Dashboard
	_, raw = admin.raw("GET", "/api/v1/dashboard", nil, map[string]string{"Accept-Language": "en"})
	_ = json.Unmarshal(raw, &d)
	for _, f := range d.TopFindings {
		if strings.Contains(f.Title, "Panel administracyjny") || strings.Contains(f.Title, "Domyślna strona") {
			t.Errorf("dashboard finding in Polish: %q", f.Title)
		}
	}
}

// An error message follows the language of the request.
func TestErrorMessageInEnglish(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	if err := e.st.UpsertBuiltinSignatures(context.Background(), []model.Signature{{Slug: "header-version-powered-by", Name: "Wersja oprogramowania w X-Powered-By",
		Category: "header", YAML: "id: header-version-powered-by\n", Enabled: true, Builtin: true}}); err != nil {
		t.Fatal(err)
	}
	var sigs model.Page[model.Signature]
	admin.want(200, "GET", "/api/v1/signatures?limit=500", nil, &sigs)
	var builtin model.Signature
	for _, g := range sigs.Items {
		if g.Builtin {
			builtin = g
			break
		}
	}
	if builtin.ID == 0 {
		t.Fatal("no built-in signature")
	}
	// The list names a built-in signature in English.
	var sigsEN model.Page[model.Signature]
	admin.want(200, "GET", "/api/v1/signatures?limit=500&lang=en", nil, &sigsEN)
	for _, g := range sigsEN.Items {
		if g.ID == builtin.ID && g.Name != "Software version in X-Powered-By" {
			t.Errorf("signature name in English = %q", g.Name)
		}
	}
	for lang, want := range map[string]string{"pl": "Sygnatury wbudowanej nie można usunąć. Wyłącz ją.", "en": "A built-in signature cannot be deleted. Disable it."} {
		resp, raw := admin.raw("DELETE", "/api/v1/signatures/"+i64s(builtin.ID)+"?lang="+lang, nil, map[string]string{auth.CSRFHeader: admin.csrf})
		var body struct {
			Error apiError `json:"error"`
		}
		_ = json.Unmarshal(raw, &body)
		if resp.StatusCode != 403 || body.Error.Message != want {
			t.Errorf("%s: %d %q", lang, resp.StatusCode, body.Error.Message)
		}
	}
}

func i64s(n int64) string { return strconv.FormatInt(n, 10) }
