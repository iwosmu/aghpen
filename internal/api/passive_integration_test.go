package api

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/passive"
)

type fakeSigImporter struct{ got string }

func (f *fakeSigImporter) ImportSignatures(_ context.Context, text, author string) (SignatureImportReport, error) {
	f.got = text
	rep := SignatureImportReport{Created: []string{}, Updated: []string{}, Skipped: []SignatureImportSkip{}}
	if strings.Contains(text, "id: ok") {
		rep.Created = append(rep.Created, "ok")
	} else {
		rep.Validation.Issues = []model.SignatureIssue{{Level: "error", Path: "[0]", Message: "unsafe"}}
	}
	return rep, nil
}

type fakeReporter struct{}

func (fakeReporter) RunReport(_ context.Context, runID int64, format string, w io.Writer) error {
	_, err := io.WriteString(w, "# report "+format)
	return err
}

type fakePassive struct{}

func (fakePassive) ImportFile(_ context.Context, name string, data []byte) (PassiveResult, error) {
	return PassiveResult{Result: passive.Result{Candidates: []passive.Candidate{{Kind: model.TargetIP, Value: "10.80.0.9", Sources: []string{"file:" + name}}}}}, nil
}
func (fakePassive) PTR(context.Context) (PassiveResult, error) {
	return PassiveResult{HostsUpdated: 2}, nil
}
func (fakePassive) CT(context.Context) (PassiveResult, error) {
	return PassiveResult{}, passive.ErrExternalDisabled
}

func multipartFile(t *testing.T, name, content string) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", name)
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestNewRoutesNotWired(t *testing.T) {
	e := setup(t, nil)
	admin := e.login("admin@example.org", adminPW)
	for _, p := range []string{"/api/v1/runs/1/report.html", "/api/v1/runs/1/report.md"} {
		resp, raw := admin.raw("GET", p, nil, nil)
		if resp.StatusCode != http.StatusNotImplemented || errCode(raw) != "not_wired" {
			t.Errorf("GET %s: %d %s", p, resp.StatusCode, raw)
		}
	}
	for _, p := range []string{"/api/v1/signatures/import", "/api/v1/passive/ptr", "/api/v1/passive/crtsh"} {
		if got := admin.do("POST", p, "x", nil); got != http.StatusNotImplemented {
			t.Errorf("POST %s: %d", p, got)
		}
	}
}

func TestSignatureImportReportAndPassiveRoutes(t *testing.T) {
	si := &fakeSigImporter{}
	e := setup(t, func(d *Deps) {
		d.SigImporter, d.Reporter, d.Passive = si, fakeReporter{}, fakePassive{}
		d.EngineInfo = func() map[string]any { return map[string]any{"prober": "nmap", "mode": "nmap-raw"} }
	})
	admin := e.login("admin@example.org", adminPW)
	ctx := context.Background()

	// healthz carries the prober
	resp, raw := admin.raw("GET", "/healthz", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(raw), `"mode":"nmap-raw"`) {
		t.Errorf("healthz: %d %s", resp.StatusCode, raw)
	}

	// signature import: multipart file, JSON text, nothing stored -> 422 with the report
	body, ct := multipartFile(t, "sigs.yaml", "id: ok\nname: OK\nbody: x")
	resp, raw = admin.raw("POST", "/api/v1/signatures/import", body, map[string]string{auth.CSRFHeader: admin.csrf, "Content-Type": ct})
	if resp.StatusCode != http.StatusCreated || !strings.Contains(string(raw), `"created":["ok"]`) {
		t.Fatalf("import file: %d %s", resp.StatusCode, raw)
	}
	var rep SignatureImportReport
	admin.want(http.StatusCreated, "POST", "/api/v1/signatures/import", map[string]string{"text": "id: ok"}, &rep)
	if si.got != "id: ok" {
		t.Errorf("JSON text: importer got %q", si.got)
	}
	resp, raw = admin.raw("POST", "/api/v1/signatures/import", "id: bad", map[string]string{auth.CSRFHeader: admin.csrf, "Content-Type": "text/yaml"})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(raw), "unsafe") {
		t.Errorf("rejected file: %d %s", resp.StatusCode, raw)
	}

	// report: format from the path, content type
	resp, raw = admin.raw("GET", "/api/v1/runs/7/report.md", nil, nil)
	if resp.StatusCode != 200 || string(raw) != "# report md" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/markdown") {
		t.Errorf("report.md: %d %q %s", resp.StatusCode, raw, resp.Header.Get("Content-Type"))
	}
	resp, raw = admin.raw("GET", "/api/v1/runs/7/report.html", nil, nil)
	if resp.StatusCode != 200 || string(raw) != "# report html" {
		t.Errorf("report.html: %d %q", resp.StatusCode, raw)
	}
	if resp, _ := admin.raw("GET", "/api/v1/runs/7/report.pdf", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("report.pdf: %d, want 404", resp.StatusCode)
	}

	// passive: import, PTR, crt.sh off, settings, confirm
	body, ct = multipartFile(t, "strefa.csv", "hostname,ip\na.test,10.80.0.9\n")
	resp, raw = admin.raw("POST", "/api/v1/passive/import", body, map[string]string{auth.CSRFHeader: admin.csrf, "Content-Type": ct})
	if resp.StatusCode != 200 || !strings.Contains(string(raw), "file:strefa.csv") {
		t.Errorf("passive import: %d %s", resp.StatusCode, raw)
	}
	var pr PassiveResult
	admin.want(200, "POST", "/api/v1/passive/ptr", nil, &pr)
	if pr.HostsUpdated != 2 {
		t.Errorf("ptr: %+v", pr)
	}
	resp, raw = admin.raw("POST", "/api/v1/passive/crtsh", nil, map[string]string{auth.CSRFHeader: admin.csrf})
	if resp.StatusCode != http.StatusConflict || errCode(raw) != "disabled" {
		t.Errorf("crtsh: %d %s", resp.StatusCode, raw)
	}
	var ps struct {
		CT bool `json:"crtsh_enabled"`
	}
	admin.want(200, "GET", "/api/v1/settings/passive", nil, &ps)
	if ps.CT {
		t.Error("crt.sh must be off by default")
	}
	admin.want(200, "PUT", "/api/v1/settings/passive", map[string]bool{"crtsh_enabled": true}, &ps)
	if got, _ := e.st.GetPassiveSettings(ctx); !got.CTEnabled {
		t.Error("setting not stored")
	}
	var sc model.Scope
	admin.want(http.StatusCreated, "POST", "/api/v1/scopes", map[string]any{"name": "pasywny"}, &sc)
	var tp model.TargetPreview
	admin.want(http.StatusCreated, "POST", "/api/v1/passive/confirm", map[string]any{"scope_id": sc.ID,
		"candidates": []map[string]any{{"value": "10.80.0.9", "sources": []string{"file:strefa.csv"}}, {"value": "999.1.1.1"}}}, &tp)
	if len(tp.Valid) != 1 || tp.Valid[0].Source != "passive" || len(tp.Invalid) != 1 || !strings.Contains(tp.Valid[0].Note, "file:strefa.csv") {
		t.Errorf("confirm: %+v", tp)
	}
	admin.want(http.StatusUnprocessableEntity, "POST", "/api/v1/passive/confirm", map[string]any{"scope_id": sc.ID}, nil)

	// a viewer may read the report but not import signatures or confirm candidates
	vu := e.users(admin)["viewer"]
	if resp, _ := vu.raw("GET", "/api/v1/runs/7/report.md", nil, nil); resp.StatusCode != 200 {
		t.Errorf("viewer report: %d", resp.StatusCode)
	}
	if got := vu.do("POST", "/api/v1/signatures/import", map[string]string{"text": "id: ok"}, nil); got != http.StatusForbidden {
		t.Errorf("viewer import: %d", got)
	}
	if got := vu.do("POST", "/api/v1/passive/confirm", map[string]any{"scope_id": sc.ID}, nil); got != http.StatusForbidden {
		t.Errorf("viewer confirm: %d", got)
	}
}
