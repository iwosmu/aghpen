package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

func ptr[T any](v T) *T { return &v }

func sampleRun() (model.ScanRun, []model.Change, []model.Finding) {
	fin := time.Date(2026, 11, 21, 18, 0, 0, 0, time.UTC)
	run := model.ScanRun{ID: 12, Trigger: "manual", ProfileName: "dmz", FinishedAt: &fin,
		Summary: &model.RunDiffSummary{ByKind: map[string]int{"service_new": 1, "service_gone": 1, "service_changed": 3}, FindingsNew: 1}}
	changes := []model.Change{
		{Kind: model.ChangeServiceChanged, Severity: model.SevHigh, HostID: 1, IP: "10.0.0.1", Port: 80, Summary: "zmiana wersji"},
		{Kind: model.ChangeServiceGone, Severity: model.SevLow, HostID: 2, IP: "10.0.0.2", Port: 22, ServiceID: ptr(int64(7)), Summary: "Usługa 10.0.0.2:22 zniknęła"},
		{Kind: model.ChangeServiceNew, Severity: model.SevMedium, HostID: 1, IP: "10.0.0.1", Port: 8080, ServiceID: ptr(int64(9)), Summary: "Nowa usługa 10.0.0.1:8080 (Jenkins)"},
		{Kind: model.ChangeHostGone, Severity: model.SevMedium, HostID: 3, IP: "10.0.0.3", Expected: true, Summary: "poza godzinami"},
	}
	findings := []model.Finding{
		{Title: "Panel administracyjny: Jenkins", Severity: model.SevHigh, Interest: 80, HostID: 1, IP: "10.0.0.1", Port: 8080, FirstRunID: 12},
		{Title: "stare ustalenie", Severity: model.SevHigh, HostID: 1, IP: "10.0.0.1", FirstRunID: 3},
	}
	return run, changes, findings
}

func TestBuildSelectsAndLinks(t *testing.T) {
	run, changes, findings := sampleRun()
	p, ok := Build(run, changes, findings, model.SevLow, "https://czujka.example/")
	if !ok || p.Event != EventRun || p.RunURL != "https://czujka.example/runs/12" || p.Scope != "profil dmz" {
		t.Fatalf("payload %+v ok %v", p, ok)
	}
	// service_changed is not an alert kind; the expected host_gone is skipped; medium before low.
	if len(p.Changes) != 2 || p.Changes[0].Kind != "service_new" || p.Changes[0].URL != "https://czujka.example/services/9" || p.Changes[1].Kind != "service_gone" {
		t.Fatalf("changes %+v", p.Changes)
	}
	if len(p.Findings) != 1 || p.Findings[0].Summary != "Panel administracyjny: Jenkins" || p.Findings[0].URL != "https://czujka.example/hosts/1" {
		t.Fatalf("findings %+v", p.Findings)
	}
	if p.Counts["service_new"] != 1 || p.Counts["findings_new"] != 1 {
		t.Errorf("counts %v", p.Counts)
	}
	for _, want := range []string{"*Czujka: skan #12 przeanalizowany* (profil dmz)", "nowa usługa: 1", "nowe znaleziska: 1", "• [wysoka] Panel administracyjny: Jenkins (10.0.0.1:8080) https://czujka.example/hosts/1",
		"• [średnia] Nowa usługa 10.0.0.1:8080 (Jenkins) https://czujka.example/services/9", "Skan: https://czujka.example/runs/12"} {
		if !strings.Contains(p.Text, want) {
			t.Errorf("text %q\nmissing %q", p.Text, want)
		}
	}
	// Minimum high: only the finding; minimum high without findings: nothing to send.
	if p, ok := Build(run, changes, findings, model.SevHigh, ""); !ok || len(p.Changes) != 0 || len(p.Findings) != 1 {
		t.Errorf("min high: %+v %v", p, ok)
	}
	if _, ok := Build(run, changes, nil, model.SevHigh, ""); ok {
		t.Error("min high without findings: want nothing to send")
	}
}

func TestPostSignsAndReportsErrors(t *testing.T) {
	var got struct {
		sig, event, ctype string
		body              []byte
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		got.sig, got.event, got.ctype = r.Header.Get(SignatureHeader), r.Header.Get("X-Czujka-Event"), r.Header.Get("Content-Type")
		got.body, _ = io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/fail":
			http.Error(w, "nope", http.StatusForbidden)
		case "/redirect":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}
	}))
	defer srv.Close()
	body := []byte(`{"text":"hi"}`)
	res := Client{}.Post(context.Background(), srv.URL+"/ok", "s3cret", EventRun, body)
	if res.Error != "" || res.Status != 200 {
		t.Fatalf("ok: %+v", res)
	}
	// Known vector: HMAC-SHA256("s3cret", body).
	if got.sig != Sign("s3cret", body) || !strings.HasPrefix(got.sig, "sha256=") || len(got.sig) != 7+64 || got.event != EventRun || got.ctype != "application/json" || string(got.body) != string(body) {
		t.Errorf("request %+v", got)
	}
	if Sign("key", []byte("The quick brown fox jumps over the lazy dog")) != "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8" {
		t.Error("HMAC-SHA256 test vector")
	}
	got.sig = "x"
	if res := (Client{}).Post(context.Background(), srv.URL+"/ok", "", EventTest, body); res.Error != "" || got.sig != "" {
		t.Errorf("no secret: header %q, %+v", got.sig, res)
	}
	if res := (Client{}).Post(context.Background(), srv.URL+"/fail", "", EventRun, body); res.Status != 403 || !strings.Contains(res.Error, "403") {
		t.Errorf("fail: %+v", res)
	}
	if res := (Client{}).Post(context.Background(), srv.URL+"/redirect", "", EventRun, body); res.Status != 302 || res.Error == "" {
		t.Errorf("a redirect is not followed: %+v", res)
	}
	if res := (Client{}).Post(context.Background(), "ftp://x/", "", EventRun, body); res.Error == "" {
		t.Error("ftp URL accepted")
	}
}

// L2 of the security review: a delivery follows no redirect and does not
// echo the response body (an internal endpoint could leak through it).
func TestPostFollowsNoRedirectAndEchoesNoBody(t *testing.T) {
	var reached int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&reached, 1) }))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	res := Client{}.Post(context.Background(), redirect.URL, "", "test", []byte("{}"))
	if atomic.LoadInt32(&reached) != 0 || res.Status != http.StatusTemporaryRedirect || res.Error == "" {
		t.Fatalf("redirect: reached=%d %+v", reached, res)
	}
	leaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal secret: db=10.0.0.5 password=hunter2"))
	}))
	defer leaky.Close()
	res = Client{}.Post(context.Background(), leaky.URL, "", "test", []byte("{}"))
	if res.Status != 500 || res.Error == "" || strings.Contains(res.Error, "hunter2") {
		t.Fatalf("the response body was echoed: %+v", res)
	}
}

func TestPostTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer srv.Close()
	c := Client{HTTP: &http.Client{Timeout: 50 * time.Millisecond}}
	start := time.Now()
	if res := c.Post(context.Background(), srv.URL, "", EventRun, []byte("{}")); res.Error == "" || res.Status != 0 || time.Since(start) > 250*time.Millisecond {
		t.Errorf("timeout: %+v after %v", res, time.Since(start))
	}
}

func TestPayloadJSONShape(t *testing.T) {
	run, changes, findings := sampleRun()
	p, _ := Build(run, changes, findings, model.SevInfo, "http://x")
	raw, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"event", "run_id", "run_url", "trigger", "scope", "finished_at", "counts", "changes", "findings", "text"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %q in %s", k, raw)
		}
	}
}

// An analysed run is finished even when the runner has not stored its end
// yet (the analysis runs in status "analyzing"): the payload never carries
// finished_at: null.
func TestMarkFinished(t *testing.T) {
	now := time.Date(2026, 11, 21, 21, 0, 0, 0, time.FixedZone("CET", 3600))
	run := model.ScanRun{ID: 4, Status: model.RunAnalyzing}
	markFinished(&run, now)
	if run.FinishedAt == nil || !run.FinishedAt.Equal(now) || run.FinishedAt.Location() != time.UTC {
		t.Fatalf("finished_at %v", run.FinishedAt)
	}
	stored := time.Date(2026, 11, 21, 19, 0, 0, 0, time.UTC)
	run.FinishedAt = &stored
	markFinished(&run, now)
	if !run.FinishedAt.Equal(stored) {
		t.Errorf("a stored end was replaced: %v", run.FinishedAt)
	}
	p, _ := Build(run, nil, nil, model.SevInfo, "")
	raw, _ := json.Marshal(p)
	if !strings.Contains(string(raw), `"finished_at":"2026-11-21T19:00:00Z"`) {
		t.Errorf("payload %s", raw)
	}
}
