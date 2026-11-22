package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
)

// Middleware is the permission guard of the API (api.Guard).
type Middleware func(model.Permission) func(http.Handler) http.Handler

// Register adds GET and PUT /settings/webhook and POST /settings/webhook/test.
func (n *Notifier) Register(r chi.Router, can Middleware) {
	r.With(can(model.PermIntegrations)).Get("/settings/webhook", n.get)
	r.With(can(model.PermIntegrations)).Put("/settings/webhook", n.put)
	r.With(can(model.PermIntegrations)).Post("/settings/webhook/test", n.test)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	v = localize(w, v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// origin is the address the browser used, the default base of the links.
func origin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (n *Notifier) get(w http.ResponseWriter, r *http.Request) {
	s, err := n.St.GetWebhook(r.Context(), false)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// putBody is WebhookSettings plus clear_secret.
type putBody struct {
	model.WebhookSettings
	ClearSecret bool `json:"clear_secret"`
}

func (n *Notifier) put(w http.ResponseWriter, r *http.Request) {
	var b putBody
	raw, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := json.Unmarshal(raw, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the request body is not valid JSON: "+err.Error())
		return
	}
	s := b.WebhookSettings
	s.URL = strings.TrimSpace(s.URL)
	if s.MinSeverity == "" {
		s.MinSeverity = model.SevMedium
	}
	if !ValidSeverity(s.MinSeverity) {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "min_severity: info, low, medium albo high")
		return
	}
	if s.URL != "" || s.Enabled {
		if err := CheckURL(s.URL); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
			return
		}
	}
	if s.UIURL == "" {
		s.UIURL = origin(r)
	} else if err := CheckURL(s.UIURL); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "ui_url: "+err.Error())
		return
	}
	out, err := n.St.PutWebhook(r.Context(), s, b.ClearSecret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// TestResult is the answer of POST /settings/webhook/test.
type TestResult struct {
	OK bool `json:"ok"`
	Result
}

// test sends one test message with the stored settings (the URL and key in
// the body, when given, override them, so the form can test before saving).
func (n *Notifier) test(w http.ResponseWriter, r *http.Request) {
	s, err := n.St.GetWebhook(r.Context(), true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var b model.WebhookSettings
	raw, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &b); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "the request body is not valid JSON: "+err.Error())
			return
		}
	}
	if b.URL != "" {
		s.URL = b.URL
	}
	if b.Secret != "" {
		s.Secret = b.Secret
	}
	if err := CheckURL(s.URL); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
		return
	}
	base := s.UIURL
	if base == "" {
		base = origin(r)
	}
	now := time.Now().UTC()
	p := Payload{Event: EventTest, RunURL: strings.TrimRight(base, "/") + "/runs", Scope: "test", FinishedAt: &now,
		Counts: map[string]int{}, Changes: []Item{}, Findings: []Item{},
		Text: "*Czujka: test webhooka.* " + strings.TrimRight(base, "/") + "/runs"}
	body, _ := json.Marshal(p)
	res := n.Client.Post(r.Context(), s.URL, s.Secret, EventTest, body)
	detail := map[string]any{"test": true, "status": res.Status, "ms": res.Ms}
	if res.Error != "" {
		detail["error"] = res.Error
	}
	_ = n.St.InsertAudit(r.Context(), model.AuditEntry{Action: "integration.webhook.send", Entity: "integration", EntityID: "webhook", UserEmail: "system", Detail: detail})
	writeJSON(w, http.StatusOK, TestResult{OK: res.Error == "", Result: res})
}
