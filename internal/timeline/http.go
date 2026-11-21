package timeline

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
)

// Middleware is the permission check of internal/api: can(permission).
type Middleware func(model.Permission) func(http.Handler) http.Handler

// Register adds the timeline routes to r (the /api/v1 router). All routes
// need results:read.
func (t *Timeline) Register(r chi.Router, can Middleware) {
	read := can(model.PermResultsRead)
	r.With(read).Get("/timeline", t.handleScrubber)
	r.With(read).Get("/timeline/at", t.handleAt)
	r.With(read).Get("/timeline/at/hosts", t.handleAtHosts)
	r.With(read).Get("/timeline/at/services", t.handleAtServices)
	r.With(read).Get("/timeline/at/findings", t.handleAtFindings)
	r.With(read).Get("/timeline/hosts/{id}", t.handleHost)
	r.With(read).Get("/timeline/services/{id}", t.handleService)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (t *Timeline) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "nie znaleziono")
		return
	}
	if r.Context().Err() != nil {
		return
	}
	t.log.Error("timeline", "path", r.URL.Path, "error", err)
	writeErr(w, http.StatusInternalServerError, "internal", "błąd wewnętrzny")
}

// params reads query parameters and collects the first error.
type params struct {
	r   *http.Request
	err string
}

func (p *params) str(n string) string { return strings.TrimSpace(p.r.URL.Query().Get(n)) }

func (p *params) list(n string) []string {
	var out []string
	for _, v := range p.r.URL.Query()[n] {
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, x)
			}
		}
	}
	return out
}

func (p *params) int64(n string) int64 {
	s := p.str(n)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		p.err = n + ": not a non-negative integer"
	}
	return v
}

func (p *params) int(n string) int { return int(p.int64(n)) }

func (p *params) boolean(n string) *bool {
	s := p.str(n)
	if s == "" {
		return nil
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		p.err = n + ": not a boolean"
		return nil
	}
	return &v
}

func (p *params) time(n string) *time.Time {
	s := p.str(n)
	if s == "" {
		return nil
	}
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		p.err = n + ": not an RFC 3339 time"
		return nil
	}
	return &v
}

func (p *params) cidr(n string) string {
	s := p.str(n)
	if s == "" {
		return ""
	}
	c, ok := validCIDR(s)
	if !ok {
		p.err = n + ": not an address or CIDR"
	}
	return c
}

func (p *params) ok(w http.ResponseWriter) bool {
	if p.err != "" {
		writeErr(w, http.StatusBadRequest, "bad_request", p.err)
		return false
	}
	return true
}

func (t *Timeline) handleScrubber(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	from, to := p.time("from"), p.time("to")
	if !p.ok(w) {
		return
	}
	out, err := t.Scrubber(r.Context(), from, to)
	if err != nil {
		t.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// run resolves run_id or at.
func (t *Timeline) run(w http.ResponseWriter, r *http.Request, p *params) (AtRun, bool) {
	id, at := p.int64("run_id"), p.time("at")
	if !p.ok(w) {
		return AtRun{}, false
	}
	run, err := t.ResolveRun(r.Context(), id, at)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "brak przeanalizowanego przebiegu dla tego punktu w czasie")
		return run, false
	}
	if err != nil {
		t.fail(w, r, err)
		return run, false
	}
	return run, true
}

func hostFilter(p *params) HostFilter {
	return HostFilter{Status: p.list("status"), CIDR: p.cidr("cidr"), Q: p.str("q"), ScopeID: p.int64("scope_id"), Port: p.int("port"),
		Limit: p.int("limit"), Offset: p.int("offset"), Sort: p.str("sort")}
}

func serviceFilter(p *params) ServiceFilter {
	return ServiceFilter{HostID: p.int64("host_id"), Port: p.int("port"), Name: p.str("name"), Tech: p.str("tech"), Class: p.str("class"),
		State: p.list("state"), TLS: p.boolean("tls"), CIDR: p.cidr("cidr"), Q: p.str("q"), Limit: p.int("limit"), Offset: p.int("offset"), Sort: p.str("sort")}
}

func findingFilter(p *params) FindingFilter {
	return FindingFilter{Severity: p.list("severity"), Type: p.str("type"), HostID: p.int64("host_id"), Limit: p.int("limit"), Offset: p.int("offset")}
}

func (t *Timeline) handleAt(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	p := &params{r: r}
	hf, sf, ff := hostFilter(p), serviceFilter(p), findingFilter(p)
	if !p.ok(w) {
		return
	}
	run, ok := t.run(w, r, p)
	if !ok {
		return
	}
	snap := Snapshot{Run: run}
	var err error
	if snap.Summary, err = t.Summary(r.Context(), run); err != nil {
		t.fail(w, r, err)
		return
	}
	if snap.Hosts, err = t.AtHosts(r.Context(), run.ID, hf); err != nil {
		t.fail(w, r, err)
		return
	}
	if snap.Services, err = t.AtServices(r.Context(), run.ID, sf); err != nil {
		t.fail(w, r, err)
		return
	}
	if snap.Findings, err = t.AtFindings(r.Context(), run, ff); err != nil {
		t.fail(w, r, err)
		return
	}
	snap.TookMs = time.Since(start).Milliseconds()
	writeJSON(w, http.StatusOK, snap)
}

func (t *Timeline) handleAtHosts(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := hostFilter(p)
	run, ok := t.run(w, r, p)
	if !ok {
		return
	}
	page, err := t.AtHosts(r.Context(), run.ID, f)
	if err != nil {
		t.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (t *Timeline) handleAtServices(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := serviceFilter(p)
	run, ok := t.run(w, r, p)
	if !ok {
		return
	}
	page, err := t.AtServices(r.Context(), run.ID, f)
	if err != nil {
		t.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (t *Timeline) handleAtFindings(w http.ResponseWriter, r *http.Request) {
	p := &params{r: r}
	f := findingFilter(p)
	run, ok := t.run(w, r, p)
	if !ok {
		return
	}
	page, err := t.AtFindings(r.Context(), run, f)
	if err != nil {
		t.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "id: not a positive integer")
		return 0, false
	}
	return id, true
}

func (t *Timeline) handleHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := t.HostLife(r.Context(), id)
	if err != nil {
		t.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (t *Timeline) handleService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := t.ServiceHistory(r.Context(), id)
	if err != nil {
		t.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
