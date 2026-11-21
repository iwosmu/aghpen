package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
)

// Server is the HTTP API.
type Server struct {
	d       Deps
	st      *store.Store
	log     *slog.Logger
	targets TargetParser
	lookup  runner.LookupFunc
	handler http.Handler
	mux     chi.Routes
	// anonAudit bounds the audit entries of requests without a session
	// (failed logins, rejected calls): anyone who reaches the port can send
	// them (security review M4). anonDropped counts the entries it dropped.
	anonAudit   *rate.Limiter
	anonDropped atomic.Int64
}

// Audit budget of requests without a session: a burst, then one per second.
const (
	anonAuditPerSec = 1
	anonAuditBurst  = 60
)

// New builds the server and its routes.
func New(d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Bus == nil {
		d.Bus = runner.NewBus()
	}
	if d.Version == "" {
		d.Version = "dev"
	}
	s := &Server{d: d, st: d.Store, log: d.Logger, targets: d.TargetParser, lookup: d.Lookup, anonAudit: rate.NewLimiter(anonAuditPerSec, anonAuditBurst)}
	if s.targets == nil {
		s.targets = BasicTargetParser{}
	}
	s.handler = s.routes()
	return s
}

// Handler returns the root handler: API under /api/v1, the UI elsewhere.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	s.mux = r
	r.Use(s.recoverer, s.securityHeaders)
	can := s.Guard()
	session := auth.RequireSession(s.authFail)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.audit, s.authenticate)
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			writeErr(w, http.StatusNotFound, "not_found", "no such route")
		})
		r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			writeErr(w, http.StatusMethodNotAllowed, "bad_request", "method not allowed")
		})

		r.Get("/healthz", s.healthz)
		r.Post("/auth/login", s.login)
		r.With(session).Post("/auth/logout", s.logout)
		r.With(session).Post("/auth/password", s.changePassword)
		r.With(session).Get("/me", s.me)
		r.With(session).Get("/permissions", s.permissions)
		r.With(session).Get("/roles", s.listRoles)

		r.With(can(model.PermUsersManage)).Get("/users", s.listUsers)
		r.With(can(model.PermUsersManage)).Post("/users", s.createUser)
		r.With(can(model.PermUsersManage)).Patch("/users/{id}", s.updateUser)
		r.With(can(model.PermUsersManage)).Delete("/users/{id}", s.deleteUser)
		r.With(can(model.PermRolesManage)).Post("/roles", s.createRole)
		r.With(can(model.PermRolesManage)).Patch("/roles/{id}", s.updateRole)
		r.With(can(model.PermRolesManage)).Delete("/roles/{id}", s.deleteRole)
		r.With(can(model.PermAuditRead)).Get("/audit", s.listAudit)

		r.With(can(model.PermTargetsRead)).Get("/scopes", s.listScopes)
		r.With(can(model.PermTargetsRead)).Get("/scopes/{id}", s.getScope)
		r.With(can(model.PermTargetsCreate)).Post("/scopes", s.createScope)
		r.With(can(model.PermTargetsUpdate)).Patch("/scopes/{id}", s.updateScope)
		r.With(can(model.PermTargetsDelete)).Delete("/scopes/{id}", s.deleteScope)
		r.With(can(model.PermTargetsRead)).Get("/scopes/{id}/targets", s.listTargets)
		r.With(can(model.PermTargetsCreate)).Post("/scopes/{id}/targets", s.addTargets)
		r.With(can(model.PermTargetsCreate)).Post("/scopes/{id}/targets/import", s.importTargets)
		r.With(can(model.PermTargetsRead)).Post("/targets/preview", s.previewTargets)
		r.With(can(model.PermTargetsUpdate)).Patch("/targets/{id}", s.updateTarget)
		r.With(can(model.PermTargetsDelete)).Delete("/targets/{id}", s.deleteTarget)

		r.With(can(model.PermScansRead)).Get("/profiles", s.listProfiles)
		r.With(can(model.PermScansRead)).Get("/profiles/{id}", s.getProfile)
		r.With(can(model.PermScansConfigure)).Post("/profiles", s.createProfile)
		r.With(can(model.PermScansConfigure)).Patch("/profiles/{id}", s.updateProfile)
		r.With(can(model.PermScansConfigure)).Delete("/profiles/{id}", s.deleteProfile)
		r.With(can(model.PermScansRead)).Post("/profiles/{id}/estimate", s.estimateProfile)
		r.With(can(model.PermScansRead)).Get("/runs", s.listRuns)
		r.With(can(model.PermScansRead)).Get("/runs/{id}", s.getRun)
		r.With(can(model.PermScansRun)).Post("/runs", s.startRun)
		r.With(can(model.PermScansRun)).Post("/runs/{id}/pause", s.runAction("pause"))
		r.With(can(model.PermScansRun)).Post("/runs/{id}/resume", s.runAction("resume"))
		r.With(can(model.PermScansRun)).Post("/runs/{id}/cancel", s.runAction("cancel"))
		r.With(can(model.PermScansRead)).Get("/runs/{id}/chunks", s.listChunks)
		r.With(can(model.PermScansRead)).Get("/runs/{id}/map", s.runMap)
		r.With(can(model.PermScansRead)).Get("/runs/{id}/events", s.runEvents)
		r.With(can(model.PermResultsRead)).Get("/events", s.globalEvents)

		r.With(can(model.PermResultsRead)).Get("/hosts", s.listHosts)
		r.With(can(model.PermResultsRead)).Get("/hosts/{id}", s.getHost)
		r.With(can(model.PermResultsUpdate)).Patch("/hosts/{id}", s.patchHost)
		r.With(can(model.PermResultsDelete)).Delete("/hosts/{id}", s.deleteHost)
		r.With(can(model.PermResultsRead)).Get("/hosts/{id}/services", s.hostServices)
		r.With(can(model.PermResultsRead)).Get("/hosts/{id}/availability", s.hostAvailability)
		r.With(can(model.PermResultsRead)).Get("/hosts/{id}/changes", s.hostChanges)
		r.With(can(model.PermResultsRead)).Get("/services", s.listServices)
		r.With(can(model.PermResultsRead)).Get("/services/{id}", s.getService)
		r.With(can(model.PermResultsUpdate)).Patch("/services/{id}", s.patchService)
		r.With(can(model.PermResultsDelete)).Delete("/services/{id}", s.deleteService)
		r.With(can(model.PermResultsRead)).Get("/services/{id}/observations", s.listObservations)
		r.With(can(model.PermResultsRead)).Get("/services/{id}/response-times", s.serviceResponseTimes)
		r.With(can(model.PermResultsRead)).Get("/service-groups", s.listServiceGroups)
		r.With(can(model.PermResultsRead)).Get("/technologies", s.listTechnologies)
		r.With(can(model.PermResultsRead)).Get("/tags", s.listTags)
		r.With(can(model.PermResultsRead)).Get("/changes", s.listChanges)
		r.With(can(model.PermResultsUpdate)).Post("/changes/{id}/ack", s.ackChange)
		r.With(can(model.PermResultsUpdate)).Post("/changes/ack", s.ackChanges)
		r.With(can(model.PermResultsRead)).Get("/diff", s.diff)
		r.With(can(model.PermResultsRead)).Get("/findings", s.listFindings)
		r.With(can(model.PermResultsRead)).Get("/findings/{id}", s.getFinding)
		r.With(can(model.PermResultsCreate)).Post("/findings", s.createFinding)
		r.With(can(model.PermResultsUpdate)).Patch("/findings/{id}", s.patchFinding)
		r.With(can(model.PermResultsDelete)).Delete("/findings/{id}", s.deleteFinding)
		r.With(can(model.PermExportRun)).Post("/findings/export/defectdojo", s.exportDojo)
		r.With(can(model.PermResultsRead)).Get("/dashboard", s.dashboard)

		r.With(can(model.PermSignaturesRead)).Get("/signatures", s.listSignatures)
		r.With(can(model.PermSignaturesRead)).Get("/signatures/{id}", s.getSignature)
		r.With(can(model.PermSignaturesCreate)).Post("/signatures", s.createSignature)
		r.With(can(model.PermSignaturesUpdate)).Patch("/signatures/{id}", s.updateSignature)
		r.With(can(model.PermSignaturesDelete)).Delete("/signatures/{id}", s.deleteSignature)
		r.With(can(model.PermSignaturesRead)).Post("/signatures/validate", s.validateSignature)
		r.With(can(model.PermSignaturesRead)).Post("/signatures/retrohunt", s.retroHunt)
		r.With(can(model.PermSignaturesCreate)).Post("/signatures/import", s.importSignatures)
		r.With(can(model.PermResultsRead)).Get("/runs/{id}/{file:report\\.(html|md)}", s.runReport)
		r.With(can(model.PermTargetsCreate)).Post("/passive/import", s.passiveImport)
		r.With(can(model.PermResultsUpdate)).Post("/passive/ptr", s.passivePTR)
		r.With(can(model.PermTargetsCreate)).Post("/passive/crtsh", s.passiveCT)
		r.With(can(model.PermTargetsCreate)).Post("/passive/confirm", s.passiveConfirm)
		r.With(can(model.PermIntegrations)).Get("/settings/passive", s.getPassiveSettings)
		r.With(can(model.PermIntegrations)).Put("/settings/passive", s.putPassiveSettings)

		r.With(can(model.PermResultsCreate)).Post("/import/results", s.importResults)
		r.With(can(model.PermExportRun)).Post("/runs/{id}/export/defectdojo", s.exportRunDojo)
		r.With(can(model.PermExportRun)).Get("/export/runs/{file}", s.exportRun)
		r.With(can(model.PermExportRun)).Get("/export/{file}", s.export)

		r.With(can(model.PermScansRead)).Get("/settings/safety", s.getSafety)
		r.With(can(model.PermSafetyManage)).Put("/settings/safety", s.putSafety)
		r.With(can(model.PermEmergencyStop)).Post("/emergency-stop", s.emergencyStop)
		r.With(can(model.PermSafetyManage)).Post("/emergency-stop/release", s.releaseEmergencyStop)
		r.With(can(model.PermIntegrations)).Get("/settings/defectdojo", s.getDojo)
		r.With(can(model.PermIntegrations)).Put("/settings/defectdojo", s.putDojo)
		r.With(can(model.PermIntegrations)).Post("/settings/defectdojo/test", s.testDojo)
		s.routesPart3(r, can)
		for _, m := range s.d.Mounts {
			r.Mount(m.Pattern, m.Router(can))
		}
		for _, reg := range s.d.Routes {
			reg(r, can)
		}
	})
	r.Get("/healthz", s.healthz) // for container health checks
	r.NotFound(s.serveUI)
	return r
}

// ---------- responses ----------

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := encodeJSON(v)
	if err != nil {
		b, status = []byte(`{"error":{"code":"internal","message":"the response could not be encoded"}}`), http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg}})
}

func writeErrDetails(w http.ResponseWriter, status int, code, msg string, details any) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg, Details: details}})
}

func (s *Server) authFail(w http.ResponseWriter, _ *http.Request, status int, code, msg string) {
	writeErr(w, status, code, msg)
}

func notWired(w http.ResponseWriter, what string) {
	writeErr(w, http.StatusNotImplemented, "not_wired", what+" is not wired into this build")
}

// fail maps an error of the store, auth or runner to an API error.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	msg := err.Error()
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, runner.ErrNotWired):
		writeErr(w, http.StatusNotImplemented, "not_wired", msg)
	case errors.Is(err, runner.ErrEmergencyStop):
		writeErr(w, http.StatusConflict, "emergency_stop", msg)
	case errors.As(err, new(*runner.ActiveRunError)):
		var a *runner.ActiveRunError
		errors.As(err, &a)
		writeErrDetails(w, http.StatusConflict, "run_active", fmt.Sprintf("Ten profil ma już aktywny przebieg #%d (w kolejce, trwający albo wstrzymany). Wstrzymaj, wznów albo anuluj go, zanim uruchomisz nowy.", a.RunID), map[string]int64{"run_id": a.RunID})
	case errors.Is(err, auth.ErrLastAdmin), errors.Is(err, store.ErrConflict), errors.Is(err, runner.ErrActiveRun), errors.Is(err, runner.ErrBadState):
		writeErr(w, http.StatusConflict, "conflict", msg)
	case errors.Is(err, auth.ErrForbidden), errors.Is(err, auth.ErrBuiltinRole):
		writeErr(w, http.StatusForbidden, "forbidden", msg)
	case errors.Is(err, store.ErrInvalid), errors.Is(err, auth.ErrValidation), errors.Is(err, runner.ErrInvalid), errors.Is(err, errValidation):
		// The sentinel ("validation: ", "invalid: ") is not for people.
		for _, p := range []string{errValidation.Error() + ": ", runner.ErrInvalid.Error() + ": ", store.ErrInvalid.Error() + ": "} {
			msg = strings.TrimPrefix(msg, p)
		}
		writeErr(w, http.StatusUnprocessableEntity, "validation", msg)
	case errors.Is(err, context.Canceled):
		// the client went away
	default:
		s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

var errValidation = errors.New("validation")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errValidation}, args...)...)
}

// ---------- requests ----------

const maxJSONBody = 8 << 20

// decode reads a JSON body into v. It answers 400 and returns false when the body is not valid.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the request body is too large or unreadable")
		return false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		body = []byte("{}")
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the request body is not valid JSON: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "the id in the path must be a positive number")
		return 0, false
	}
	return id, true
}

// params reads query parameters and remembers the first error.
type params struct {
	r   *http.Request
	err error
}

func query(r *http.Request) *params { return &params{r: r} }

func (p *params) str(name string) string { return strings.TrimSpace(p.r.URL.Query().Get(name)) }

func (p *params) list(name string) []string {
	var out []string
	for _, v := range p.r.URL.Query()[name] {
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, x)
			}
		}
	}
	return out
}

func (p *params) int(name string) int {
	v := p.str(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil && p.err == nil {
		p.err = fmt.Errorf("query parameter %s must be a number", name)
	}
	return n
}

func (p *params) int64(name string) int64 {
	v := p.str(name)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil && p.err == nil {
		p.err = fmt.Errorf("query parameter %s must be a number", name)
	}
	return n
}

func (p *params) boolean(name string) *bool {
	v := p.str(name)
	if v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		if p.err == nil {
			p.err = fmt.Errorf("query parameter %s must be true or false", name)
		}
		return nil
	}
	return &b
}

func (p *params) time(name string) *time.Time {
	v := p.str(name)
	if v == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return &t
		}
	}
	if p.err == nil {
		p.err = fmt.Errorf("query parameter %s must be an RFC 3339 time or a date", name)
	}
	return nil
}

func (p *params) cidr(name string) string {
	v := p.str(name)
	if v == "" {
		return ""
	}
	if _, _, err := net.ParseCIDR(v); err != nil && net.ParseIP(v) == nil && p.err == nil {
		p.err = fmt.Errorf("query parameter %s must be an address or a CIDR", name)
	}
	return v
}

func (p *params) opts() store.ListOpts {
	return store.ListOpts{Limit: p.int("limit"), Offset: p.int("offset"), Sort: p.str("sort"), Q: p.str("q")}
}

// ok answers 400 when a query parameter was wrong.
func (p *params) ok(w http.ResponseWriter) bool {
	if p.err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", p.err.Error())
		return false
	}
	return true
}

// mergePatch applies the allowed keys of a JSON object to a struct (partial update).
func mergePatch(target any, patch map[string]json.RawMessage, allowed ...string) error {
	cur, err := json.Marshal(target)
	if err != nil {
		return err
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(cur, &m); err != nil {
		return err
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k, v := range patch {
		if !ok[k] {
			return invalid("field %q cannot be changed", k)
		}
		m[k] = v
	}
	merged, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(merged, target); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// ---------- middleware ----------

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("panic in handler", "path", r.URL.Path, "panic", rec, "stack", string(debug.Stack()))
				writeErr(w, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		if s.secure(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// secure tells whether the session cookie gets the Secure flag.
func (s *Server) secure(r *http.Request) bool {
	switch s.d.CookieSecure {
	case "true":
		return true
	case "false":
		return false
	}
	return r.TLS != nil || (s.d.TrustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

func (s *Server) clientIP(r *http.Request) string {
	if s.d.TrustProxy {
		// The rightmost entry is the one the trusted proxy appended: the
		// address it saw. Entries to its left come from the client and can be
		// forged, so they never key the login rate limit or the audit log.
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if a, err := netip.ParseAddr(strings.TrimSpace(parts[i])); err == nil {
				return a.Unmap().String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authenticate resolves the session cookie. A mutating request of a session
// must carry the CSRF token. Requests without a session pass on; the route
// guards answer 401 where a session is needed.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(auth.CookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		p, err := s.d.Auth.AuthenticateToken(r.Context(), c.Value)
		if errors.Is(err, auth.ErrNoSession) {
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if a := auditOf(r); a != nil {
			a.user = p
		}
		r = r.WithContext(auth.WithPrincipal(r.Context(), p))
		login := strings.HasSuffix(r.URL.Path, "/auth/login")
		if !auth.SafeMethod(r.Method) && !login && !p.CheckCSRF(r.Header.Get(auth.CSRFHeader)) {
			if a := auditOf(r); a != nil {
				a.detail["reason"] = "csrf"
			}
			writeErr(w, http.StatusForbidden, "forbidden", "missing or wrong CSRF token: send the csrf_token of the session in the X-CSRF-Token header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func principal(r *http.Request) *auth.Principal { return auth.FromContext(r.Context()) }

func userID(r *http.Request) *int64 {
	if p := principal(r); p != nil {
		id := p.User.ID
		return &id
	}
	return nil
}

func userEmail(r *http.Request) string {
	if p := principal(r); p != nil {
		return p.User.Email
	}
	return ""
}

// ---------- audit ----------

type auditInfo struct {
	user     *auth.Principal
	action   string
	entity   string
	entityID string
	detail   map[string]any
	force    bool // audit a read (exports)
}

type auditKey struct{}

func auditOf(r *http.Request) *auditInfo {
	a, _ := r.Context().Value(auditKey{}).(*auditInfo)
	return a
}

// auditSet lets a handler name the action and add details to the audit entry of its request.
func auditSet(r *http.Request, action, entity string, entityID any, detail map[string]any) {
	a := auditOf(r)
	if a == nil {
		return
	}
	if action != "" {
		a.action = action
	}
	if entity != "" {
		a.entity = entity
	}
	if entityID != nil {
		a.entityID = fmt.Sprint(entityID)
	}
	for k, v := range detail {
		a.detail[k] = v
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

var singular = map[string]string{"hosts": "host", "services": "service", "findings": "finding", "runs": "run", "scopes": "scope",
	"targets": "target", "profiles": "profile", "users": "user", "roles": "role", "signatures": "signature", "changes": "change"}

var actionWords = map[string]bool{"pause": true, "resume": true, "cancel": true, "ack": true, "validate": true, "retrohunt": true,
	"preview": true, "import": true, "test": true, "release": true, "estimate": true, "login": true, "logout": true, "defectdojo": true, "results": true}

// namedActions are the routes whose audit action does not follow the generic rule.
var namedActions = map[string][2]string{
	"POST /api/v1/runs":                        {"run.start", "run"},
	"PUT /api/v1/settings/safety":              {"safety.update", "safety"},
	"POST /api/v1/emergency-stop":              {"safety.emergency_stop", "safety"},
	"POST /api/v1/emergency-stop/release":      {"safety.emergency_stop_release", "safety"},
	"PUT /api/v1/settings/defectdojo":          {"integration.defectdojo.update", "integration"},
	"POST /api/v1/settings/defectdojo/test":    {"integration.defectdojo.test", "integration"},
	"PUT /api/v1/settings/webhook":             {"integration.webhook.update", "integration"},
	"POST /api/v1/settings/webhook/test":       {"integration.webhook.test", "integration"},
	"POST /api/v1/findings/export/defectdojo":  {"finding.export.defectdojo", "finding"},
	"POST /api/v1/runs/{id}/export/defectdojo": {"run.export.defectdojo", "run"},
	"POST /api/v1/import/results":              {"result.import", "result"},
}

// defaultAction names the audit action from the route: PATCH /hosts/{id} is "host.update".
// A denied request gets the same name as an allowed one, so the log can be filtered by action.
func defaultAction(method, pattern string) (action, entity string) {
	if n, ok := namedActions[method+" "+pattern]; ok {
		return n[0], n[1]
	}
	var lit []string
	for _, seg := range strings.Split(strings.TrimPrefix(pattern, "/api/v1"), "/") {
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		if sg, ok := singular[seg]; ok {
			seg = sg
		}
		lit = append(lit, seg)
	}
	if len(lit) == 0 {
		return strings.ToLower(method), ""
	}
	entity = lit[0]
	action = strings.Join(lit, ".")
	if method == http.MethodPost && actionWords[lit[len(lit)-1]] {
		return action, entity
	}
	verb := map[string]string{http.MethodPost: "create", http.MethodPatch: "update", http.MethodPut: "update", http.MethodDelete: "delete"}[method]
	if verb == "" {
		verb = strings.ToLower(method)
	}
	return action + "." + verb, entity
}

// audit writes one audit entry for every mutating request, also for the ones
// that were rejected. Request bodies are never logged.
func (s *Server) audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := &auditInfo{detail: map[string]any{}}
		r = r.WithContext(context.WithValue(r.Context(), auditKey{}, a))
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if auth.SafeMethod(r.Method) && !a.force {
			return
		}
		pattern := ""
		if rc := chi.RouteContext(r.Context()); rc != nil {
			pattern = rc.RoutePattern()
		}
		if pattern == "" || strings.HasSuffix(pattern, "*") {
			// A request that a middleware rejected (no session, CSRF) never reached its route: look the route up.
			if tc := chi.NewRouteContext(); s.mux != nil && s.mux.Match(tc, r.Method, r.URL.Path) {
				pattern = tc.RoutePattern()
			}
		}
		action, entity := defaultAction(r.Method, pattern)
		if a.action != "" {
			action = a.action
		}
		if a.entity != "" {
			entity = a.entity
		}
		if a.entityID == "" {
			a.entityID = chi.URLParam(r, "id")
		}
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		a.detail["status"] = sw.status
		a.detail["method"] = r.Method
		a.detail["path"] = r.URL.Path
		if sw.status >= 400 {
			a.detail["ok"] = false
		}
		if a.user == nil {
			if !s.anonAudit.Allow() {
				s.anonDropped.Add(1)
				return
			}
			if n := s.anonDropped.Swap(0); n > 0 {
				a.detail["dropped_before"] = n // entries without a session dropped by the budget
			}
		}
		e := model.AuditEntry{Action: action, Entity: entity, EntityID: a.entityID, Detail: a.detail, IP: s.clientIP(r)}
		if a.user != nil {
			id := a.user.User.ID
			e.UserID, e.UserEmail = &id, a.user.User.Email
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if err := s.st.InsertAudit(ctx, e); err != nil {
			s.log.Error("audit log write failed", "action", action, "err", err)
		}
	})
}
