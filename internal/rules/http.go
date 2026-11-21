package rules

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/model"
)

// Middleware is the permission guard of the API (api: auth.Require(p, s.authFail)).
type Middleware func(model.Permission) func(http.Handler) http.Handler

// Router returns the routes of the rules, to be mounted at /api/v1/rules.
// Reading, validating and dry runs need results:read; writing a rule needs
// the signature permissions (rules are detection content like signatures);
// a manual evaluation writes findings and needs results:update.
func (s *Service) Router(can Middleware) chi.Router {
	r := chi.NewRouter()
	r.With(can(model.PermResultsRead)).Get("/", s.hList)
	r.With(can(model.PermSignaturesCreate)).Post("/", s.hCreate)
	r.With(can(model.PermResultsRead)).Post("/validate", s.hValidate)
	r.With(can(model.PermResultsRead)).Post("/dry-run", s.hDryRun)
	r.With(can(model.PermResultsUpdate)).Post("/evaluate", s.hEvaluate)
	r.With(can(model.PermResultsRead)).Get("/{id}", s.hGet)
	r.With(can(model.PermSignaturesUpdate)).Patch("/{id}", s.hUpdate)
	r.With(can(model.PermSignaturesDelete)).Delete("/{id}", s.hDelete)
	r.With(can(model.PermResultsRead)).Get("/{id}/violations", s.hViolations)
	return r
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// WriteJSON writes v with the status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteErr writes the error envelope of the API.
func WriteErr(w http.ResponseWriter, status int, code, msg string, details any) {
	WriteJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg, Details: details}})
}

// Decode reads a JSON body (at most 1 MiB) into v; it answers 400 and returns false on error.
func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		WriteErr(w, http.StatusBadRequest, "bad_request", "the request body is too large or unreadable", nil)
		return false
	}
	if strings.TrimSpace(string(body)) == "" {
		body = []byte("{}")
	}
	if err := json.Unmarshal(body, v); err != nil {
		WriteErr(w, http.StatusBadRequest, "bad_request", "the request body is not valid JSON: "+err.Error(), nil)
		return false
	}
	return true
}

func (s *Service) fail(w http.ResponseWriter, err error, val *Validation) {
	switch {
	case errors.Is(err, ErrNotFound):
		WriteErr(w, http.StatusNotFound, "not_found", "not found", nil)
	case errors.Is(err, ErrInvalid):
		WriteErr(w, http.StatusUnprocessableEntity, "validation", "reguła ma błędy", val)
	case errors.Is(err, ErrConflict):
		WriteErr(w, http.StatusConflict, "conflict", err.Error(), nil)
	case errors.Is(err, context.Canceled):
	default:
		s.log.Error("rules request failed", "error", err)
		WriteErr(w, http.StatusInternalServerError, "internal", "internal error", nil)
	}
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		WriteErr(w, http.StatusBadRequest, "bad_request", "bad id", nil)
		return 0, false
	}
	return id, true
}

func (s *Service) hList(w http.ResponseWriter, r *http.Request) {
	rules, err := s.List(r.Context())
	if err != nil {
		s.fail(w, err, nil)
		return
	}
	WriteJSON(w, http.StatusOK, model.Page[StoredRule]{Items: rules, Total: len(rules), Limit: len(rules)})
}

func (s *Service) hGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rule, err := s.Get(r.Context(), id)
	if err != nil {
		s.fail(w, err, nil)
		return
	}
	WriteJSON(w, http.StatusOK, rule)
}

type ruleBody struct {
	YAML    *string `json:"yaml"`
	Enabled *bool   `json:"enabled"`
}

func (s *Service) hCreate(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if !Decode(w, r, &b) {
		return
	}
	if b.YAML == nil {
		WriteErr(w, http.StatusUnprocessableEntity, "validation", "pole yaml jest wymagane", nil)
		return
	}
	author := ""
	if p := auth.FromContext(r.Context()); p != nil {
		author = p.User.Email
	}
	rule, val, err := s.Create(r.Context(), *b.YAML, b.Enabled, author)
	if err != nil {
		s.fail(w, err, &val)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"rule": rule, "validation": val})
}

func (s *Service) hUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b ruleBody
	if !Decode(w, r, &b) {
		return
	}
	rule, val, err := s.Update(r.Context(), id, b.YAML, b.Enabled)
	if err != nil {
		s.fail(w, err, &val)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"rule": rule, "validation": val})
}

func (s *Service) hDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.Delete(r.Context(), id); err != nil {
		s.fail(w, err, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) hValidate(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if !Decode(w, r, &b) {
		return
	}
	text := ""
	if b.YAML != nil {
		text = *b.YAML
	}
	WriteJSON(w, http.StatusOK, s.Validate(text))
}

func (s *Service) hDryRun(w http.ResponseWriter, r *http.Request) {
	var b struct {
		YAML  string `json:"yaml"`
		Limit int    `json:"limit"`
	}
	if !Decode(w, r, &b) {
		return
	}
	res, err := s.DryRun(r.Context(), b.YAML, b.Limit)
	if err != nil {
		s.fail(w, err, nil)
		return
	}
	WriteJSON(w, http.StatusOK, res)
}

func (s *Service) hEvaluate(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Evaluate(r.Context(), 0)
	if err != nil {
		s.fail(w, err, nil)
		return
	}
	WriteJSON(w, http.StatusOK, rep)
}

func (s *Service) hViolations(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	var statuses []string
	if v := q.Get("status"); v != "" {
		statuses = strings.Split(v, ",")
	}
	page, err := s.Violations(r.Context(), id, statuses, limit, offset)
	if err != nil {
		s.fail(w, err, nil)
		return
	}
	WriteJSON(w, http.StatusOK, page)
}
