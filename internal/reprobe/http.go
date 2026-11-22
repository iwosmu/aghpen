package reprobe

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
)

// Middleware is the permission check of internal/api: can(permission).
type Middleware func(model.Permission) func(http.Handler) http.Handler

// Service serves the reprobe routes over a StoreBackend.
type Service struct {
	B   *StoreBackend
	Now func() time.Time // default time.Now
}

// Register adds the routes to r (the /api/v1 router):
// GET /reprobe/plan and GET /settings/reprobe need scans:read;
// PUT /settings/reprobe needs scans:configure.
func (s *Service) Register(r chi.Router, can Middleware) {
	r.With(can(model.PermScansRead)).Get("/reprobe/plan", s.plan)
	r.With(can(model.PermScansRead)).Get("/settings/reprobe", s.getSettings)
	r.With(can(model.PermScansConfigure)).Put("/settings/reprobe", s.putSettings)
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

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) plan(w http.ResponseWriter, r *http.Request) {
	in, err := s.B.Snapshot(r.Context(), s.now())
	if err != nil {
		s.B.log.Error("reprobe plan", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal", "błąd wewnętrzny")
		return
	}
	writeJSON(w, http.StatusOK, Build(in))
}

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.B.Settings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "błąd wewnętrzny")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Service) putSettings(w http.ResponseWriter, r *http.Request) {
	cur, err := s.B.Settings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "błąd wewnętrzny")
		return
	}
	// A partial body changes only the fields it names.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&cur); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}
	out, err := s.B.PutSettings(r.Context(), cur)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
