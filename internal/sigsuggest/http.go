package sigsuggest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg}})
}

// Handler serves POST /signatures/suggest {"service_id": N}. It reads stored
// data only and saves nothing; the analyst saves the YAML with POST /signatures.
func (s *Suggester) Handler(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the request body is too large or unreadable")
		return
	}
	var body struct {
		ServiceID int64 `json:"service_id"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the request body is not valid JSON: "+err.Error())
		return
	}
	if body.ServiceID <= 0 {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "pole service_id jest wymagane")
		return
	}
	res, err := s.Suggest(r.Context(), body.ServiceID)
	switch {
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "usługa nie ma zapisanej obserwacji")
	case errors.Is(err, context.Canceled):
	case err != nil:
		s.log.Error("signature suggestion failed", "service", body.ServiceID, "error", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	default:
		writeJSON(w, http.StatusOK, res)
	}
}
