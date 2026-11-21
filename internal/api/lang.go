package api

import (
	"net/http"
	"strings"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/model"
)

// reqLang is the language of the texts the server writes for this request:
// "en" or "pl". The query parameter lang wins; otherwise the first tag of
// Accept-Language; otherwise "pl".
func reqLang(r *http.Request) string {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang")))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language")))
		v, _, _ = strings.Cut(v, ",")
		v, _, _ = strings.Cut(v, ";")
	}
	if v == "en" || strings.HasPrefix(v, "en-") {
		return "en"
	}
	return "pl"
}

// localize renders the summaries of changes in the language of the request.
// The store already renders Polish, so only English rewrites them.
func localize(r *http.Request, cs []model.Change) {
	lang := reqLang(r)
	for i := range cs {
		cs[i].Summary = analyze.RenderSummary(cs[i], lang)
	}
}

// getChange is GET /changes/{id}: one change, its summary in the language
// of the request.
func (s *Server) getChange(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	c, err := s.st.GetChange(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c.Summary = analyze.RenderSummary(c, reqLang(r))
	writeJSON(w, http.StatusOK, c)
}

// summaryIn is analyze.RenderSummary, for handlers that do not import analyze.
func summaryIn(c model.Change, lang string) string { return analyze.RenderSummary(c, lang) }
