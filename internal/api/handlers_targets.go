package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/targets"
)

func (s *Server) listScopes(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	o := q.opts()
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListScopes(r.Context(), o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.st.GetScope(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func checkScope(sc *model.Scope) error {
	sc.Name = strings.TrimSpace(sc.Name)
	if sc.Name == "" || len(sc.Name) > 200 {
		return invalid("the scope needs a name of at most 200 characters")
	}
	if sc.Criticality == 0 {
		sc.Criticality = 3
	}
	if sc.Criticality < 1 || sc.Criticality > 5 {
		return invalid("criticality must be between 1 and 5")
	}
	return nil
}

func (s *Server) createScope(w http.ResponseWriter, r *http.Request) {
	var in model.Scope
	if !decode(w, r, &in) {
		return
	}
	if err := checkScope(&in); err != nil {
		s.fail(w, r, err)
		return
	}
	sc, err := s.st.CreateScope(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", sc.ID, map[string]any{"name": sc.Name})
	writeJSON(w, http.StatusCreated, sc)
}

func (s *Server) updateScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var patch map[string]json.RawMessage
	if !decode(w, r, &patch) {
		return
	}
	sc, err := s.st.GetScope(r.Context(), id)
	if err == nil {
		err = mergePatch(&sc, patch, "name", "description", "owner", "criticality", "tags")
	}
	if err == nil {
		err = checkScope(&sc)
	}
	if err == nil {
		sc, err = s.st.UpdateScope(r.Context(), sc)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) deleteScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteScope(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := query(r)
	o := q.opts()
	if !q.ok(w) {
		return
	}
	if _, err := s.st.GetScope(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	page, err := s.st.ListTargets(r.Context(), id, o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for i := range page.Items {
		page.Items[i].MapsTo = targets.MapsTo(page.Items[i].Value)
	}
	writeJSON(w, http.StatusOK, page)
}

// preview removes duplicates and computes the counters of a parsed target list.
func (s *Server) preview(r *http.Request, valid []model.Target, invalid []model.InvalidLine) (model.TargetPreview, error) {
	return s.previewAt(r, valid, invalid, nil)
}

// lineOf returns the line (from 1) of the source that holds a target value; 0 when unknown.
type lineOf func(value string) int

// textLines maps target values to the first line of text that holds them:
// each line is parsed alone with the same parser; a value the parser does
// not find on one line (a JSON file, say) is searched as text.
func (s *Server) textLines(text string) lineOf {
	var idx map[string]int
	var lines []string
	return func(v string) int {
		if idx == nil {
			idx = map[string]int{}
			lines = strings.Split(text, "\n")
			for i, ln := range lines {
				if strings.TrimSpace(ln) == "" {
					continue
				}
				ts, _ := s.targets.ParseText(ln)
				for _, t := range ts {
					if _, ok := idx[t.Value]; !ok {
						idx[t.Value] = i + 1
					}
				}
			}
		}
		if n, ok := idx[v]; ok {
			return n
		}
		for i, ln := range lines {
			if strings.Contains(ln, v) {
				return i + 1
			}
		}
		return 0
	}
}

// previewAt is preview with the source lines: an entry that the safety
// policy or the operator lock drops keeps its real line number.
func (s *Server) previewAt(r *http.Request, valid []model.Target, invalid []model.InvalidLine, at lineOf) (model.TargetPreview, error) {
	p := model.TargetPreview{Valid: []model.Target{}, Invalid: invalid}
	if p.Invalid == nil {
		p.Invalid = []model.InvalidLine{}
	}
	seen := map[string]bool{}
	for _, t := range valid {
		if seen[t.Value] {
			p.Duplicates++
			continue
		}
		seen[t.Value] = true
		if t.Tags == nil {
			t.Tags = []string{}
		}
		p.Valid = append(p.Valid, t)
		p.AddressCount += t.Addresses
	}
	policy, err := s.st.GetSafetyPolicy(r.Context())
	if err != nil {
		return p, err
	}
	if len(policy.AllowedNetworks) > 0 || len(policy.OperatorNetworks) > 0 {
		// A target outside the allowed networks of the policy, or outside the
		// operator lock, is refused at entry.
		kept, dropped, err := runner.FilterAllowed(r.Context(), p.Valid, policy, s.lookup)
		if err != nil {
			return p, err
		}
		p.Valid = append([]model.Target{}, kept...)
		p.AddressCount = 0
		for _, t := range p.Valid {
			p.AddressCount += t.Addresses
		}
		for _, d := range dropped {
			d.Line = 0 // FilterAllowed numbers its own input, not the source
			if at != nil {
				d.Line = at(d.Value)
			}
			p.Invalid = append(p.Invalid, d)
		}
	}
	p.Excluded = s.targets.Excluded(p.Valid, policy.Exclusions)
	return p, nil
}

// save stores the valid targets of a preview in a scope.
func (s *Server) saveTargets(r *http.Request, scopeID int64, p model.TargetPreview) (model.TargetPreview, error) {
	saved, dup, err := s.st.AddTargets(r.Context(), scopeID, p.Valid, userID(r))
	if err != nil {
		return p, err
	}
	p.Valid = saved
	p.Duplicates += dup
	p.AddressCount = 0
	for _, t := range saved {
		p.AddressCount += t.Addresses
	}
	auditSet(r, "", "", scopeID, map[string]any{"saved": len(saved), "duplicates": p.Duplicates, "invalid": len(p.Invalid), "addresses": p.AddressCount})
	return p, nil
}

// parseTargetBody accepts {"text": "..."} or an array of Target objects.
func (s *Server) parseTargetBody(w http.ResponseWriter, r *http.Request) ([]model.Target, []model.InvalidLine, lineOf, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the request body is too large or unreadable")
		return nil, nil, nil, false
	}
	trim := bytes.TrimSpace(body)
	if len(trim) > 0 && trim[0] == '[' {
		var items []model.Target
		if err := json.Unmarshal(trim, &items); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "the request body is not a valid target list: "+err.Error())
			return nil, nil, nil, false
		}
		valid, invalid := []model.Target{}, []model.InvalidLine{}
		pos := map[string]int{} // value → item number, from 1
		for i, it := range items {
			t, err := ParseTarget(it.Value)
			if err != nil {
				invalid = append(invalid, model.InvalidLine{Line: i + 1, Value: it.Value, Reason: err.Error()})
				continue
			}
			if _, ok := pos[t.Value]; !ok {
				pos[t.Value] = i + 1
			}
			t.Note, t.Source = it.Note, "api"
			if it.Tags != nil {
				t.Tags = it.Tags
			}
			valid = append(valid, t)
		}
		return valid, invalid, func(v string) int { return pos[v] }, true
	}
	var in struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(trim, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the request body is not valid JSON: "+err.Error())
		return nil, nil, nil, false
	}
	valid, invalid := s.targets.ParseText(in.Text)
	return valid, invalid, s.textLines(in.Text), true
}

func (s *Server) previewTargets(w http.ResponseWriter, r *http.Request) {
	valid, invalid, at, ok := s.parseTargetBody(w, r)
	if !ok {
		return
	}
	p, err := s.previewAt(r, valid, invalid, at)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) addTargets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.st.GetScope(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	valid, invalid, at, ok := s.parseTargetBody(w, r)
	if !ok {
		return
	}
	p, err := s.previewAt(r, valid, invalid, at)
	if err == nil {
		p, err = s.saveTargets(r, id, p)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// readUpload returns the content of the multipart field "file".
func readUpload(w http.ResponseWriter, r *http.Request, limit int64) (name string, data []byte, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "expected multipart/form-data with a field named file")
		return "", nil, false
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the form has no field named file")
		return "", nil, false
	}
	defer f.Close()
	data, err = io.ReadAll(f)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the uploaded file is unreadable")
		return "", nil, false
	}
	return hdr.Filename, data, true
}

func (s *Server) importTargets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.st.GetScope(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	name, data, ok := readUpload(w, r, 32<<20)
	if !ok {
		return
	}
	valid, invalid, err := s.targets.ParseFile(name, data)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
		return
	}
	p, err := s.previewAt(r, valid, invalid, s.textLines(string(data)))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	dry := r.FormValue("dry_run")
	if dry == "true" || dry == "1" {
		auditSet(r, "", "", id, map[string]any{"dry_run": true, "file": name, "valid": len(p.Valid)})
		writeJSON(w, http.StatusOK, p)
		return
	}
	if p, err = s.saveTargets(r, id, p); err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", nil, map[string]any{"file": name})
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var patch map[string]json.RawMessage
	if !decode(w, r, &patch) {
		return
	}
	t, err := s.st.GetTarget(r.Context(), id)
	if err == nil {
		err = mergePatch(&t, patch, "value", "note", "tags", "enabled")
	}
	if err == nil {
		parsed, perr := ParseTarget(t.Value)
		if perr != nil {
			err = invalid("value: %v", perr)
		} else {
			t.Kind, t.Value, t.Addresses = parsed.Kind, parsed.Value, parsed.Addresses
		}
	}
	if err == nil {
		t, err = s.st.UpdateTarget(r.Context(), t)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t.MapsTo = targets.MapsTo(t.Value)
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteTarget(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
