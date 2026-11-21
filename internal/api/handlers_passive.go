package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/passive"
)

// ---------- signature import ----------

// readText returns an uploaded text: a multipart field "file" or "text", a
// JSON body {"text": "..."} (or "yaml"), or the raw body of any other type.
func readText(w http.ResponseWriter, r *http.Request, limit int64) (name, text string, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch ct {
	case "multipart/form-data":
		if err := r.ParseMultipartForm(16 << 20); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "the multipart form is unreadable")
			return "", "", false
		}
		if f, hdr, err := r.FormFile("file"); err == nil {
			defer f.Close()
			data, err := io.ReadAll(f)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "bad_request", "the uploaded file is unreadable")
				return "", "", false
			}
			return hdr.Filename, string(data), true
		}
		if t := r.FormValue("text"); t != "" {
			return "", t, true
		}
		writeErr(w, http.StatusBadRequest, "bad_request", "the form has neither a field named file nor a field named text")
		return "", "", false
	case "application/json":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "the request body is too large or unreadable")
			return "", "", false
		}
		var in struct {
			Name string `json:"name"`
			Text string `json:"text"`
			YAML string `json:"yaml"`
		}
		if err := json.Unmarshal(body, &in); err == nil && (in.Text != "" || in.YAML != "") {
			if in.Text == "" {
				in.Text = in.YAML
			}
			return in.Name, in.Text, true
		}
		// A JSON signature file sent as the body itself.
		return "", string(body), true
	default:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "the request body is too large or unreadable")
			return "", "", false
		}
		return "", string(body), true
	}
}

func (s *Server) importSignatures(w http.ResponseWriter, r *http.Request) {
	auditSet(r, "signature.import", "signature", nil, nil)
	if s.d.SigImporter == nil {
		notWired(w, "the signature importer (internal/sigwire)")
		return
	}
	name, text, ok := readText(w, r, 16<<20)
	if !ok {
		return
	}
	if strings.TrimSpace(text) == "" {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "the signature file is empty")
		return
	}
	rep, err := s.d.SigImporter.ImportSignatures(r.Context(), text, userEmail(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", nil, map[string]any{"file": name, "created": rep.Created, "updated": rep.Updated, "skipped": len(rep.Skipped), "issues": len(rep.Validation.Issues)})
	switch {
	case len(rep.Created)+len(rep.Updated) > 0:
		writeJSON(w, http.StatusCreated, rep)
	default:
		writeErrDetails(w, http.StatusUnprocessableEntity, "validation", "no signature of the file was stored", rep)
	}
}

// ---------- run report ----------

func (s *Server) runReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if s.d.Reporter == nil {
		notWired(w, "the run report (internal/report)")
		return
	}
	format := "html"
	if strings.HasSuffix(chi.URLParam(r, "file"), ".md") {
		format = "md"
	}
	var buf bytes.Buffer
	if err := s.d.Reporter.RunReport(r.Context(), id, format, &buf); err != nil {
		s.fail(w, r, err)
		return
	}
	if format == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The report is a self-contained document with inline styles.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	}
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="czujka-run-`+chi.URLParam(r, "id")+"."+format+`"`)
	}
	_, _ = w.Write(buf.Bytes())
}

// ---------- passive sources ----------

func (s *Server) passiveImport(w http.ResponseWriter, r *http.Request) {
	if s.d.Passive == nil {
		notWired(w, "the passive sources (internal/passive)")
		return
	}
	name, data, ok := readUpload(w, r, 64<<20)
	if !ok {
		return
	}
	res, err := s.d.Passive.ImportFile(r.Context(), name, data)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "the file could not be read: "+err.Error())
		return
	}
	auditSet(r, "passive.import", "passive", nil, map[string]any{"file": name, "bytes": len(data), "candidates": len(res.Candidates), "out_of_scope": len(res.OutOfScope)})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) passivePTR(w http.ResponseWriter, r *http.Request) {
	if s.d.Passive == nil {
		notWired(w, "the passive sources (internal/passive)")
		return
	}
	res, err := s.d.Passive.PTR(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "passive.ptr", "passive", nil, map[string]any{"hints": len(res.Hints), "hosts_updated": res.HostsUpdated})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) passiveCT(w http.ResponseWriter, r *http.Request) {
	if s.d.Passive == nil {
		notWired(w, "the passive sources (internal/passive)")
		return
	}
	res, err := s.d.Passive.CT(r.Context())
	if errors.Is(err, passive.ErrExternalDisabled) {
		writeErr(w, http.StatusConflict, "disabled", "crt.sh is turned off; an administrator can turn it on in PUT /settings/passive")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "passive.crtsh", "passive", nil, map[string]any{"candidates": len(res.Candidates)})
	writeJSON(w, http.StatusOK, res)
}

// passiveConfirm turns selected candidates into targets of a scope.
func (s *Server) passiveConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ScopeID    int64 `json:"scope_id"`
		Candidates []struct {
			Value   string   `json:"value"`
			Sources []string `json:"sources"`
			Note    string   `json:"note"`
		} `json:"candidates"`
	}
	if !decode(w, r, &in) {
		return
	}
	auditSet(r, "passive.confirm", "scope", in.ScopeID, nil)
	if in.ScopeID <= 0 || len(in.Candidates) == 0 {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "scope_id and at least one candidate are required")
		return
	}
	if _, err := s.st.GetScope(r.Context(), in.ScopeID); err != nil {
		s.fail(w, r, err)
		return
	}
	valid, invalid := []model.Target{}, []model.InvalidLine{}
	for i, c := range in.Candidates {
		ts, bad := s.targets.ParseText(c.Value)
		if len(bad) > 0 || len(ts) != 1 {
			reason := "not one target"
			if len(bad) > 0 {
				reason = bad[0].Reason
			}
			invalid = append(invalid, model.InvalidLine{Line: i + 1, Value: c.Value, Reason: reason})
			continue
		}
		t := ts[0]
		t.Source = "passive"
		t.Note = c.Note
		if t.Note == "" && len(c.Sources) > 0 {
			t.Note = "źródło pasywne: " + strings.Join(c.Sources, ", ")
		}
		if t.Tags == nil {
			t.Tags = []string{}
		}
		t.Tags = append(t.Tags, "passive")
		valid = append(valid, t)
	}
	p, err := s.preview(r, valid, invalid)
	if err == nil {
		p, err = s.saveTargets(r, in.ScopeID, p)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) getPassiveSettings(w http.ResponseWriter, r *http.Request) {
	p, err := s.st.GetPassiveSettings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) putPassiveSettings(w http.ResponseWriter, r *http.Request) {
	in, err := s.st.GetPassiveSettings(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !decode(w, r, &in) {
		return
	}
	out, err := s.st.PutPassiveSettings(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "settings.passive.update", "settings", "passive", map[string]any{"crtsh_enabled": out.CTEnabled})
	writeJSON(w, http.StatusOK, out)
}
