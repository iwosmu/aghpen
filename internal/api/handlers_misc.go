package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/model"
)

// ---------- signatures ----------

func (s *Server) listSignatures(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	f := signatureFilter(q)
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListSignatures(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getSignature(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	g, err := s.st.GetSignature(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// checkSignature runs the validator. It answers the request and returns false
// when the YAML is not acceptable: unsafe_signature for a safety issue, validation otherwise.
func (s *Server) checkSignature(w http.ResponseWriter, yaml string) (model.Signature, bool) {
	if strings.TrimSpace(yaml) == "" {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "yaml is required")
		return model.Signature{}, false
	}
	res, meta := s.d.Signatures.Validate(yaml)
	for _, is := range res.Issues {
		if is.Safety {
			writeErrDetails(w, http.StatusUnprocessableEntity, "unsafe_signature", "the signature breaks a safe-detection rule: "+is.Message, res)
			return meta, false
		}
	}
	if !res.OK {
		writeErrDetails(w, http.StatusUnprocessableEntity, "validation", "the signature is not valid", res)
		return meta, false
	}
	if meta.Slug == "" {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "the signature has no id (slug)")
		return meta, false
	}
	return meta, true
}

func (s *Server) signaturesChanged(ctx context.Context) {
	if s.d.Hooks.SignaturesChanged != nil {
		s.d.Hooks.SignaturesChanged(context.WithoutCancel(ctx))
	}
}

func (s *Server) createSignature(w http.ResponseWriter, r *http.Request) {
	var in struct {
		YAML    string `json:"yaml"`
		Enabled *bool  `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	if s.d.Signatures == nil {
		notWired(w, "the signature validator (internal/sig)")
		return
	}
	meta, ok := s.checkSignature(w, in.YAML)
	if !ok {
		return
	}
	meta.YAML, meta.Builtin, meta.Enabled = in.YAML, false, in.Enabled == nil || *in.Enabled
	if meta.Author == "" {
		meta.Author = userEmail(r)
	}
	g, err := s.st.CreateSignature(r.Context(), meta)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.signaturesChanged(r.Context())
	auditSet(r, "", "", g.ID, map[string]any{"slug": g.Slug})
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) updateSignature(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		YAML    *string `json:"yaml"`
		Enabled *bool   `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	g, err := s.st.GetSignature(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.YAML != nil && *in.YAML != g.YAML {
		if g.Builtin {
			writeErr(w, http.StatusForbidden, "forbidden", "a built-in signature cannot be edited; disable it and add your own copy")
			return
		}
		if s.d.Signatures == nil {
			notWired(w, "the signature validator (internal/sig)")
			return
		}
		meta, ok := s.checkSignature(w, *in.YAML)
		if !ok {
			return
		}
		g.Slug, g.Name, g.Category, g.Description, g.Tags, g.Interest, g.YAML = meta.Slug, meta.Name, meta.Category, meta.Description, meta.Tags, meta.Interest, *in.YAML
		if meta.Author != "" {
			g.Author = meta.Author
		}
	}
	if in.Enabled != nil {
		g.Enabled = *in.Enabled
	}
	if g, err = s.st.UpdateSignature(r.Context(), g); err != nil {
		s.fail(w, r, err)
		return
	}
	s.signaturesChanged(r.Context())
	auditSet(r, "", "", nil, map[string]any{"slug": g.Slug, "enabled": g.Enabled})
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) deleteSignature(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	g, err := s.st.GetSignature(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if g.Builtin {
		writeErr(w, http.StatusForbidden, "forbidden", "a built-in signature cannot be deleted; disable it")
		return
	}
	if err := s.st.DeleteSignature(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.signaturesChanged(r.Context())
	auditSet(r, "", "", nil, map[string]any{"slug": g.Slug})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validateSignature(w http.ResponseWriter, r *http.Request) {
	var in struct {
		YAML string `json:"yaml"`
	}
	if !decode(w, r, &in) {
		return
	}
	if s.d.Signatures == nil {
		notWired(w, "the signature validator (internal/sig)")
		return
	}
	res, _ := s.d.Signatures.Validate(in.YAML)
	if res.Issues == nil {
		res.Issues = []model.SignatureIssue{}
	}
	if res.Paths == nil {
		res.Paths = []string{}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) retroHunt(w http.ResponseWriter, r *http.Request) {
	var in struct {
		YAML       string `json:"yaml"`
		ID         int64  `json:"id"`
		LatestOnly bool   `json:"latest_only"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.YAML == "" && in.ID > 0 {
		g, err := s.st.GetSignature(r.Context(), in.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		in.YAML = g.YAML
	}
	if strings.TrimSpace(in.YAML) == "" {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "send yaml or id")
		return
	}
	if s.d.RetroHunter == nil {
		notWired(w, "retro-hunt (internal/sig)")
		return
	}
	res, err := s.d.RetroHunter.RetroHunt(r.Context(), in.YAML, in.LatestOnly)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", err.Error())
		return
	}
	if res.Hits == nil {
		res.Hits = []model.RetroHit{}
	}
	auditSet(r, "", "", nil, map[string]any{"scanned": res.Scanned, "hits": len(res.Hits)})
	writeJSON(w, http.StatusOK, res)
}

// ---------- safety policy and emergency stop ----------

func (s *Server) getSafety(w http.ResponseWriter, r *http.Request) {
	p, err := s.st.GetSafetyPolicy(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) putSafety(w http.ResponseWriter, r *http.Request) {
	cur, err := s.st.GetSafetyPolicy(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in := cur
	if !decode(w, r, &in) {
		return
	}
	in.EmergencyStop = cur.EmergencyStop // only the emergency-stop routes change the flag
	switch {
	case in.MaxPPS < 1 || in.MaxPPS > 100000:
		err = invalid("max_pps must be between 1 and 100000")
	case in.MaxHTTPRPS <= 0 || in.MaxHTTPRPS > 10000:
		err = invalid("max_http_rps must be above 0 and at most 10000")
	case in.MaxPerHostRPS <= 0 || in.MaxPerHostRPS > in.MaxHTTPRPS:
		err = invalid("max_per_host_rps must be above 0 and not above max_http_rps")
	case in.MaxPathsPerHost < 0 || in.MaxPathsPerHost > 100:
		err = invalid("max_paths_per_host must be between 0 and 100")
	case strings.TrimSpace(in.UserAgent) == "" || len(in.UserAgent) > 300 || strings.ContainsAny(in.UserAgent, "\r\n"):
		err = invalid("user_agent must be one line of at most 300 characters")
	case strings.ContainsAny(in.AllowedPorts+in.DeniedPorts, " ;|&$`'\"\\\n"):
		err = invalid("allowed_ports and denied_ports must be nmap port lists")
	}
	if err == nil {
		// Safe detection only: the scanner never uses a method other than GET or HEAD.
		methods := []string{}
		for _, m := range in.AllowedMethods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != http.MethodGet && m != http.MethodHead {
				err = invalid("allowed_methods can only hold GET and HEAD (safe detection), got %q", m)
				break
			}
			methods = append(methods, m)
		}
		if len(methods) == 0 {
			methods = []string{http.MethodGet, http.MethodHead}
		}
		in.AllowedMethods = methods
	}
	if err == nil {
		ex := []string{}
		for _, e := range in.Exclusions {
			t, perr := ParseTarget(e)
			if perr != nil {
				err = invalid("exclusion %q: %v", e, perr)
				break
			}
			ex = append(ex, t.Value)
		}
		in.Exclusions = ex
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.st.PutSafetyPolicy(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "safety.update", "safety", nil, map[string]any{"max_pps": p.MaxPPS, "max_http_rps": p.MaxHTTPRPS, "exclusions": len(p.Exclusions)})
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) emergencyStop(w http.ResponseWriter, r *http.Request) {
	auditSet(r, "safety.emergency_stop", "safety", nil, nil)
	var p model.SafetyPolicy
	var err error
	if s.d.Runner != nil {
		p, err = s.d.Runner.EmergencyStop(r.Context())
	} else {
		p, err = s.st.SetEmergencyStop(r.Context(), true)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) releaseEmergencyStop(w http.ResponseWriter, r *http.Request) {
	auditSet(r, "safety.emergency_stop_release", "safety", nil, nil)
	var p model.SafetyPolicy
	var err error
	if s.d.Runner != nil {
		p, err = s.d.Runner.ReleaseEmergencyStop(r.Context())
	} else {
		p, err = s.st.SetEmergencyStop(r.Context(), false)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// ---------- DefectDojo settings ----------

func (s *Server) getDojo(w http.ResponseWriter, r *http.Request) {
	d, err := s.st.GetDefectDojo(r.Context(), false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func checkDojo(d *model.DefectDojoSettings) error {
	d.URL = strings.TrimRight(strings.TrimSpace(d.URL), "/")
	if d.URL != "" {
		u, err := url.Parse(d.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return invalid("url must be an http or https address")
		}
	}
	if d.Enabled && d.URL == "" {
		return invalid("url is required when the integration is enabled")
	}
	if d.MinInterest < 0 || d.MinInterest > 100 {
		return invalid("min_interest must be between 0 and 100")
	}
	return nil
}

func (s *Server) putDojo(w http.ResponseWriter, r *http.Request) {
	in, err := s.st.GetDefectDojo(r.Context(), false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !decode(w, r, &in) {
		return
	}
	if err := checkDojo(&in); err != nil {
		s.fail(w, r, err)
		return
	}
	keyChanged := in.APIKey != ""
	d, err := s.st.PutDefectDojo(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The API key never goes to the audit log.
	auditSet(r, "integration.defectdojo.update", "integration", "defectdojo", map[string]any{"url": d.URL, "enabled": d.Enabled, "api_key_changed": keyChanged})
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) testDojo(w http.ResponseWriter, r *http.Request) {
	stored, err := s.st.GetDefectDojo(r.Context(), true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in := stored
	in.APIKey = ""
	if !decode(w, r, &in) {
		return
	}
	if in.APIKey == "" {
		in.APIKey = stored.APIKey // test the stored key when the form sends none
	}
	if err := checkDojo(&in); err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "integration.defectdojo.test", "integration", "defectdojo", map[string]any{"url": in.URL})
	if s.d.Dojo == nil {
		notWired(w, "the DefectDojo client (internal/defectdojo)")
		return
	}
	ok, msg, version := s.d.Dojo.Test(r.Context(), in)
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "message": msg, "version": version})
}

// ---------- health ----------

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	out := map[string]any{"status": "ok", "version": s.d.Version, "db": "ok", "tde": false}
	if err := s.st.Ping(ctx); err != nil {
		out["status"], out["db"] = "error", "unreachable"
		writeJSON(w, http.StatusServiceUnavailable, out)
		return
	}
	tde := s.st.TDE(ctx)
	out["tde"] = tde.Active
	out["tde_detail"] = tde
	out["field_encryption"] = map[string]any{"algorithm": "AES-256-GCM envelope", "key_id": s.st.Keyring().CurrentID()}
	out["engine"] = s.d.Runner != nil && s.d.Runner.EngineWired()
	writeJSON(w, http.StatusOK, out)
}

// ---------- result import ----------

func (s *Server) importResults(w http.ResponseWriter, r *http.Request) {
	auditSet(r, "result.import", "result", nil, nil)
	name, data, ok := readUpload(w, r, 256<<20)
	if !ok {
		return
	}
	auditSet(r, "", "", nil, map[string]any{"file": name, "bytes": len(data)})
	if s.d.Importer == nil {
		notWired(w, "the result importer (internal/interchange)")
		return
	}
	if s.d.Runner == nil {
		notWired(w, "the run manager")
		return
	}
	format, hosts, invalidLines, err := s.d.Importer.ParseResults(name, data)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "the file could not be read: "+err.Error())
		return
	}
	rep := model.ImportReport{Format: format, Invalid: invalidLines, Skipped: len(invalidLines)}
	if rep.Invalid == nil {
		rep.Invalid = []model.InvalidLine{}
	}
	if len(hosts) == 0 {
		writeJSON(w, http.StatusOK, rep)
		return
	}
	run, err := s.d.Runner.Import(r.Context(), name, hosts, userID(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rep.RunID, rep.Hosts = &run.ID, len(hosts)
	for _, h := range hosts {
		rep.Services += len(h.Services)
	}
	auditSet(r, "", "", run.ID, map[string]any{"format": format, "hosts": rep.Hosts, "services": rep.Services})
	writeJSON(w, http.StatusCreated, rep)
}

// ---------- streaming export ----------

// rowWriter streams rows as a JSON array or as CSV. Nothing is buffered beyond
// one row plus the write buffer, so 100 000 rows do not sit in memory.
type rowWriter struct {
	w      http.ResponseWriter
	csv    *csv.Writer
	enc    *json.Encoder
	n      int
	header []string
}

func newRowWriter(w http.ResponseWriter, name, format string, header []string) *rowWriter {
	rw := &rowWriter{w: w, header: header}
	file := fmt.Sprintf("czujka-%s-%s.%s", name, time.Now().UTC().Format("20060102-150405"), format)
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		rw.csv = csv.NewWriter(w)
		_ = rw.csv.Write(header)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "[")
		rw.enc = json.NewEncoder(w)
	}
	return rw
}

// csvSafe stops a spreadsheet from running a cell as a formula.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (rw *rowWriter) write(obj any, cells func() []string) error {
	rw.n++
	if rw.csv != nil {
		row := cells()
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		if err := rw.csv.Write(row); err != nil {
			return err
		}
		if rw.n%500 == 0 {
			rw.csv.Flush()
			return rw.csv.Error()
		}
		return nil
	}
	if rw.n > 1 {
		if _, err := io.WriteString(rw.w, ","); err != nil {
			return err
		}
	}
	return rw.enc.Encode(obj)
}

func (rw *rowWriter) close() {
	if rw.csv != nil {
		rw.csv.Flush()
		return
	}
	_, _ = io.WriteString(rw.w, "]\n")
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func tsp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return ts(*t)
}

func ints(v []int) string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = strconv.Itoa(x)
	}
	return strings.Join(out, " ")
}

func techList(v []model.Technology) string {
	out := make([]string, 0, len(v))
	for _, t := range v {
		if t.Version != "" {
			out = append(out, t.Name+" "+t.Version)
		} else {
			out = append(out, t.Name)
		}
	}
	return strings.Join(out, "; ")
}

func splitFile(w http.ResponseWriter, r *http.Request, formats ...string) (base, format string, ok bool) {
	file := chi.URLParam(r, "file")
	base, format = strings.TrimSuffix(file, path.Ext(file)), strings.TrimPrefix(path.Ext(file), ".")
	for _, f := range formats {
		if f == format {
			return base, format, true
		}
	}
	writeErr(w, http.StatusBadRequest, "bad_request", "the format must be one of: "+strings.Join(formats, ", "))
	return "", "", false
}

// export streams hosts, services, findings, changes or signatures as JSON or CSV. The list filters apply.
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	kind, format, ok := splitFile(w, r, "json", "csv")
	if !ok {
		return
	}
	q := query(r)
	ctx := r.Context()
	if a := auditOf(r); a != nil {
		a.force = true // exports leave the system: they go to the audit log although they are reads
	}
	auditSet(r, "export."+kind, "export", nil, map[string]any{"format": format, "query": r.URL.RawQuery})
	var rw *rowWriter
	var err error
	switch kind {
	case "hosts":
		f := hostFilter(q)
		if !q.ok(w) {
			return
		}
		rw = newRowWriter(w, kind, format, []string{"id", "ip", "hostnames", "status", "p_alive", "stability", "first_seen", "last_seen", "last_up",
			"os_guess", "mac", "vendor", "label", "owner", "criticality", "tags", "interest", "service_count", "open_ports", "technologies", "note"})
		err = s.st.EachHost(ctx, f, func(h *model.Host) error {
			return rw.write(h, func() []string {
				return []string{strconv.FormatInt(h.ID, 10), h.IP, strings.Join(h.Hostnames, " "), string(h.Status), fmt.Sprintf("%.3f", h.PAlive),
					fmt.Sprintf("%.3f", h.Stability), ts(h.FirstSeen), ts(h.LastSeen), tsp(h.LastUp), h.OSGuess, h.MAC, h.Vendor, h.Label, h.Owner,
					strconv.Itoa(h.Criticality), strings.Join(h.Tags, " "), strconv.Itoa(h.Interest), strconv.Itoa(h.ServiceCount), ints(h.OpenPorts),
					strings.Join(h.Technologies, "; "), h.Note}
			})
		})
	case "services":
		f := serviceFilter(q)
		if !q.ok(w) {
			return
		}
		rw = newRowWriter(w, kind, format, []string{"id", "host_id", "ip", "hostname", "port", "proto", "state", "name", "product", "version", "tls",
			"title", "http_status", "url", "technologies", "classes", "interest", "group_key", "tags", "first_seen", "last_seen", "last_changed", "banner", "note"})
		err = s.st.EachService(ctx, f, func(v *model.Service) error {
			return rw.write(v, func() []string {
				return []string{strconv.FormatInt(v.ID, 10), strconv.FormatInt(v.HostID, 10), v.IP, v.Hostname, strconv.Itoa(v.Port), v.Proto, string(v.State),
					v.Name, v.Product, v.Version, strconv.FormatBool(v.TLS), v.Title, strconv.Itoa(v.HTTPStatus), v.URL, techList(v.Technologies),
					strings.Join(v.Classes, " "), strconv.Itoa(v.Interest), v.GroupKey, strings.Join(v.Tags, " "), ts(v.FirstSeen), ts(v.LastSeen),
					tsp(v.LastChanged), v.Banner, v.Note}
			})
		})
	case "findings":
		f := findingFilter(q)
		if !q.ok(w) {
			return
		}
		rw = newRowWriter(w, kind, format, []string{"id", "key", "type", "title", "severity", "status", "interest", "ip", "port", "url", "signature",
			"tags", "assignee", "first_seen", "last_seen", "dojo_url", "manual", "description", "note"})
		err = s.st.EachFinding(ctx, f, func(v *model.Finding) error {
			return rw.write(v, func() []string {
				return []string{strconv.FormatInt(v.ID, 10), v.Key, v.Type, v.Title, string(v.Severity), string(v.Status), strconv.Itoa(v.Interest), v.IP,
					strconv.Itoa(v.Port), v.URL, v.Signature, strings.Join(v.Tags, " "), v.Assignee, ts(v.FirstSeen), ts(v.LastSeen), v.DojoURL,
					strconv.FormatBool(v.Manual), v.Description, v.Note}
			})
		})
	case "changes":
		f := changeFilter(q)
		if !q.ok(w) {
			return
		}
		rw = newRowWriter(w, kind, format, []string{"id", "run_id", "prev_run_id", "at", "kind", "severity", "ip", "port", "summary", "field", "before",
			"after", "expected", "acked_by", "acked_at"})
		err = s.st.EachChange(ctx, f, func(v *model.Change) error {
			return rw.write(v, func() []string {
				prev := ""
				if v.PrevRunID != nil {
					prev = strconv.FormatInt(*v.PrevRunID, 10)
				}
				before, _ := json.Marshal(v.Before)
				after, _ := json.Marshal(v.After)
				return []string{strconv.FormatInt(v.ID, 10), strconv.FormatInt(v.RunID, 10), prev, ts(v.At), string(v.Kind), string(v.Severity), v.IP,
					strconv.Itoa(v.Port), v.Summary, v.Field, string(before), string(after), strconv.FormatBool(v.Expected), v.AckedBy, tsp(v.AckedAt)}
			})
		})
	case "signatures":
		f := signatureFilter(q)
		if !q.ok(w) {
			return
		}
		rw = newRowWriter(w, kind, format, []string{"id", "slug", "name", "category", "enabled", "builtin", "author", "tags", "interest", "match_count",
			"updated_at", "description", "yaml"})
		err = s.st.EachSignature(ctx, f, func(v *model.Signature) error {
			return rw.write(v, func() []string {
				return []string{strconv.FormatInt(v.ID, 10), v.Slug, v.Name, v.Category, strconv.FormatBool(v.Enabled), strconv.FormatBool(v.Builtin), v.Author,
					strings.Join(v.Tags, " "), strconv.Itoa(v.Interest), strconv.Itoa(v.MatchCount), ts(v.UpdatedAt), v.Description, v.YAML}
			})
		})
	default:
		writeErr(w, http.StatusNotFound, "not_found", "the export kind must be hosts, services, findings, changes or signatures")
		return
	}
	if rw != nil {
		rw.close()
		auditSet(r, "", "", nil, map[string]any{"rows": rw.n})
	}
	if err != nil {
		// The status line is sent already; the truncated body and the log tell the story.
		s.log.Error("export failed", "kind", kind, "err", err)
		auditSet(r, "", "", nil, map[string]any{"error": err.Error()})
	}
}

// exportRun streams the results of one run: JSON (HostResult records), CSV
// (one row per service) or nmap XML (through the Exporter seam).
func (s *Server) exportRun(w http.ResponseWriter, r *http.Request) {
	base, format, ok := splitFile(w, r, "json", "csv", "xml")
	if !ok {
		return
	}
	id, err := strconv.ParseInt(base, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "the run id must be a number")
		return
	}
	run, err := s.st.GetRun(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if a := auditOf(r); a != nil {
		a.force = true
	}
	auditSet(r, "export.run", "export", id, map[string]any{"format": format})
	cookies := canSeeCookies(r)
	clean := func(h *model.HostResult) {
		if !cookies {
			for i := range h.Services {
				redactCookies(&h.Services[i])
			}
		}
	}
	if format == "xml" {
		if s.d.Exporter == nil {
			notWired(w, "the nmap XML exporter (internal/interchange)")
			return
		}
		var hosts []model.HostResult
		if err := s.st.EachRunResult(r.Context(), id, func(h *model.HostResult) error {
			clean(h)
			hosts = append(hosts, *h)
			return nil
		}); err != nil {
			s.fail(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="czujka-run-%d.xml"`, id))
		if err := s.d.Exporter.NmapXML(w, run, hosts); err != nil {
			s.log.Error("nmap XML export failed", "run", id, "err", err)
		}
		return
	}
	rw := newRowWriter(w, fmt.Sprintf("run-%d", id), format, []string{"run_id", "ip", "hostnames", "up", "reason", "observed_at", "port", "proto", "state",
		"name", "product", "version", "tunnel", "http_status", "title", "url", "technologies", "classes"})
	err = s.st.EachRunResult(r.Context(), id, func(h *model.HostResult) error {
		clean(h)
		if format == "json" {
			return rw.write(h, nil)
		}
		head := []string{strconv.FormatInt(h.RunID, 10), h.IP, strings.Join(h.Hostnames, " "), strconv.FormatBool(h.Up), h.Reason, ts(h.ObservedAt)}
		if len(h.Services) == 0 {
			return rw.write(nil, func() []string { return append(head, make([]string, 12)...) })
		}
		for i := range h.Services {
			sv := &h.Services[i]
			status, title, u := "", "", ""
			if sv.HTTP != nil {
				status, title, u = strconv.Itoa(sv.HTTP.Status), sv.HTTP.Title, sv.HTTP.URL
			}
			if err := rw.write(nil, func() []string {
				return append(append([]string{}, head...), strconv.Itoa(sv.Port), sv.Proto, sv.State, sv.Name, sv.Product, sv.Version, sv.Tunnel, status, title, u,
					techList(sv.Technologies), strings.Join(sv.Classes, " "))
			}); err != nil {
				return err
			}
		}
		return nil
	})
	rw.close()
	auditSet(r, "", "", nil, map[string]any{"rows": rw.n})
	if err != nil {
		s.log.Error("run export failed", "run", id, "err", err)
	}
}

// ---------- web UI ----------

func (s *Server) uiFS() fs.FS {
	if s.d.WebDir != "" {
		if st, err := os.Stat(path.Join(s.d.WebDir, "index.html")); err == nil && !st.IsDir() {
			return os.DirFS(s.d.WebDir)
		}
	}
	if s.d.WebFS != nil {
		if _, err := fs.Stat(s.d.WebFS, "index.html"); err == nil {
			return s.d.WebFS
		}
	}
	return nil
}

const noUI = `<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>Czujka</title></head><body style="font-family:system-ui;max-width:40rem;margin:4rem auto">
<h1>Czujka</h1><p>Serwer API działa pod <code>/api/v1</code>. Interfejs WWW nie jest zbudowany w tym obrazie
(brak <code>web/dist</code>; ustaw <code>CZUJKA_WEB_DIR</code>).</p>
<p>The API server is running under <code>/api/v1</code>. The web UI is not built into this image.</p>
<p><a href="/api/v1/healthz">/api/v1/healthz</a></p></body></html>`

// serveUI serves the built single-page application: real files as they are,
// every other path as index.html, so client-side routes survive a reload.
func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusNotFound, "not_found", "no such route")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "bad_request", "method not allowed")
		return
	}
	ui := s.uiFS()
	if ui == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, noUI)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if st, err := fs.Stat(ui, name); err != nil || st.IsDir() {
		if path.Ext(name) != "" { // a missing asset is a 404, not the app shell
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	} else if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	http.ServeFileFS(w, r, ui, name)
}
