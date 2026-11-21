package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/iwosmu/aghpen/internal/interchange"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"io"
)

// routesPart3 adds manual entry, findings files, DefectDojo status sync, run
// notes and ad-hoc runs (docs/API.md).
func (s *Server) routesPart3(r chi.Router, can Guard) {
	r.With(can(model.PermResultsCreate)).Post("/hosts", s.createHostManual)
	r.With(can(model.PermResultsCreate)).Post("/hosts/{id}/services", s.addServicesManual)
	r.With(can(model.PermResultsCreate)).Post("/import/findings", s.importFindings)
	r.With(can(model.PermExportRun)).Get("/export/findings.dojo.json", s.exportFindingsDojo("json"))
	r.With(can(model.PermExportRun)).Get("/export/findings.dojo.csv", s.exportFindingsDojo("csv"))
	r.With(can(model.PermResultsUpdate)).Post("/defectdojo/pull", s.dojoPull)
	r.With(can(model.PermExportRun)).Post("/defectdojo/sync", s.dojoSync)
	r.With(can(model.PermScansRun)).Patch("/runs/{id}", s.patchRun)
	r.With(can(model.PermScansRun)).Post("/runs/adhoc", s.startAdHoc)
}

// ---------- manual entry ----------

// manualService is one service entered by hand.
type manualService struct {
	Port         int                `json:"port"`
	Proto        string             `json:"proto"`
	State        string             `json:"state"`
	Name         string             `json:"name"`
	Product      string             `json:"product"`
	Version      string             `json:"version"`
	Banner       string             `json:"banner"`
	TLS          bool               `json:"tls"`
	Title        string             `json:"title"`
	URL          string             `json:"url"`
	HTTPStatus   int                `json:"http_status"`
	Technologies []model.Technology `json:"technologies"`
}

// manualHost is a host entered by hand, with optional services.
type manualHost struct {
	IP         string          `json:"ip"`
	Hostnames  []string        `json:"hostnames"`
	Up         *bool           `json:"up"` // default true
	OSGuess    string          `json:"os_guess"`
	MAC        string          `json:"mac"`
	ObservedAt *time.Time      `json:"observed_at"`
	Services   []manualService `json:"services"`
}

// ManualEntryResult is the answer of the manual entry routes.
type ManualEntryResult struct {
	Run  model.ScanRun `json:"run"`
	Host model.Host    `json:"host"`
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func (ms manualService) result() (model.ServiceResult, error) {
	sv := model.ServiceResult{Port: ms.Port, Proto: strings.ToLower(strings.TrimSpace(ms.Proto)), State: strings.ToLower(strings.TrimSpace(ms.State)),
		Name: clip(ms.Name, 100), Product: clip(ms.Product, 200), Version: clip(ms.Version, 100), Banner: clip(ms.Banner, 2000),
		Confidence: 1, Technologies: ms.Technologies}
	if sv.Port < 1 || sv.Port > 65535 {
		return sv, invalid("port %d must be between 1 and 65535", ms.Port)
	}
	switch sv.Proto {
	case "":
		sv.Proto = "tcp"
	case "tcp", "udp":
	default:
		return sv, invalid("proto must be tcp or udp")
	}
	switch sv.State {
	case "":
		sv.State = "open"
	case "open", "filtered", "closed":
	default:
		return sv, invalid("state must be open, filtered or closed")
	}
	if ms.TLS {
		sv.Tunnel = "ssl"
	}
	if ms.Title != "" || ms.URL != "" || ms.HTTPStatus != 0 {
		h := &model.HTTPFingerprint{Title: clip(ms.Title, 500), URL: clip(ms.URL, 2000), Status: ms.HTTPStatus, Scheme: "http"}
		if ms.TLS || strings.HasPrefix(strings.ToLower(h.URL), "https://") {
			h.Scheme = "https"
		}
		sv.HTTP = h
	}
	return sv, nil
}

func (mh manualHost) result() (model.HostResult, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(mh.IP))
	if err != nil {
		return model.HostResult{}, invalid("ip %q is not an IP address", mh.IP)
	}
	h := model.HostResult{IP: a.Unmap().String(), Up: true, Reason: "manual", OSGuess: clip(mh.OSGuess, 200), MAC: clip(mh.MAC, 40), Attempts: 1}
	if mh.Up != nil {
		h.Up = *mh.Up
	}
	if mh.ObservedAt != nil {
		h.ObservedAt = mh.ObservedAt.UTC()
	}
	for _, n := range mh.Hostnames {
		if n = clip(n, 253); n != "" {
			h.Hostnames = append(h.Hostnames, strings.ToLower(n))
		}
	}
	if len(mh.Services) > 1000 {
		return h, invalid("at most 1000 services per host")
	}
	for _, ms := range mh.Services {
		sv, err := ms.result()
		if err != nil {
			return h, err
		}
		h.Services = append(h.Services, sv)
	}
	if !h.Up && len(h.Services) > 0 {
		return h, invalid("a host entered as down cannot have services")
	}
	return h, nil
}

// ingestManual sends hand-entered host results through the run manager (the
// same sink and analysis as a scan) and returns the run and the stored host.
func (s *Server) ingestManual(w http.ResponseWriter, r *http.Request, h model.HostResult) {
	if s.d.Runner == nil {
		notWired(w, "the run manager")
		return
	}
	run, err := s.d.Runner.Ingest(r.Context(), runner.TriggerManualEntry, "", []model.HostResult{h}, userID(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := s.st.HostIDsByIP(r.Context(), []string{h.IP})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	host, err := s.st.GetHost(r.Context(), ids[h.IP])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "host", host.ID, map[string]any{"ip": h.IP, "services": len(h.Services), "run_id": run.ID})
	writeJSON(w, http.StatusCreated, ManualEntryResult{Run: run, Host: host})
}

func (s *Server) createHostManual(w http.ResponseWriter, r *http.Request) {
	var in manualHost
	if !decode(w, r, &in) {
		return
	}
	auditSet(r, "host.create", "host", nil, map[string]any{"ip": in.IP})
	h, err := in.result()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ingestManual(w, r, h)
}

func (s *Server) addServicesManual(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	auditSet(r, "service.create", "host", id, nil)
	host, err := s.st.GetHost(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		manualService
		Services []manualService `json:"services"`
	}
	if !decode(w, r, &in) {
		return
	}
	list := in.Services
	if in.Port != 0 {
		list = append(list, in.manualService)
	}
	if len(list) == 0 {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "give one service (port, proto, ...) or a list in services")
		return
	}
	mh := manualHost{IP: host.IP, Hostnames: host.Hostnames, Services: list}
	h, err := mh.result()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ingestManual(w, r, h)
}

// ---------- findings files ----------

// FindingsImportResult is the answer of POST /import/findings.
type FindingsImportResult struct {
	interchange.FindingsReport
	Created      int    `json:"created"`
	Updated      int    `json:"updated"`
	HostsCreated int    `json:"hosts_created"` // hosts that the file named and the inventory did not know (manual-entry run)
	RunID        *int64 `json:"run_id"`
}

func findingProto(key string) string {
	if strings.Contains(key, "/udp-") {
		return "udp"
	}
	return "tcp"
}

func (s *Server) importFindings(w http.ResponseWriter, r *http.Request) {
	auditSet(r, "finding.import", "finding", nil, nil)
	name, data, ok := readUpload(w, r, 64<<20)
	if !ok {
		return
	}
	findings, rep, err := interchange.ImportFindings(bytes.NewReader(data), interchange.FindingsOptions{Format: r.FormValue("format"), Source: r.FormValue("source")})
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "the file could not be read: "+err.Error())
		return
	}
	out := FindingsImportResult{FindingsReport: rep}
	if out.Invalid == nil {
		out.Invalid = []model.InvalidLine{}
	}
	ctx := r.Context()
	ips := make([]string, 0, len(findings))
	for i := range findings {
		if a, err := netip.ParseAddr(strings.TrimSpace(findings[i].IP)); err == nil {
			findings[i].IP = a.Unmap().String()
			ips = append(ips, findings[i].IP)
		}
	}
	known, err := s.st.HostIDsByIP(ctx, ips)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// A host that the file names and the inventory does not know is entered by
	// hand (one manual-entry run), so every finding has a host and the host
	// takes the normal ingest and analysis.
	newHosts := map[string]*model.HostResult{}
	var order []string
	for _, f := range findings {
		if f.IP == "" || known[f.IP] != 0 {
			continue
		}
		h := newHosts[f.IP]
		if h == nil {
			h = &model.HostResult{IP: f.IP, Up: true, Reason: "manual", Attempts: 1}
			newHosts[f.IP] = h
			order = append(order, f.IP)
		}
		if f.Port > 0 && f.Port <= 65535 {
			dup := false
			for _, sv := range h.Services {
				dup = dup || (sv.Port == f.Port && sv.Proto == findingProto(f.Key))
			}
			if !dup {
				h.Services = append(h.Services, model.ServiceResult{Port: f.Port, Proto: findingProto(f.Key), State: "open"})
			}
		}
	}
	if len(order) > 0 && s.d.Runner != nil {
		sort.Strings(order)
		hosts := make([]model.HostResult, 0, len(order))
		for _, ip := range order {
			hosts = append(hosts, *newHosts[ip])
		}
		run, err := s.d.Runner.Ingest(ctx, runner.TriggerManualEntry, name, hosts, userID(r))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out.RunID, out.HostsCreated = &run.ID, len(hosts)
		if known, err = s.st.HostIDsByIP(ctx, ips); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	hostIDs := make([]int64, 0, len(known))
	for _, id := range known {
		hostIDs = append(hostIDs, id)
	}
	svcs, err := s.st.ServiceIDsOf(ctx, hostIDs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	kept := findings[:0]
	for i, f := range findings {
		f.HostID = known[f.IP]
		if f.HostID == 0 {
			out.Skipped++
			if len(out.Invalid) < interchange.MaxInvalidReported {
				out.Invalid = append(out.Invalid, model.InvalidLine{Line: i + 1, Value: f.Title, Reason: "obserwacja bez adresu hosta: nie można jej przypisać do inwentarza"})
			}
			continue
		}
		if f.Port > 0 {
			if id, ok := svcs[f.HostID][store.ServiceKey(f.Port, findingProto(f.Key))]; ok {
				f.ServiceID = &id
			}
		}
		kept = append(kept, f)
	}
	out.Findings = len(kept)
	if out.Created, out.Updated, err = s.st.ImportFindings(ctx, kept); err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", nil, map[string]any{"file": name, "format": out.Format, "created": out.Created, "updated": out.Updated, "skipped": out.Skipped})
	writeJSON(w, http.StatusCreated, out)
}

// maxFindingsExport caps one findings file.
const maxFindingsExport = 100000

func (s *Server) exportFindingsDojo(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := query(r)
		f := findingFilter(q)
		if !q.ok(w) {
			return
		}
		var list []model.Finding
		err := s.st.EachFinding(r.Context(), f, func(x *model.Finding) error {
			if len(list) < maxFindingsExport {
				list = append(list, *x)
			}
			return nil
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		name := "czujka-findings-dojo." + format
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		auditSet(r, "finding.export.file", "finding", nil, map[string]any{"format": "dojo-" + format, "findings": len(list)})
		if format == "csv" {
			err = interchange.WriteDojoGenericCSV(w, list)
		} else {
			err = interchange.WriteDojoGenericJSON(w, list)
		}
		if err != nil {
			s.log.Error("findings export", "err", err)
		}
	}
}

// ---------- DefectDojo status sync ----------

func (s *Server) dojoSettings(w http.ResponseWriter, r *http.Request) (model.DefectDojoSettings, bool) {
	if s.d.Dojo == nil {
		notWired(w, "the DefectDojo client")
		return model.DefectDojoSettings{}, false
	}
	d, err := s.st.GetDefectDojo(r.Context(), true)
	if err != nil {
		s.fail(w, r, err)
		return d, false
	}
	if d.URL == "" || d.APIKey == "" {
		writeErr(w, http.StatusConflict, "not_configured", "DefectDojo nie jest skonfigurowane: ustaw adres i klucz API w /settings/defectdojo")
		return d, false
	}
	return d, true
}

func (s *Server) dojoPull(w http.ResponseWriter, r *http.Request) {
	apply := query(r).boolean("apply")
	auditSet(r, "finding.pull.defectdojo", "finding", nil, map[string]any{"apply": apply != nil && *apply})
	d, ok := s.dojoSettings(w, r)
	if !ok {
		return
	}
	out, err := s.d.Dojo.PullStatus(r.Context(), d, apply != nil && *apply)
	if err != nil {
		writeErrDetails(w, http.StatusBadGateway, "defectdojo", "DefectDojo: "+err.Error(), out)
		return
	}
	auditSet(r, "", "", nil, map[string]any{"checked": out.Checked, "updates": len(out.Updates), "applied": out.Applied, "conflicts": len(out.Conflicts)})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) dojoSync(w http.ResponseWriter, r *http.Request) {
	auditSet(r, "finding.sync.defectdojo", "finding", nil, nil)
	d, ok := s.dojoSettings(w, r)
	if !ok {
		return
	}
	out, err := s.d.Dojo.SyncLifecycle(r.Context(), d)
	if err != nil {
		writeErrDetails(w, http.StatusBadGateway, "defectdojo", "DefectDojo: "+err.Error(), out)
		return
	}
	auditSet(r, "", "", nil, map[string]any{"closed": out.Closed, "reopened": out.Reopened, "skipped": out.Skipped})
	writeJSON(w, http.StatusOK, out)
}

// ---------- runs: note, label, ad-hoc ----------

func (s *Server) patchRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	run, err := s.st.GetRun(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Note  *string `json:"note"`
		Label *string `json:"label"`
	}
	if !decode(w, r, &in) {
		return
	}
	note, label := run.Note, run.Label
	if in.Note != nil {
		note = strings.TrimSpace(*in.Note)
	}
	if in.Label != nil {
		label = strings.TrimSpace(*in.Label)
	}
	if len(note) > 4000 || len(label) > 100 || strings.ContainsAny(label, "\r\n") {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "note is at most 4000 characters, label one line of at most 100")
		return
	}
	run, err = s.st.SetRunNote(r.Context(), id, note, label)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "run.update", "run", id, map[string]any{"label": label, "note_set": note != ""})
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) startAdHoc(w http.ResponseWriter, r *http.Request) {
	var in model.AdHocScope
	if !decode(w, r, &in) {
		return
	}
	auditSet(r, "run.start", "run", nil, map[string]any{"adhoc": true, "addresses": len(in.Addresses), "ports": in.Ports, "profile_id": in.ProfileID})
	if s.d.Runner == nil {
		notWired(w, "the run manager")
		return
	}
	in.Reason = clip(in.Reason, 500)
	run, err := s.d.Runner.StartAdHoc(r.Context(), in, userID(r), runner.TriggerReprobe)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", run.ID, nil)
	writeJSON(w, http.StatusCreated, run)
}

// ---------- import into a scope ----------

// coveredBy reports whether a target of the list contains the address.
func coveredBy(a netip.Addr, targets []model.Target) bool {
	for _, t := range targets {
		switch t.Kind {
		case model.TargetIP:
			if b, err := netip.ParseAddr(t.Value); err == nil && b.Unmap() == a {
				return true
			}
		case model.TargetCIDR:
			if p, err := netip.ParsePrefix(t.Value); err == nil && p.Contains(a) {
				return true
			}
		case model.TargetRange:
			x, y, _ := strings.Cut(t.Value, "-")
			from, e1 := netip.ParseAddr(x)
			to, e2 := netip.ParseAddr(y)
			if e1 == nil && e2 == nil && a.Compare(from) >= 0 && a.Compare(to) <= 0 {
				return true
			}
		}
	}
	return false
}

// addImportToScope adds the answering hosts of an import that the scope does
// not cover yet as IP targets of the scope (source "import"), so the import
// and every later scan see them in that scope. Targets outside the allowed
// networks of the policy are refused like any other entry.
func (s *Server) addImportToScope(r *http.Request, scopeID int64, hosts []model.HostResult) (added int, invalidLines []model.InvalidLine, err error) {
	existing, err := s.st.EnabledTargets(r.Context(), []int64{scopeID})
	if err != nil {
		return 0, nil, err
	}
	var valid []model.Target
	for _, h := range hosts {
		a, err := netip.ParseAddr(strings.TrimSpace(h.IP))
		if err != nil || !h.Up || coveredBy(a.Unmap(), existing) {
			continue
		}
		t, err := ParseTarget(a.Unmap().String())
		if err != nil {
			continue
		}
		t.Source, t.Tags = "import", []string{"import"}
		valid = append(valid, t)
	}
	if len(valid) == 0 {
		return 0, nil, nil
	}
	p, err := s.preview(r, valid, nil)
	if err != nil {
		return 0, nil, err
	}
	saved, _, err := s.st.AddTargets(r.Context(), scopeID, p.Valid, userID(r))
	return len(saved), p.Invalid, err
}

func parseScopeID(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return 0, invalid("scope_id must be a positive number")
	}
	return id, nil
}

// interchangeExporter writes run results through internal/interchange when no
// Exporter is wired: every run export uses the one interchange dialect.
type interchangeExporter struct{}

func (interchangeExporter) RunWriter(w io.Writer, format string, run model.ScanRun) (ResultWriter, error) {
	f := map[string]string{"xml": interchange.FormatNmapXML, "json": interchange.FormatJSON, "csv": interchange.FormatCSV}[format]
	if f == "" {
		return nil, fmt.Errorf("unknown export format %q", format)
	}
	meta := interchange.Meta{RunID: run.ID, Args: fmt.Sprintf("czujka run %d (%s)", run.ID, run.ProfileName), GeneratedAt: time.Now().UTC()}
	if run.FinishedAt != nil {
		meta.GeneratedAt = *run.FinishedAt
	}
	return interchange.NewWriter(w, f, meta)
}
