package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// ---------- filters (shared by the list and the export endpoints) ----------

func hostFilter(q *params) store.HostFilter {
	return store.HostFilter{ListOpts: q.opts(), Status: q.list("status"), Tag: q.str("tag"), ScopeID: q.int64("scope_id"), CIDR: q.cidr("cidr"),
		Tech: q.str("tech"), Port: q.int("port"), MinInterest: q.int("min_interest"), Unstable: q.boolean("unstable")}
}

func serviceFilter(q *params) store.ServiceFilter {
	return store.ServiceFilter{ListOpts: q.opts(), HostID: q.int64("host_id"), Port: q.int("port"), State: q.list("state"), Name: q.str("name"),
		Tech: q.str("tech"), Class: q.str("class"), Tag: q.str("tag"), GroupKey: q.str("group_key"), MinInterest: q.int("min_interest"),
		TLS: q.boolean("tls"), RunID: q.int64("run_id"), CertWithin: q.int("cert_within_days")}
}

func changeFilter(q *params) store.ChangeFilter {
	return store.ChangeFilter{ListOpts: q.opts(), RunID: q.int64("run_id"), Kind: q.list("kind"), Severity: q.list("severity"), HostID: q.int64("host_id"),
		Acked: q.boolean("acked"), Expected: q.boolean("expected"), From: q.time("from"), To: q.time("to")}
}

func findingFilter(q *params) store.FindingFilter {
	return store.FindingFilter{ListOpts: q.opts(), Status: q.list("status"), Severity: q.list("severity"), Type: q.str("type"), HostID: q.int64("host_id"),
		ServiceID: q.int64("service_id"), Tag: q.str("tag"), MinInterest: q.int("min_interest"), Exported: q.boolean("exported")}
}

func signatureFilter(q *params) store.SignatureFilter {
	return store.SignatureFilter{ListOpts: q.opts(), Category: q.str("category"), Enabled: q.boolean("enabled"), Builtin: q.boolean("builtin"), Tag: q.str("tag")}
}

// ---------- hosts ----------

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	f := hostFilter(q)
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListHosts(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	h, err := s.st.GetHost(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func patchKeys(p map[string]json.RawMessage) []string {
	out := make([]string, 0, len(p))
	for k := range p {
		out = append(out, k)
	}
	return out
}

func (s *Server) patchHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var patch map[string]json.RawMessage
	if !decode(w, r, &patch) {
		return
	}
	auditSet(r, "", "", nil, map[string]any{"fields": patchKeys(patch)})
	h, err := s.st.PatchHost(r.Context(), id, patch, userEmail(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteHost(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) hostServices(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.st.GetHost(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	svcs, err := s.st.HostServices(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, svcs)
}

func (s *Server) hostAvailability(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.st.Availability(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p.Recent == nil {
		p.Recent = []model.HostObservation{}
	}
	if s.d.Analyzer != nil {
		p.DownAfterMisses = s.d.Analyzer.DownAfterMisses(p)
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) hostChanges(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := query(r)
	f := changeFilter(q)
	f.HostID = id
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListChanges(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// ---------- services ----------

// redactCookies removes raw cookie values. Only users with results:update may see them.
func redactCookies(res *model.ServiceResult) {
	if res == nil || res.HTTP == nil {
		return
	}
	for i := range res.HTTP.Cookies {
		res.HTTP.Cookies[i].Value = ""
	}
}

func canSeeCookies(r *http.Request) bool { return principal(r).Can(model.PermResultsUpdate) }

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	f := serviceFilter(q)
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListServices(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, err := s.st.GetService(r.Context(), id, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if v.Latest != nil && !canSeeCookies(r) {
		redactCookies(&v.Latest.Result)
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) patchService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var patch map[string]json.RawMessage
	if !decode(w, r, &patch) {
		return
	}
	auditSet(r, "", "", nil, map[string]any{"fields": patchKeys(patch)})
	v, err := s.st.PatchService(r.Context(), id, patch, userEmail(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteService(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listObservations(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := query(r)
	o := q.opts()
	if !q.ok(w) {
		return
	}
	if _, err := s.st.GetService(r.Context(), id, false); err != nil {
		s.fail(w, r, err)
		return
	}
	page, err := s.st.ListObservations(r.Context(), id, o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !canSeeCookies(r) {
		for i := range page.Items {
			redactCookies(&page.Items[i].Result)
		}
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) listServiceGroups(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	o := q.opts()
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListServiceGroups(r.Context(), o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) listTechnologies(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.TechnologyCounts(r.Context(), 0)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listTags(w http.ResponseWriter, r *http.Request) {
	out, err := s.st.TagCounts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.st.Dashboard(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// ---------- changes ----------

func (s *Server) listChanges(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	f := changeFilter(q)
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListChanges(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) ackChange(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.st.GetChange(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.st.AckChanges(r.Context(), []int64{id}, userEmail(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.st.GetChange(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) ackChanges(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []int64 `json:"ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.IDs) == 0 {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "ids is required")
		return
	}
	n, err := s.st.AckChanges(r.Context(), in.IDs, userEmail(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", nil, map[string]any{"ids": len(in.IDs), "acked": n})
	writeJSON(w, http.StatusOK, map[string]int{"acked": n})
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	from, to := q.int64("from"), q.int64("to")
	if !q.ok(w) {
		return
	}
	if from <= 0 || to <= 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "from and to must be run ids")
		return
	}
	for _, id := range []int64{from, to} {
		if _, err := s.st.GetRun(r.Context(), id); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if s.d.Analyzer == nil {
		notWired(w, "the diff of two runs (internal/analyze)")
		return
	}
	rep, err := s.d.Analyzer.Diff(r.Context(), from, to)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rep.Changes == nil {
		rep.Changes = []model.Change{}
	}
	writeJSON(w, http.StatusOK, rep)
}

// ---------- findings ----------

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	f := findingFilter(q)
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListFindings(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	f, err := s.st.GetFinding(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) createFinding(w http.ResponseWriter, r *http.Request) {
	var in model.Finding
	if !decode(w, r, &in) {
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "title is required")
		return
	}
	if in.HostID == 0 && in.IP != "" {
		page, err := s.st.ListHosts(r.Context(), store.HostFilter{CIDR: in.IP, ListOpts: store.ListOpts{Limit: 1}})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if len(page.Items) == 1 {
			in.HostID = page.Items[0].ID
		}
	}
	host, err := s.st.GetHost(r.Context(), in.HostID)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "host_id (or the ip of a known host) is required")
		return
	}
	in.IP = host.IP
	if in.ServiceID != nil {
		svc, err := s.st.GetService(r.Context(), *in.ServiceID, false)
		if err != nil || svc.HostID != host.ID {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "service_id is not a service of this host")
			return
		}
		in.Port = svc.Port
	}
	switch in.Severity {
	case "":
		in.Severity = model.SevInfo
	case model.SevInfo, model.SevLow, model.SevMedium, model.SevHigh:
	default:
		writeErr(w, http.StatusUnprocessableEntity, "validation", "severity must be info, low, medium or high")
		return
	}
	switch in.Status {
	case "":
		in.Status = model.FindingNew
	case model.FindingNew, model.FindingTriaged, model.FindingAccepted, model.FindingFalsePositive, model.FindingResolved:
	default:
		writeErr(w, http.StatusUnprocessableEntity, "validation", "unknown status")
		return
	}
	if in.Interest < 0 || in.Interest > 100 {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "interest must be between 0 and 100")
		return
	}
	if in.Type == "" {
		in.Type = "manual"
	}
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	in.Key = fmt.Sprintf("manual|%s|%d|%s", host.IP, in.Port, hex.EncodeToString(rnd))
	f, err := s.st.CreateManualFinding(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", f.ID, map[string]any{"title": f.Title, "ip": f.IP})
	writeJSON(w, http.StatusCreated, f)
}

func (s *Server) patchFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var patch map[string]json.RawMessage
	if !decode(w, r, &patch) {
		return
	}
	auditSet(r, "", "", nil, map[string]any{"fields": patchKeys(patch)})
	if st, ok := patch["status"]; ok {
		auditSet(r, "", "", nil, map[string]any{"status": strings.Trim(string(st), `"`)})
	}
	f, err := s.st.PatchFinding(r.Context(), id, patch, userEmail(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) deleteFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteFinding(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const maxDojoExport = 5000

func (s *Server) exportDojo(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs    []int64 `json:"ids"`
		Filter *struct {
			Status      []string `json:"status"`
			Severity    []string `json:"severity"`
			Type        string   `json:"type"`
			HostID      int64    `json:"host_id"`
			Tag         string   `json:"tag"`
			MinInterest int      `json:"min_interest"`
			Exported    *bool    `json:"exported"`
			Q           string   `json:"q"`
		} `json:"filter"`
	}
	if !decode(w, r, &in) {
		return
	}
	auditSet(r, "finding.export.defectdojo", "finding", nil, nil)
	if len(in.IDs) == 0 && in.Filter == nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "send ids or filter")
		return
	}
	if s.d.Dojo == nil {
		notWired(w, "the DefectDojo client (internal/defectdojo)")
		return
	}
	settings, err := s.st.GetDefectDojo(r.Context(), true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !settings.Enabled || settings.URL == "" || settings.APIKey == "" {
		writeErr(w, http.StatusConflict, "conflict", "DefectDojo is not configured: set the URL and the API key and enable the integration")
		return
	}
	f := store.FindingFilter{IDs: in.IDs, ListOpts: store.ListOpts{Limit: 1000}}
	if in.Filter != nil {
		f.Status, f.Severity, f.Type, f.HostID, f.Tag, f.MinInterest, f.Exported, f.Q = in.Filter.Status, in.Filter.Severity, in.Filter.Type,
			in.Filter.HostID, in.Filter.Tag, in.Filter.MinInterest, in.Filter.Exported, in.Filter.Q
	}
	var findings []model.Finding
	err = s.st.EachFinding(r.Context(), f, func(x *model.Finding) error {
		if len(findings) >= maxDojoExport {
			return invalid("more than %d findings match; narrow the filter", maxDojoExport)
		}
		findings = append(findings, *x)
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, links, err := s.d.Dojo.Export(r.Context(), settings, findings)
	for _, l := range links {
		if e := s.st.SetFindingDojo(r.Context(), l.FindingID, l.DojoID, l.URL); e != nil {
			s.log.Error("store DefectDojo link", "finding", l.FindingID, "err", e)
		}
	}
	if res.Errors == nil {
		res.Errors = []string{}
	}
	auditSet(r, "", "", nil, map[string]any{"selected": len(findings), "exported": res.Exported, "updated": res.Updated, "failed": res.Failed})
	if err != nil {
		writeErrDetails(w, http.StatusBadGateway, "internal", "DefectDojo export failed: "+err.Error(), res)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
