package wire

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"encoding/json"
	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/defectdojo"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
	"strconv"
)

const userAgent = "Czujka/1.0 (DefectDojo export)"

// Dojo adapts internal/defectdojo to the API seam and adds the automatic export after a run.
type Dojo struct {
	st  *store.Store
	log *slog.Logger
}

func client(s model.DefectDojoSettings) (*defectdojo.Client, error) {
	cfg := defectdojo.FromSettings(s)
	cfg.UserAgent = userAgent
	return defectdojo.New(cfg)
}

// Test checks the URL and the token.
func (d Dojo) Test(ctx context.Context, s model.DefectDojoSettings) (ok bool, message, version string) {
	c, err := client(s)
	if err != nil {
		return false, err.Error(), ""
	}
	info, err := c.Test(ctx)
	if err != nil {
		return false, err.Error(), ""
	}
	return info.OK, info.Message, info.Version
}

func scopeMappings(s model.DefectDojoSettings) []defectdojo.ScopeMapping {
	out := make([]defectdojo.ScopeMapping, 0, len(s.ScopeMappings))
	for _, m := range s.ScopeMappings {
		out = append(out, defectdojo.ScopeMapping{ScopeID: m.ScopeID, ProductTypeName: m.ProductTypeName, ProductName: m.ProductName, EngagementName: m.EngagementName})
	}
	return out
}

// Export sends findings and returns where each one lives in DefectDojo. With
// per-scope mappings in the settings, the findings of a host in a mapped scope
// go to the product and engagement of that scope.
func (d Dojo) Export(ctx context.Context, s model.DefectDojoSettings, findings []model.Finding) (model.DojoExportResult, []api.DojoLink, error) {
	c, err := client(s)
	if err != nil {
		return model.DojoExportResult{}, nil, err
	}
	def := defectdojo.TargetFromSettings(s)
	groups := map[defectdojo.Target][]model.Finding{def: findings}
	if maps := scopeMappings(s); len(maps) > 0 && d.st != nil {
		ids := make([]int64, 0, len(findings))
		for _, f := range findings {
			ids = append(ids, f.HostID)
		}
		scopes, err := d.st.HostScopeIDs(ctx, ids)
		if err != nil {
			return model.DojoExportResult{}, nil, err
		}
		groups = defectdojo.GroupByTarget(findings, func(f model.Finding) []int64 { return scopes[f.HostID] }, maps, def)
	}
	var res model.DojoExportResult
	var links []api.DojoLink
	var firstErr error
	for t, part := range groups {
		out, err := c.ExportFindings(ctx, t, part)
		res.Exported += out.Result.Exported
		res.Updated += out.Result.Updated
		res.Failed += out.Result.Failed
		res.Errors = append(res.Errors, out.Result.Errors...)
		if res.TestID == 0 || t == def {
			res.TestID, res.TestURL = out.Result.TestID, out.Result.TestURL
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, f := range part {
			if ref, ok := out.Findings[f.Key]; ok && ref.ID != 0 {
				links = append(links, api.DojoLink{FindingID: f.ID, DojoID: ref.ID, URL: ref.URL})
			}
		}
	}
	if res.Errors == nil {
		res.Errors = []string{}
	}
	return res, links, firstErr
}

// exported returns the findings that were sent to DefectDojo (dojo_id set).
func (d Dojo) exported(ctx context.Context) ([]model.Finding, error) {
	yes := true
	var out []model.Finding
	err := d.st.EachFinding(ctx, store.FindingFilter{Exported: &yes}, func(f *model.Finding) error {
		if len(out) < 20000 {
			out = append(out, *f)
		}
		return nil
	})
	return out, err
}

// linkOrphans stores the DefectDojo id and link of findings that an export
// sent but did not confirm (defectdojo.UnconfirmedError): Czujka findings
// without dojo_id whose key DefectDojo holds. It returns how many it linked.
func (d Dojo) linkOrphans(ctx context.Context, c *defectdojo.Client, s model.DefectDojoSettings) (int, error) {
	no := false
	var unlinked []model.Finding
	err := d.st.EachFinding(ctx, store.FindingFilter{Exported: &no}, func(f *model.Finding) error {
		if len(unlinked) < 20000 {
			unlinked = append(unlinked, *f)
		}
		return nil
	})
	if err != nil || len(unlinked) == 0 {
		return 0, err
	}
	def := defectdojo.TargetFromSettings(s)
	groups := map[defectdojo.Target][]model.Finding{def: unlinked}
	if maps := scopeMappings(s); len(maps) > 0 {
		ids := make([]int64, 0, len(unlinked))
		for _, f := range unlinked {
			ids = append(ids, f.HostID)
		}
		scopes, err := d.st.HostScopeIDs(ctx, ids)
		if err != nil {
			return 0, err
		}
		groups = defectdojo.GroupByTarget(unlinked, func(f model.Finding) []int64 { return scopes[f.HostID] }, maps, def)
	}
	n := 0
	for t, part := range groups {
		keys := make([]string, 0, len(part))
		for _, f := range part {
			keys = append(keys, f.Key)
		}
		refs, err := c.LinkOrphans(ctx, t, keys)
		if err != nil {
			return n, err
		}
		for _, f := range part {
			if ref, ok := refs[f.Key]; ok {
				if err := d.st.SetFindingDojo(ctx, f.ID, ref.ID, ref.URL); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, nil
}

// PullStatus reads the DefectDojo state of every exported finding and
// proposes Czujka status updates (defectdojo.ProposeStatusUpdates). With
// apply it writes them as edits by "defectdojo" (the audit log and the status
// override record who changed what).
func (d Dojo) PullStatus(ctx context.Context, s model.DefectDojoSettings, apply bool) (api.DojoPull, error) {
	out := api.DojoPull{}
	c, err := client(s)
	if err != nil {
		return out, err
	}
	linked, err := d.linkOrphans(ctx, c, s)
	if err != nil {
		out.Errors = append(out.Errors, fmt.Sprintf("łączenie niepotwierdzonych eksportów: %v", err))
	}
	out.Linked = linked
	findings, err := d.exported(ctx)
	if err != nil {
		return out, err
	}
	local := make([]defectdojo.LocalStatus, 0, len(findings))
	for _, f := range findings {
		local = append(local, defectdojo.LocalStatus{Finding: f})
	}
	out.StatusPull, err = c.PullStatus(ctx, local)
	if err != nil || !apply {
		return out, err
	}
	for _, u := range out.Updates {
		patch := map[string]json.RawMessage{"status": json.RawMessage(strconv.Quote(string(u.To)))}
		if _, err := d.st.PatchFinding(ctx, u.FindingID, patch, "defectdojo"); err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("obserwacja #%d: %v", u.FindingID, err))
			continue
		}
		out.Applied++
	}
	return out, nil
}

// SyncLifecycle closes in DefectDojo the exported findings that Czujka
// resolved and reopens the ones that Czujka sees again.
func (d Dojo) SyncLifecycle(ctx context.Context, s model.DefectDojoSettings) (defectdojo.LifecycleResult, error) {
	c, err := client(s)
	if err != nil {
		return defectdojo.LifecycleResult{Errors: []string{}}, err
	}
	findings, err := d.exported(ctx)
	if err != nil {
		return defectdojo.LifecycleResult{Errors: []string{}}, err
	}
	return c.SyncLifecycle(ctx, findings, time.Now())
}

// UploadNmap uploads the nmap XML of one run as an "Nmap Scan" import.
func (d Dojo) UploadNmap(ctx context.Context, s model.DefectDojoSettings, title string, xml io.Reader, scanDate time.Time) (api.DojoUpload, error) {
	c, err := client(s)
	if err != nil {
		return api.DojoUpload{}, err
	}
	r, err := c.ImportNmapXML(ctx, defectdojo.TargetFromSettings(s), title, xml, scanDate)
	return api.DojoUpload{TestID: r.TestID, TestURL: r.TestURL, Reimport: r.Reimport, Created: r.Created, Closed: r.Closed,
		Reactivated: r.Reactivated, Untouched: r.Untouched, Total: r.Total}, err
}

// AutoExport is the DefectDojo step after an analysed run: with auto_export
// it sends the findings that the run saw; with status_sync it then closes
// resolved findings, reopens observed ones and pulls the status changes made
// in DefectDojo. It never fails the run: the result goes to the log and to
// the audit log.
func (d Dojo) AutoExport(ctx context.Context, runID int64) {
	s, err := d.st.GetDefectDojo(ctx, true)
	if err != nil || !s.Enabled || s.URL == "" || s.APIKey == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if s.AutoExport {
		d.autoExport(ctx, s, runID)
	}
	if s.StatusSync {
		d.statusSync(ctx, s, runID)
	}
}

func (d Dojo) statusSync(ctx context.Context, s model.DefectDojoSettings, runID int64) {
	lc, err := d.SyncLifecycle(ctx, s)
	detail := map[string]any{"run_id": runID, "closed": lc.Closed, "reopened": lc.Reopened, "errors": len(lc.Errors)}
	if err != nil {
		detail["error"] = err.Error()
	}
	pull, err := d.PullStatus(ctx, s, true)
	detail["checked"], detail["applied"], detail["conflicts"] = pull.Checked, pull.Applied, len(pull.Conflicts)
	if err != nil {
		detail["pull_error"] = err.Error()
	}
	d.log.Info("DefectDojo status sync", "run", runID, "closed", lc.Closed, "reopened", lc.Reopened, "applied", pull.Applied)
	_ = d.st.InsertAudit(ctx, model.AuditEntry{Action: "finding.sync.defectdojo", Entity: "finding", EntityID: fmt.Sprint(runID), UserEmail: "system", Detail: detail})
}

func (d Dojo) autoExport(ctx context.Context, s model.DefectDojoSettings, runID int64) {
	var err error
	var findings []model.Finding
	err = d.st.EachFinding(ctx, store.FindingFilter{LastRunID: runID, MinInterest: s.MinInterest,
		Status: []string{string(model.FindingNew), string(model.FindingTriaged), string(model.FindingAccepted)}}, func(f *model.Finding) error {
		if len(findings) < 5000 {
			findings = append(findings, *f)
		}
		return nil
	})
	if err != nil || len(findings) == 0 {
		return
	}
	res, links, err := d.Export(ctx, s, findings)
	for _, l := range links {
		if e := d.st.SetFindingDojo(ctx, l.FindingID, l.DojoID, l.URL); e != nil {
			d.log.Error("store DefectDojo link", "finding", l.FindingID, "err", e)
		}
	}
	detail := map[string]any{"run_id": runID, "selected": len(findings), "exported": res.Exported, "updated": res.Updated, "failed": res.Failed, "auto": true}
	if err != nil {
		detail["error"] = err.Error()
		d.log.Error("automatic DefectDojo export failed", "run", runID, "err", err)
	} else {
		d.log.Info("automatic DefectDojo export", "run", runID, "exported", res.Exported, "updated", res.Updated, "failed", res.Failed)
	}
	_ = d.st.InsertAudit(ctx, model.AuditEntry{Action: "finding.export.defectdojo", Entity: "finding", EntityID: fmt.Sprint(runID), UserEmail: "system", Detail: detail})
}
