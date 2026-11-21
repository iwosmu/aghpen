package wire

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/defectdojo"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
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

// Export sends findings and returns where each one lives in DefectDojo.
func (d Dojo) Export(ctx context.Context, s model.DefectDojoSettings, findings []model.Finding) (model.DojoExportResult, []api.DojoLink, error) {
	c, err := client(s)
	if err != nil {
		return model.DojoExportResult{}, nil, err
	}
	out, err := c.ExportFindings(ctx, defectdojo.TargetFromSettings(s), findings)
	var links []api.DojoLink
	for _, f := range findings {
		if ref, ok := out.Findings[f.Key]; ok && ref.ID != 0 {
			links = append(links, api.DojoLink{FindingID: f.ID, DojoID: ref.ID, URL: ref.URL})
		}
	}
	return out.Result, links, err
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

// AutoExport sends the findings that a run saw to DefectDojo when the
// integration is enabled with auto_export. It never fails the run: the result
// goes to the log and to the audit log.
func (d Dojo) AutoExport(ctx context.Context, runID int64) {
	s, err := d.st.GetDefectDojo(ctx, true)
	if err != nil || !s.Enabled || !s.AutoExport || s.URL == "" || s.APIKey == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
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
