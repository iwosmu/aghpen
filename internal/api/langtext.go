package api

import (
	"net/http"
	"strings"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/i18n"
	"github.com/iwosmu/aghpen/internal/model"
)

// Lang is the language of the texts the server writes for this request:
// "en" or "pl" (reqLang). Sub-routers use it.
func Lang(r *http.Request) string { return reqLang(r) }

// ResponseLang is the language contentLanguage chose for the response w is
// writing: "en" or "pl".
func ResponseLang(w http.ResponseWriter) string {
	if w.Header().Get("Content-Language") == "en" {
		return "en"
	}
	return "pl"
}

// contentLanguage sets Content-Language on every API response to the
// language of the request (reqLang). writeJSON renders the server's texts in
// it. Files that leave Czujka keep Polish unless ?lang= asks otherwise: the
// exports and the run reports read only the query parameter, and the
// DefectDojo export always keeps its language.
func (s *Server) contentLanguage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Vary", "Accept-Language")
		h.Set("Content-Language", respLang(r))
		next.ServeHTTP(w, r)
	})
}

func respLang(r *http.Request) string {
	p := r.URL.Path
	switch {
	case strings.Contains(p, ".dojo."), strings.Contains(p, "/defectdojo"):
		return "pl"
	case strings.Contains(p, "/export/"), strings.Contains(p, "/report."):
		if strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang"))) == "en" {
			return "en"
		}
		return "pl"
	}
	return reqLang(r)
}

// localizeResponse renders the texts of a response value in the language of
// the response. Polish values pass unchanged: the store holds Polish. The
// value is changed in place; every handler builds it for this request.
func localizeResponse(w http.ResponseWriter, v any) any {
	if ResponseLang(w) != "en" {
		return v
	}
	const en = "en"
	switch x := v.(type) {
	case map[string]apiError:
		if e, ok := x["error"]; ok {
			e.Message = ErrorMessageIn(e.Message, en)
			x["error"] = e
		}
	case model.Finding:
		return analyze.RenderFinding(x, en)
	case *model.Finding:
		*x = analyze.RenderFinding(*x, en)
	case []model.Finding:
		analyze.LocalizeFindings(x, en)
	case model.Page[model.Finding]:
		analyze.LocalizeFindings(x.Items, en)
	case model.Service:
		localizeService(&x)
		return x
	case *model.Service:
		localizeService(x)
	case []model.Service:
		localizeServices(x)
	case model.Page[model.Service]:
		localizeServices(x.Items)
	case model.Dashboard:
		localizeDashboard(&x)
		return x
	case *model.Dashboard:
		localizeDashboard(x)
	case model.ScanRun:
		localizeRun(&x)
		return x
	case *model.ScanRun:
		localizeRun(x)
	case []model.ScanRun:
		for i := range x {
			localizeRun(&x[i])
		}
	case model.Page[model.ScanRun]:
		for i := range x.Items {
			localizeRun(&x.Items[i])
		}
	case model.ScanProfile:
		localizeProfile(&x)
		return x
	case *model.ScanProfile:
		localizeProfile(x)
	case []model.ScanProfile:
		for i := range x {
			localizeProfile(&x[i])
		}
	case model.Page[model.ScanProfile]:
		for i := range x.Items {
			localizeProfile(&x.Items[i])
		}
	case model.Role:
		localizeRole(&x)
		return x
	case []model.Role:
		for i := range x {
			localizeRole(&x[i])
		}
	case model.Page[model.Role]:
		for i := range x.Items {
			localizeRole(&x.Items[i])
		}
	case PassiveResult:
		for i := range x.Candidates {
			x.Candidates[i].Reason = i18n.Text(x.Candidates[i].Reason, en)
		}
		return x
	case model.RetroHuntResult:
		for i := range x.Notes {
			x.Notes[i] = i18n.Text(x.Notes[i], en)
		}
		return x
	case *model.RetroHuntResult:
		for i := range x.Notes {
			x.Notes[i] = i18n.Text(x.Notes[i], en)
		}
	case model.Signature:
		localizeSignature(&x)
		return x
	case *model.Signature:
		localizeSignature(x)
	case []model.Signature:
		for i := range x {
			localizeSignature(&x[i])
		}
	case model.Page[model.Signature]:
		for i := range x.Items {
			localizeSignature(&x.Items[i])
		}
	}
	return v
}

func localizeService(s *model.Service) {
	analyze.LocalizeReasons(s.InterestWhy, "en")
	for i := range s.Technologies {
		s.Technologies[i].Name = analyze.SignatureNameIn(s.Technologies[i].Name, "en")
	}
	if s.Latest != nil {
		localizeResult(&s.Latest.Result)
	}
}

func localizeServices(ss []model.Service) {
	for i := range ss {
		localizeService(&ss[i])
	}
}

// localizeResult renders the names of signature matches and technologies
// of one observation.
func localizeResult(res *model.ServiceResult) {
	for i := range res.Matches {
		res.Matches[i].Name = analyze.SignatureNameIn(res.Matches[i].Name, "en")
	}
	for i := range res.Technologies {
		res.Technologies[i].Name = analyze.SignatureNameIn(res.Technologies[i].Name, "en")
	}
}

func localizeDashboard(d *model.Dashboard) {
	analyze.LocalizeFindings(d.TopFindings, "en")
	localizeServices(d.TopServices)
	localizeServices(d.CertsExpiring)
	if d.LastRun != nil {
		localizeRun(d.LastRun)
	}
	if d.ActiveRun != nil {
		localizeRun(d.ActiveRun)
	}
}

// Stored names the server writes itself.
const (
	manualEntryProfilePL   = "wpis ręczny"
	defaultProfileNamePL   = "Domyślny"
	defaultProfileDescPL   = "Top 1000 portów, wybrane usługi UDP, rozpoznawanie usług, HTTP i TLS."
	manualEntryProfileEN   = "manual entry"
	defaultProfileNameEN   = "Default"
	defaultProfileDescEN   = "Top 1000 ports, selected UDP services, service detection, HTTP and TLS."
	triggerManualEntryName = "manual-entry"
)

func localizeRole(r *model.Role) {
	if r.Builtin {
		r.Name, r.Description = i18n.Text(r.Name, "en"), i18n.Text(r.Description, "en")
	}
}

func localizeRun(run *model.ScanRun) {
	for i, s := range run.Stats.Warnings {
		run.Stats.Warnings[i] = i18n.Text(s, "en")
	}
	for i, s := range run.Stats.Notes {
		run.Stats.Notes[i] = i18n.Text(s, "en")
	}
	if run.AdHoc != nil {
		run.AdHoc.Reason = i18n.Text(run.AdHoc.Reason, "en")
	}
	run.Error = i18n.ErrorMessage(run.Error, "en")
	if run.ProfileName == manualEntryProfilePL && run.Trigger == triggerManualEntryName {
		run.ProfileName = manualEntryProfileEN
	}
	if run.ProfileName == defaultProfileNamePL {
		run.ProfileName = defaultProfileNameEN
	}
}

// localizeProfile renders the name and description of the default profile
// while they are the ones a new installation got (store.DefaultProfile);
// a name an operator chose stays.
func localizeProfile(p *model.ScanProfile) {
	if p.Name == defaultProfileNamePL {
		p.Name = defaultProfileNameEN
	}
	if p.Description == defaultProfileDescPL {
		p.Description = defaultProfileDescEN
	}
}

func localizeSignature(g *model.Signature) {
	g.Name, g.Description = analyze.SignatureTextIn(g.Slug, g.Name, g.Description, g.Builtin, "en")
}
