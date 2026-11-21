package wire

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/passive"
	"github.com/iwosmu/aghpen/internal/report"
	"github.com/iwosmu/aghpen/internal/sigwire"
	"github.com/iwosmu/aghpen/internal/store"
)

// ---------- signature import ----------

// SigImporter is api.SignatureImporter over sigwire.Import.
type SigImporter struct{ sw *sigwire.Wire }

// ImportSignatures stores every valid signature of the text and reloads the engine.
func (s SigImporter) ImportSignatures(ctx context.Context, text, author string) (api.SignatureImportReport, error) {
	rep, err := s.sw.Import(ctx, text, author)
	out := api.SignatureImportReport{Created: rep.Created, Updated: rep.Updated, Skipped: []api.SignatureImportSkip{}, Validation: rep.Validation}
	for _, k := range rep.Skipped {
		out.Skipped = append(out.Skipped, api.SignatureImportSkip{Slug: k.Slug, Reason: k.Reason})
	}
	if out.Created == nil {
		out.Created = []string{}
	}
	if out.Updated == nil {
		out.Updated = []string{}
	}
	return out, err
}

// ---------- run report ----------

// Reporter is api.Reporter: it builds the report input of a run from the store.
type Reporter struct {
	st  *store.Store
	loc *time.Location
}

// RunReport writes the report of one run as "html" or "md".
func (r Reporter) RunReport(ctx context.Context, runID int64, format string, w io.Writer) error {
	in, err := r.Input(ctx, runID)
	if err != nil {
		return err
	}
	if format == "md" {
		_, err = io.WriteString(w, report.Markdown(in))
		return err
	}
	return report.WriteHTML(w, in)
}

// Input reads everything the report of a run shows.
func (r Reporter) Input(ctx context.Context, runID int64) (report.Input, error) {
	run, err := r.st.GetRun(ctx, runID)
	if err != nil {
		return report.Input{}, err
	}
	in := report.Input{Organization: "CBI AGH", GeneratedAt: time.Now(), Location: r.loc, Run: run}
	if run.Summary != nil {
		in.Summary = *run.Summary
		if run.Summary.PrevRunID != nil {
			if prev, err := r.st.GetRun(ctx, *run.Summary.PrevRunID); err == nil {
				in.PrevRun = &prev
			}
		}
	}
	if in.Summary.ByKind == nil {
		in.Summary.ByKind = map[string]int{}
	}
	if run.ProfileID != nil {
		if p, err := r.st.GetProfile(ctx, *run.ProfileID); err == nil {
			in.Profile = &p
			for _, id := range p.ScopeIDs {
				if sc, err := r.st.GetScope(ctx, id); err == nil {
					in.Scopes = append(in.Scopes, sc.Name)
				}
			}
		}
	}
	if in.Policy, err = r.st.GetSafetyPolicy(ctx); err != nil {
		return in, err
	}
	err = r.st.EachChange(ctx, store.ChangeFilter{RunID: runID}, func(c *model.Change) error {
		in.Changes = append(in.Changes, *c)
		return nil
	})
	if err != nil {
		return in, err
	}
	fp, err := r.st.ListFindings(ctx, store.FindingFilter{LastRunID: runID, ListOpts: store.ListOpts{Limit: 200, Sort: "-interest"}})
	if err != nil {
		return in, err
	}
	in.Findings = fp.Items
	sp, err := r.st.ListServices(ctx, store.ServiceFilter{RunID: runID, ListOpts: store.ListOpts{Limit: 100, Sort: "-interest"}})
	if err != nil {
		return in, err
	}
	in.Services = sp.Items
	hp, err := r.st.ListHosts(ctx, store.HostFilter{Status: []string{"unstable", "expected-offline", "down"}, ListOpts: store.ListOpts{Limit: 200}})
	if err != nil {
		return in, err
	}
	in.Hosts = hp.Items
	return in, nil
}

// ---------- passive sources ----------

// Passive is api.PassiveSources over internal/passive. The scope is every
// enabled target of every scope plus the live hosts of the inventory.
type Passive struct {
	st  *store.Store
	log *slog.Logger
}

func (p Passive) scope(ctx context.Context) (passive.Scope, error) {
	scopes, err := p.st.ListScopes(ctx, store.ListOpts{Limit: 1000})
	if err != nil {
		return passive.Scope{}, err
	}
	ids := make([]int64, 0, len(scopes.Items))
	for _, s := range scopes.Items {
		ids = append(ids, s.ID)
	}
	var ts []model.Target
	if len(ids) > 0 {
		if ts, err = p.st.EnabledTargets(ctx, ids); err != nil {
			return passive.Scope{}, err
		}
	}
	var known []string
	err = p.st.EachHost(ctx, store.HostFilter{Status: []string{"up", "unstable", "expected-offline"}}, func(h *model.Host) error {
		known = append(known, h.IP)
		return nil
	})
	if err != nil {
		return passive.Scope{}, err
	}
	return passive.ScopeFromTargets(ts, known), nil
}

func result(res passive.Result) api.PassiveResult {
	if res.Facts == nil {
		res.Facts = []passive.Fact{}
	}
	if res.OutOfScope == nil {
		res.OutOfScope = []passive.Fact{}
	}
	if res.Candidates == nil {
		res.Candidates = []passive.Candidate{}
	}
	if res.Hints == nil {
		res.Hints = []passive.Hint{}
	}
	if res.Sources == nil {
		res.Sources = []passive.SourceReport{}
	}
	return api.PassiveResult{Result: res}
}

// ImportFile reads a passive file (DNS zone, CSV, JSON, JSONL). Nothing is saved.
func (p Passive) ImportFile(ctx context.Context, name string, data []byte) (api.PassiveResult, error) {
	facts, frep, err := passive.Parse(bytes.NewReader(data), name)
	if err != nil {
		return api.PassiveResult{}, err
	}
	scope, err := p.scope(ctx)
	if err != nil {
		return api.PassiveResult{}, err
	}
	res := passive.Merge(scope, facts)
	res.Sources = []passive.SourceReport{{Name: "file:" + name, Facts: len(facts)}}
	out := result(res)
	out.File = &frep
	return out, nil
}

// PTR looks up the reverse names of the known live hosts through the system
// resolver and adds the names to those hosts.
func (p Passive) PTR(ctx context.Context) (api.PassiveResult, error) {
	scope, err := p.scope(ctx)
	if err != nil {
		return api.PassiveResult{}, err
	}
	out := result(passive.Collect(ctx, scope, passive.Options{}, &passive.PTRSource{}))
	for _, h := range out.Hints {
		if !h.Known || len(h.Hostnames) == 0 {
			continue
		}
		n, err := p.st.AddHostnames(ctx, h.IP, h.Hostnames)
		if err != nil {
			return out, fmt.Errorf("add hostnames of %s: %w", h.IP, err)
		}
		if n {
			out.HostsUpdated++
		}
	}
	return out, nil
}

// CT asks crt.sh for the certificates of the scope domains. It runs only
// when an administrator turned it on (PUT /settings/passive).
func (p Passive) CT(ctx context.Context) (api.PassiveResult, error) {
	set, err := p.st.GetPassiveSettings(ctx)
	if err != nil {
		return api.PassiveResult{}, err
	}
	if !set.CTEnabled {
		return api.PassiveResult{}, passive.ErrExternalDisabled
	}
	scope, err := p.scope(ctx)
	if err != nil {
		return api.PassiveResult{}, err
	}
	p.log.Warn("passive: asking crt.sh, an external service, for the scope domains", "domains", len(scope.Domains))
	return result(passive.Collect(ctx, scope, passive.Options{AllowExternal: true}, &passive.CTSource{Enabled: true})), nil
}
