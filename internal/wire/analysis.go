// Package wire connects the packages of Czujka: it holds the adapters between
// the pure libraries (internal/analyze, internal/interchange,
// internal/defectdojo) and the parts that own state (store, runner, API).
// cmd/czujka calls Build once at start.
package wire

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/analyze"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/probe"
	"github.com/iwosmu/aghpen/internal/rules"
	"github.com/iwosmu/aghpen/internal/store"
)

// maxGroupAll is the largest number of open services for which the grouping
// compares every service with every other one of its base group. Above it each
// service gets its own key from analyze.GroupKey.
const maxGroupAll = 60000

// AutoExporter sends the findings of a run to an external system after the analysis.
type AutoExporter interface {
	AutoExport(ctx context.Context, runID int64)
}

// Analysis runs internal/analyze over the data of the store. It is the
// runner's post-run hook (runner.Analyzer) and the API's diff seam (api.Analyzer).
type Analysis struct {
	st   *store.Store
	loc  *time.Location
	log  *slog.Logger
	Auto AutoExporter // optional

	// Policy evaluates the exposure rules after every analysis (runs, imports,
	// manual entries, re-probes); optional.
	Policy interface {
		Evaluate(ctx context.Context, runID int64) (rules.Report, error)
	}
}

// NewAnalysis returns the analysis adapter. loc is the timezone of the availability histogram.
func NewAnalysis(st *store.Store, loc *time.Location, log *slog.Logger) *Analysis {
	if loc == nil {
		loc = time.UTC
	}
	if log == nil {
		log = slog.Default()
	}
	return &Analysis{st: st, loc: loc, log: log}
}

func oldestFirst(obs []model.HostObservation) []model.HostObservation {
	out := append([]model.HostObservation(nil), obs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// portScope returns the ports that the profile really scans, resolved by the
// engine's own port resolver (probe.EffectivePorts: top-N lists, ranges, the
// allow and deny lists of the safety policy). A service on a port outside
// this set is never reported as gone. UDP ports count only when the profile
// names them explicitly. Nil means every port is in scope.
func (a *Analysis) portScope(ctx context.Context, p model.ScanProfile) func(proto string, port int) bool {
	policy, err := a.st.GetSafetyPolicy(ctx)
	if err != nil {
		policy = store.DefaultSafetyPolicy()
	}
	explicit, hasExplicit := ParsePorts(p.Ports)
	set, err := probe.EffectivePorts(p.Ports, policy.AllowedPorts, policy.DeniedPorts)
	if err != nil {
		if hasExplicit {
			return explicit
		}
		return nil
	}
	return func(proto string, port int) bool {
		if proto == "" || proto == "tcp" {
			return set.Has(port)
		}
		return hasExplicit && explicit(proto, port)
	}
}

// ParsePorts turns an explicit port list ("22,80,443,8000-8100", "T:80,U:53")
// into a membership test. ok is false for a spec that names no explicit
// ports, such as "top-100" or "-": the scope is then unknown.
func ParsePorts(spec string) (in func(proto string, port int) bool, ok bool) {
	type span struct {
		proto  string
		lo, hi int
	}
	var spans []span
	proto := ""
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if len(part) > 2 && part[1] == ':' {
			switch part[0] {
			case 'T', 't':
				proto = "tcp"
			case 'U', 'u':
				proto = "udp"
			default:
				return nil, false
			}
			part = part[2:]
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 || a > 65535 {
			return nil, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b > 65535 {
				return nil, false
			}
		}
		spans = append(spans, span{proto, a, b})
	}
	if len(spans) == 0 {
		return nil, false
	}
	return func(p string, port int) bool {
		if p == "" {
			p = "tcp"
		}
		for _, s := range spans {
			if port >= s.lo && port <= s.hi && (s.proto == "" || s.proto == p) {
				return true
			}
		}
		return false
	}, true
}

func statusOr(status string, up bool) model.HostStatus {
	if status != "" {
		return model.HostStatus(status)
	}
	if up {
		return model.HostUp
	}
	return model.HostUnstable
}

// AnalyzeRun is the post-run analysis (internal/analyze doc.go gives the
// order). It looks only at the hosts that the run probed: an address the run
// did not reach has no observation, so it is never a miss and never "gone".
// The function can run again for the same run (a resumed run, a restart): it
// reads the stored state and replaces the changes of the run.
func (a *Analysis) AnalyzeRun(ctx context.Context, runID int64) (*model.RunDiffSummary, error) {
	run, err := a.st.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sum := model.RunDiffSummary{ByKind: map[string]int{}}

	var hosts []store.RunHost
	if err := a.st.EachRunHost(ctx, runID, func(h *store.RunHost) error {
		hosts = append(hosts, *h)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := a.st.DeleteRunChanges(ctx, runID); err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return &sum, a.st.SetRunSummary(ctx, runID, sum)
	}
	ids := make([]int64, len(hosts))
	at := time.Time{}
	for i := range hosts {
		ids[i] = hosts[i].HostID
		if hosts[i].ObservedAt.After(at) {
			at = hosts[i].ObservedAt
		}
	}

	// The profile of the run gives the per-profile model rule
	// (retry.down_after_misses) and the ports the run probed.
	prof, hasProf := a.runProfile(ctx, run)
	var aopt analyze.AssessOptions
	if hasProf {
		aopt = analyze.OptionsFor(prof)
	}

	// 1. Stability model. The ingest already added the observation of this run
	// to the histogram and to the observation list; Assess reads that state.
	assess := make(map[int64]analyze.Assessment, len(hosts))
	nObs := make(map[int64]int, len(hosts))
	const batch = 500
	for lo := 0; lo < len(ids); lo += batch {
		part := ids[lo:min(lo+batch, len(ids))]
		buckets, err := a.st.AvailabilityBuckets(ctx, part)
		if err != nil {
			return nil, err
		}
		recent, err := a.st.HostObservations(ctx, part, analyze.RecentCap)
		if err != nil {
			return nil, err
		}
		for _, id := range part {
			p := analyze.Profile{Recent: oldestFirst(recent[id])}
			if b := buckets[id]; b != nil {
				p.Buckets = *b
				for _, c := range b {
					nObs[id] += c.Up + c.Down
				}
			}
			assess[id] = analyze.AssessWith(p, a.loc, aopt)
		}
	}

	// 2. Diff against what was known about each host before this run.
	prevHosts, err := a.st.PrevHosts(ctx, runID, ids)
	if err != nil {
		return nil, err
	}
	prevRun, err := a.st.PrevCompletedRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	pairs := map[int64]int64{}
	for id, p := range prevHosts {
		if p.RunID > prevRun && run.ProfileID == nil {
			prevRun = p.RunID
		}
		switch {
		case p.Up:
			pairs[id] = p.RunID
		case p.ServiceRun != 0:
			pairs[id] = p.ServiceRun // a silent host carries its last known services forward
		}
	}
	prevSvcs, _, err := a.st.RunServiceResults(ctx, pairs)
	if err != nil {
		return nil, err
	}
	cur := analyze.Snapshot{RunID: runID, At: at, Hosts: make([]analyze.HostSnapshot, 0, len(hosts))}
	var prev *analyze.Snapshot
	if len(prevHosts) > 0 || prevRun != 0 {
		if prevRun == 0 {
			for _, p := range prevHosts {
				prevRun = max(prevRun, p.RunID)
			}
		}
		prev = &analyze.Snapshot{RunID: prevRun}
	}
	obsStatus := make([]store.ObsStatus, 0, len(hosts))
	for i := range hosts {
		h := &hosts[i]
		as := assess[h.HostID]
		obsStatus = append(obsStatus, store.ObsStatus{HostID: h.HostID, Status: string(as.Status)})
		hs := analyze.HostSnapshot{HostID: h.HostID, IP: h.IP, Up: h.Up, Services: h.Services, ServiceIDs: h.ServiceIDs, PortsUnknown: h.HasUnknownPorts()}
		hs.SetAssessment(as, nObs[h.HostID])
		cur.Hosts = append(cur.Hosts, hs)
		if p, ok := prevHosts[h.HostID]; ok && prev != nil {
			prev.Hosts = append(prev.Hosts, analyze.HostSnapshot{HostID: h.HostID, IP: h.IP, Up: p.Up, Status: statusOr(p.Status, p.Up), Services: prevSvcs[h.HostID]})
		}
	}
	// Scope of the ports: an explicit port list of the profile limits "gone".
	// An imported file is a full view of the hosts it lists.
	var opts analyze.DiffOptions
	if hasProf {
		opts.PortInScope = a.portScope(ctx, prof)
	}
	changes, dsum := analyze.Diff(prev, cur, opts)
	sum = dsum
	if sum.ByKind == nil {
		sum.ByKind = map[string]int{}
	}
	newSvc := map[string]bool{} // host id | port/proto
	var goneIDs []int64
	upNow := map[int64]bool{}
	for i := range hosts {
		upNow[hosts[i].HostID] = hosts[i].Up
	}
	for _, c := range changes {
		switch c.Kind {
		case model.ChangeServiceNew:
			newSvc[strconv.FormatInt(c.HostID, 10)+"|"+strconv.Itoa(c.Port)] = true
		case model.ChangeServiceGone:
			// Gone only when the host answered and the port did not; the
			// services of a silent host are unknown (the ingest sets that).
			if c.ServiceID != nil && upNow[c.HostID] {
				goneIDs = append(goneIDs, *c.ServiceID)
			}
		}
	}

	// 3. Grouping keys over every open service, then the interest score of the services of this run.
	keys, sizes, total, err := a.groupKeys(ctx, hosts)
	if err != nil {
		return nil, err
	}
	scopes, err := a.st.ListScopes(ctx, store.ListOpts{Limit: 1000})
	if err != nil {
		return nil, err
	}
	crit := map[int64]int{}
	for _, sc := range scopes.Items {
		crit[sc.ID] = sc.Criticality
	}
	var svcRows []store.ServiceAnalysis
	hostRows := make([]store.HostAnalysis, 0, len(hosts))
	var findings []model.Finding
	derived := map[string]bool{}
	var upHosts []int64
	for i := range hosts {
		h := &hosts[i]
		as := assess[h.HostID]
		row := store.HostAnalysis{ID: h.HostID, Status: as.Status, PAlive: as.PAlive, Pattern: as.Pattern, Interest: -1}
		if !h.Up {
			hostRows = append(hostRows, row) // services of a silent host are unknown: keep its score
			continue
		}
		upHosts = append(upHosts, h.HostID)
		hc := 0
		for _, id := range h.ScopeIDs {
			hc = max(hc, crit[id])
		}
		_, known := prevHosts[h.HostID]
		in := analyze.FindingInput{HostID: h.HostID, IP: h.IP, Hostnames: h.Hostnames, RunID: runID, At: h.ObservedAt, ScopeCriticality: hc}
		var scores []int
		for j := range h.Services {
			sv := h.Services[j]
			if sv.State != "" && sv.State != "open" {
				continue
			}
			sid, hasID := h.ServiceIDs[store.ServiceKey(sv.Port, sv.Proto)]
			isNew := prev != nil && newSvc[strconv.FormatInt(h.HostID, 10)+"|"+strconv.Itoa(sv.Port)]
			key := keys[sid]
			score, why := analyze.Interest(analyze.InterestInput{Service: sv, Hostnames: h.Hostnames, NewExposure: isNew, GroupSize: sizes[key],
				TotalServices: total, ScopeCriticality: hc, Now: now})
			scores = append(scores, score)
			fs := analyze.FindingService{Result: sv, New: isNew, Interest: score}
			if hasID {
				id := sid
				fs.ServiceID = &id
				svcRows = append(svcRows, store.ServiceAnalysis{ID: sid, Interest: score, InterestWhy: why, GroupKey: key,
					Classes: analyze.EffectiveClasses(&sv, h.Hostnames)})
			}
			in.Services = append(in.Services, fs)
		}
		row.Interest = analyze.HostInterest(scores, prev != nil && !known)
		hostRows = append(hostRows, row)
		for _, f := range analyze.DeriveFindings(in) {
			if f.Key != "" && !derived[f.Key] {
				derived[f.Key] = true
				findings = append(findings, f)
			}
		}
	}

	// 4. Store: statuses, scores, changes, findings.
	if err := a.st.SetObservationStatus(ctx, runID, obsStatus); err != nil {
		return nil, err
	}
	if err := a.st.UpdateServiceAnalysis(ctx, svcRows); err != nil {
		return nil, err
	}
	if err := a.st.UpdateHostAnalysis(ctx, hostRows); err != nil {
		return nil, err
	}
	if err := a.st.InsertChanges(ctx, changes); err != nil {
		return nil, err
	}
	if partialData(run.Trigger) { // a profile scan marks missing services at ingest
		if err := a.st.MarkServicesGone(ctx, goneIDs); err != nil {
			return nil, err
		}
	}
	if sum.FindingsNew, err = a.st.UpsertFindings(ctx, findings); err != nil {
		return nil, err
	}
	// A finding of an answering host that this run no longer derives is resolved.
	// Only findings that no analyst has triaged change (store.ResolveFindings).
	if len(upHosts) > 0 && run.Trigger != "manual-entry" { // a manual entry adds facts, it does not prove absence
		var stale []int64
		err := a.st.EachFinding(ctx, store.FindingFilter{HostIDs: upHosts, Status: []string{string(model.FindingNew)}}, func(f *model.Finding) error {
			// Policy findings belong to internal/rules: Policy.Evaluate resolves them.
			if f.Manual || derived[f.Key] || f.LastRunID >= runID || f.Type == rules.FindingType {
				return nil
			}
			if f.Port != 0 && opts.PortInScope != nil && !opts.PortInScope("tcp", f.Port) && !opts.PortInScope("udp", f.Port) {
				return nil // the run did not look at this port
			}
			stale = append(stale, f.ID)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if _, err := a.st.ResolveFindings(ctx, stale); err != nil {
			return nil, err
		}
	}
	if err := a.st.SetRunSummary(ctx, runID, sum); err != nil {
		return nil, err
	}
	a.log.Info("run analysed", "run", runID, "hosts", len(hosts), "changes", len(changes), "findings", len(findings), "findings_new", sum.FindingsNew)
	if a.Policy != nil {
		// Exposure rules see the analysed inventory; their findings then go to
		// DefectDojo with the others.
		if rep, err := a.Policy.Evaluate(ctx, runID); err != nil {
			a.log.Error("policy evaluation failed", "run", runID, "err", err)
		} else {
			a.log.Info("policy evaluated", "run", runID, "report", rep)
		}
	}
	if a.Auto != nil {
		a.Auto.AutoExport(ctx, runID)
	}
	return &sum, nil
}

// partialData is true for runs whose results do not cover every port of the
// hosts they list: imports, manual entries and re-probes. Their ingest does
// not mark unreported services; the analysis marks the ones it reports gone.
func partialData(trigger string) bool {
	return trigger == "import" || trigger == "manual-entry" || trigger == "reprobe"
}

// runProfile returns the profile whose options a run used, with the ports of
// an ad-hoc run in place of the profile ports.
func (a *Analysis) runProfile(ctx context.Context, run model.ScanRun) (model.ScanProfile, bool) {
	var id int64
	switch {
	case run.AdHoc != nil:
		id = run.AdHoc.ProfileID
	case run.ProfileID != nil:
		id = *run.ProfileID
	default:
		return model.ScanProfile{}, false
	}
	p, err := a.st.GetProfile(ctx, id)
	if err != nil {
		return model.ScanProfile{}, false
	}
	if run.AdHoc != nil && strings.TrimSpace(run.AdHoc.Ports) != "" {
		p.Ports = run.AdHoc.Ports
	}
	return p, true
}

// groupKeys returns the grouping key of every open service, the size of each
// group and the number of open services. It stores the keys that changed for
// services outside this run; the services of this run are stored by the caller.
func (a *Analysis) groupKeys(ctx context.Context, hosts []store.RunHost) (keys map[int64]string, sizes map[string]int, total int, err error) {
	keys, err = a.st.OpenServiceGroups(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	total = len(keys)
	inRun := map[int64]bool{}
	if total <= maxGroupAll {
		names, err := a.st.HostNames(ctx)
		if err != nil {
			return nil, nil, 0, err
		}
		var items []analyze.GroupItem
		var ids []int64
		err = a.st.EachObservation(ctx, store.ObsFilter{LatestOnly: true, OpenOnly: true}, func(o *store.ObservationRow) error {
			items = append(items, analyze.GroupItem{Service: o.Result, Hostnames: names[o.HostID]})
			ids = append(ids, o.ServiceID)
			return nil
		})
		if err != nil {
			return nil, nil, 0, err
		}
		for i := range hosts {
			for _, id := range hosts[i].ServiceIDs {
				inRun[id] = true
			}
		}
		var changed []store.ServiceGroupKey
		for i, k := range analyze.AssignGroupKeys(items) {
			if keys[ids[i]] != k && !inRun[ids[i]] {
				changed = append(changed, store.ServiceGroupKey{ID: ids[i], GroupKey: k})
			}
			keys[ids[i]] = k
		}
		if err := a.st.UpdateServiceGroups(ctx, changed); err != nil {
			return nil, nil, 0, err
		}
	} else {
		for i := range hosts {
			h := &hosts[i]
			for j := range h.Services {
				if id, ok := h.ServiceIDs[store.ServiceKey(h.Services[j].Port, h.Services[j].Proto)]; ok {
					keys[id] = analyze.GroupKey(h.Services[j], h.Hostnames...)
				}
			}
		}
	}
	sizes = map[string]int{}
	for _, k := range keys {
		if k != "" {
			sizes[k]++
		}
	}
	return keys, sizes, total, nil
}

func (a *Analysis) snapshot(ctx context.Context, runID int64) (analyze.Snapshot, error) {
	snap := analyze.Snapshot{RunID: runID}
	err := a.st.EachRunHost(ctx, runID, func(h *store.RunHost) error {
		if h.ObservedAt.After(snap.At) {
			snap.At = h.ObservedAt
		}
		snap.Hosts = append(snap.Hosts, analyze.HostSnapshot{HostID: h.HostID, IP: h.IP, Up: h.Up, Status: statusOr(h.ObsStatus, h.Up),
			Services: h.Services, ServiceIDs: h.ServiceIDs})
		return nil
	})
	return snap, err
}

// Diff compares any two runs (GET /diff). Only hosts that both runs probed can
// change: a host that the newer run did not reach is unknown, not gone.
func (a *Analysis) Diff(ctx context.Context, fromRunID, toRunID int64) (model.DiffReport, error) {
	var rep model.DiffReport
	var err error
	if rep.From, err = a.st.GetRun(ctx, fromRunID); err != nil {
		return rep, err
	}
	if rep.To, err = a.st.GetRun(ctx, toRunID); err != nil {
		return rep, err
	}
	from, err := a.snapshot(ctx, fromRunID)
	if err != nil {
		return rep, err
	}
	to, err := a.snapshot(ctx, toRunID)
	if err != nil {
		return rep, err
	}
	var opts analyze.DiffOptions
	if p, ok := a.runProfile(ctx, rep.To); ok {
		opts.PortInScope = a.portScope(ctx, p)
	}
	rep.Changes, rep.Summary = analyze.Diff(&from, to, opts)
	if rep.Changes == nil {
		rep.Changes = []model.Change{}
	}
	return rep, nil
}

// DownAfterMisses tells how many more misses in a row would report the host
// inactive, under the rule of the profile that probed the host last. For a
// host that is already down it gives the threshold that reported it: the
// profile rule, or the number of misses in a row after which p_alive fell
// below analyze.DownThreshold.
func (a *Analysis) DownAfterMisses(p model.AvailabilityProfile) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var opt analyze.AssessOptions
	recent := oldestFirst(p.Recent)
	if n := len(recent); n > 0 && recent[n-1].RunID != 0 {
		if run, err := a.st.GetRun(ctx, recent[n-1].RunID); err == nil {
			if prof, ok := a.runProfile(ctx, run); ok {
				opt = analyze.OptionsFor(prof)
			}
		}
	}
	as := analyze.AssessWith(analyze.Profile{Buckets: p.Buckets, Recent: recent}, a.loc, opt)
	if as.Status != model.HostDown {
		return as.DownAfterMisses
	}
	if as.Rule > 0 {
		return as.Rule
	}
	for i, s := range as.Steps {
		if s.PAlive < analyze.DownThreshold {
			return i + 1
		}
	}
	return max(as.ConsecutiveMisses, 1)
}
