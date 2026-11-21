// Package timeline is the time machine of Czujka: the network as it was at
// any past run, built from the stored observations.
//
// It reads the tables of internal/store through st.Pool() with its own SQL
// and registers its own routes (Register). It writes nothing except optional
// indexes at Start. Wire it in cmd/czujka with:
//
//	tl := timeline.New(st, logger)
//	if err := tl.Start(ctx); err != nil { ... }
//	tl.Register(r, can)   // inside r.Route("/api/v1", ...), next to the other routes
//
// Definitions (the same in every route):
//
//   - The runs on the time line are the analysed runs (runs.summary IS NOT
//     NULL), ordered by id. "As of run R" means every observation of a run
//     with id <= R.
//   - A host as of R has the state of its latest observation as of R: up,
//     or the status the availability model gave it then (unstable,
//     expected-offline, down, unknown).
//   - A service as of R takes its latest observation as of R. It is "gone"
//     when its host answered in a later run (still <= R) that did not see
//     the service, "unknown" when its host was silent in every later run, and
//     "open" otherwise. A service not probed in R so keeps its last earlier
//     observation.
//   - A finding was open at R when it was first seen in a run <= R and was
//     not resolved before R (resolved findings keep last_run_id).
package timeline

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/store"
)

// Timeline serves the time machine routes. It is safe for concurrent use.
type Timeline struct {
	st  *store.Store
	log *slog.Logger

	mu    sync.Mutex
	cache *scrubCache
}

// New returns a Timeline over the store.
func New(st *store.Store, logger *slog.Logger) *Timeline {
	if logger == nil {
		logger = slog.Default()
	}
	return &Timeline{st: st, log: logger}
}

// Start creates the indexes the timeline queries need, when they are missing.
// See docs/API.md (Time machine, Re-probing) for the EXPLAIN that justifies each one.
func (t *Timeline) Start(ctx context.Context) error {
	for _, q := range indexes {
		if _, err := t.st.Pool().Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// ---------- API types ----------

// RunPoint is one marker of the scrubber: one analysed run with the state of
// the inventory as of that run and the changes the run found.
type RunPoint struct {
	RunID       int64     `json:"run_id"`
	At          time.Time `json:"at"` // finished_at, else started_at, else created_at
	Trigger     string    `json:"trigger"`
	Status      string    `json:"status"`
	ProfileName string    `json:"profile_name"`
	// State of the inventory as of this run.
	HostsUp         int `json:"hosts_up"`
	HostsMissing    int `json:"hosts_missing"` // silent, not reported inactive (unstable, expected-offline, unknown)
	HostsDown       int `json:"hosts_down"`
	ServicesOpen    int `json:"services_open"`
	ServicesUnknown int `json:"services_unknown"` // open before, host silent since
	FindingsOpen    int `json:"findings_open"`
	// What this run itself did.
	Probed          int            `json:"probed"`    // hosts observed in this run
	ProbedUp        int            `json:"probed_up"` // of them answered
	Changes         int            `json:"changes"`
	ChangesExpected int            `json:"changes_expected"`
	ChangesByKind   map[string]int `json:"changes_by_kind"`
}

// Scrubber is the answer of GET /timeline.
type Scrubber struct {
	Runs   []RunPoint `json:"runs"`
	From   *time.Time `json:"from"`
	To     *time.Time `json:"to"`
	TookMs int64      `json:"took_ms"`
}

// AtHost is one host as it was at a run.
type AtHost struct {
	ID         int64     `json:"id"`
	IP         string    `json:"ip"`
	Hostnames  []string  `json:"hostnames"`
	Label      string    `json:"label"`
	Status     string    `json:"status"` // then
	Up         bool      `json:"up"`
	ObservedAt time.Time `json:"observed_at"` // of the observation used
	RunID      int64     `json:"run_id"`      // of the observation used
	StatusNow  string    `json:"status_now"`
	OpenPorts  []int     `json:"open_ports"` // services open or unknown then
}

// AtService is one service as it was at a run.
type AtService struct {
	ID           int64     `json:"id"`
	HostID       int64     `json:"host_id"`
	IP           string    `json:"ip"`
	Port         int       `json:"port"`
	Proto        string    `json:"proto"`
	State        string    `json:"state"` // then: open | unknown | gone
	Name         string    `json:"name"`
	Product      string    `json:"product"`
	Version      string    `json:"version"`
	Title        string    `json:"title"`
	HTTPStatus   int       `json:"http_status"`
	TLS          bool      `json:"tls"`
	Technologies []string  `json:"technologies"`
	Classes      []string  `json:"classes"`
	ObservedAt   time.Time `json:"observed_at"`
	RunID        int64     `json:"run_id"` // run of the observation used (may be earlier than the asked run)
	StateNow     string    `json:"state_now"`
	ChangedSince bool      `json:"changed_since"` // product, version or title differ today
}

// AtFinding is one finding that was open at a run.
type AtFinding struct {
	ID         int64     `json:"id"`
	Key        string    `json:"key"`
	Type       string    `json:"type"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	Interest   int       `json:"interest"`
	HostID     int64     `json:"host_id"`
	IP         string    `json:"ip"`
	Port       int       `json:"port"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	FirstRunID int64     `json:"first_run_id"`
	LastRunID  int64     `json:"last_run_id"`
	StatusNow  string    `json:"status_now"`
}

// Page is the list envelope (the same as model.Page).
type Page[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// AtSummary counts the inventory at a run and compares it with today.
type AtSummary struct {
	HostsUp            int            `json:"hosts_up"`
	HostsMissing       int            `json:"hosts_missing"`
	HostsDown          int            `json:"hosts_down"`
	ServicesOpen       int            `json:"services_open"`
	ServicesUnknown    int            `json:"services_unknown"`
	FindingsOpen       int            `json:"findings_open"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	Diff               AtDiff         `json:"diff_to_now"`
}

// AtDiff compares the inventory at a run with the inventory today.
type AtDiff struct {
	ServicesGoneSince   int      `json:"services_gone_since"`   // existed then, not open today
	ServicesNewSince    int      `json:"services_new_since"`    // open today, did not exist then
	ServicesChanged     int      `json:"services_changed"`      // existed both times, product, version or title differ
	HostsDownSince      int      `json:"hosts_down_since"`      // answered then, not up today
	HostsUpSince        int      `json:"hosts_up_since"`        // up today, did not answer then
	HostsNewSince       int      `json:"hosts_new_since"`       // never observed up to then
	FindingsOpenedSince int      `json:"findings_opened_since"` // first seen after then, open today
	FindingsClosedSince int      `json:"findings_closed_since"` // open then, resolved today
	Sentences           []string `json:"sentences"`             // Polish, for the UI banner
}

// AtRun is the run that a snapshot shows.
type AtRun struct {
	ID          int64     `json:"id"`
	At          time.Time `json:"at"`
	Trigger     string    `json:"trigger"`
	Status      string    `json:"status"`
	ProfileName string    `json:"profile_name"`
}

// Snapshot is the answer of GET /timeline/at.
type Snapshot struct {
	Run      AtRun           `json:"run"`
	Summary  AtSummary       `json:"summary"`
	Hosts    Page[AtHost]    `json:"hosts"`
	Services Page[AtService] `json:"services"`
	Findings Page[AtFinding] `json:"findings"`
	TookMs   int64           `json:"took_ms"`
}

// Interval is one stretch of a swim lane.
type Interval struct {
	State        string    `json:"state"`            // host: up | missing | down; service: open | unknown
	Status       string    `json:"status,omitempty"` // host lane: the model status (unstable, expected-offline ...)
	From         time.Time `json:"from"`
	To           time.Time `json:"to"` // the first observation after the interval, or the last observation when Ongoing
	FromRun      int64     `json:"from_run"`
	ToRun        int64     `json:"to_run"` // last run inside the interval
	Observations int       `json:"observations"`
	Ongoing      bool      `json:"ongoing"`
}

// VersionMark is a change of product or version inside a service lane.
type VersionMark struct {
	At     time.Time `json:"at"`
	RunID  int64     `json:"run_id"`
	Before string    `json:"before"`
	After  string    `json:"after"`
}

// ServiceLane is the life line of one service of a host.
type ServiceLane struct {
	ServiceID int64         `json:"service_id"`
	Port      int           `json:"port"`
	Proto     string        `json:"proto"`
	Name      string        `json:"name"`
	StateNow  string        `json:"state_now"`
	Intervals []Interval    `json:"intervals"`
	Versions  []VersionMark `json:"versions"`
}

// HostLife is the answer of GET /timeline/hosts/{id}.
type HostLife struct {
	HostID    int64         `json:"host_id"`
	IP        string        `json:"ip"`
	StatusNow string        `json:"status_now"`
	FirstSeen *time.Time    `json:"first_seen"`
	LastSeen  *time.Time    `json:"last_seen"`
	Host      []Interval    `json:"host"`
	Services  []ServiceLane `json:"services"`
	TookMs    int64         `json:"took_ms"`
}

// FieldValue is one value of a field and the stretch in which it held.
type FieldValue struct {
	Value        string    `json:"value"`
	From         time.Time `json:"from"`
	To           time.Time `json:"to"` // last observation with this value
	FromRun      int64     `json:"from_run"`
	ToRun        int64     `json:"to_run"`
	Observations int       `json:"observations"`
}

// FieldHistory is the value history of one field that changed.
type FieldHistory struct {
	Field  string       `json:"field"` // title | version | status | certificate | headers | technologies | name
	Values []FieldValue `json:"values"`
}

// ServiceHistory is the answer of GET /timeline/services/{id}.
type ServiceHistory struct {
	ServiceID    int64             `json:"service_id"`
	HostID       int64             `json:"host_id"`
	IP           string            `json:"ip"`
	Port         int               `json:"port"`
	Proto        string            `json:"proto"`
	Observations int               `json:"observations"`
	Changed      []FieldHistory    `json:"changed"`   // fields with more than one value, in a fixed order
	Unchanged    map[string]string `json:"unchanged"` // fields that kept one value
	TookMs       int64             `json:"took_ms"`
}

// ---------- pure logic (unit tested) ----------

// hostObs is one host observation.
type hostObs struct {
	RunID  int64
	At     time.Time
	Up     bool
	Status string
}

// hostState maps an observation to the lane state of a host.
func hostState(o hostObs) (state, status string) {
	if o.Up {
		return "up", "up"
	}
	switch o.Status {
	case "down":
		return "down", "down"
	case "":
		return "missing", "unknown"
	default:
		return "missing", o.Status
	}
}

// mergeRuns returns one observation per run (several observations of one run
// come from a resumed chunk): up when any of them answered; the time and the
// status of the latest. Input and output are oldest first.
func mergeRuns(obs []hostObs) []hostObs {
	out := make([]hostObs, 0, len(obs))
	idx := map[int64]int{}
	for _, o := range obs {
		if i, ok := idx[o.RunID]; ok {
			p := &out[i]
			p.Up = p.Up || o.Up
			if o.At.After(p.At) {
				p.At = o.At
				if o.Status != "" {
					p.Status = o.Status
				}
			}
			if p.Up {
				p.Status = "up"
			}
			continue
		}
		idx[o.RunID] = len(out)
		out = append(out, o)
	}
	return out
}

// hostIntervals compresses the observations of a host (oldest first) into
// intervals of the same state and status.
func hostIntervals(obs []hostObs) []Interval {
	obs = mergeRuns(obs)
	var out []Interval
	for _, o := range obs {
		state, status := hostState(o)
		if n := len(out); n > 0 && out[n-1].State == state && out[n-1].Status == status {
			out[n-1].To, out[n-1].ToRun = o.At, o.RunID
			out[n-1].Observations++
			continue
		}
		if n := len(out); n > 0 {
			out[n-1].To = o.At // the stretch lasts until the next observation
		}
		out = append(out, Interval{State: state, Status: status, From: o.At, To: o.At, FromRun: o.RunID, ToRun: o.RunID, Observations: 1})
	}
	if n := len(out); n > 0 {
		out[n-1].Ongoing = true
	}
	return out
}

// svcObs is one observation of a service.
type svcObs struct {
	ServiceID int64
	RunID     int64
	At        time.Time
	Product   string
	Version   string
}

func versionText(o svcObs) string { return strings.TrimSpace(o.Product + " " + o.Version) }

// serviceLane walks the runs of the host (oldest first, one per run) and
// returns the intervals in which the service was open (observed) or unknown
// (open before, host silent since), and the version changes. A run in which
// the host answered without the service ends the life of the service until
// it is observed again.
func serviceLane(host []hostObs, obs []svcObs) ([]Interval, []VersionMark) {
	byRun := make(map[int64]svcObs, len(obs))
	for _, o := range obs {
		if p, ok := byRun[o.RunID]; !ok || o.At.After(p.At) {
			byRun[o.RunID] = o
		}
	}
	// A service observation of a run the host list lacks still counts.
	runs := mergeRuns(host)
	have := map[int64]bool{}
	for _, h := range runs {
		have[h.RunID] = true
	}
	for _, o := range obs {
		if !have[o.RunID] {
			have[o.RunID] = true
			runs = append(runs, hostObs{RunID: o.RunID, At: o.At, Up: true})
		}
	}
	sort.SliceStable(runs, func(i, j int) bool {
		if !runs[i].At.Equal(runs[j].At) {
			return runs[i].At.Before(runs[j].At)
		}
		return runs[i].RunID < runs[j].RunID
	})

	var out []Interval
	var marks []VersionMark
	state := "" // "" = absent
	lastVer, haveVer := "", false
	closeAt := func(at time.Time) {
		if n := len(out); n > 0 && state != "" {
			out[n-1].To = at
		}
	}
	for _, h := range runs {
		o, seen := byRun[h.RunID]
		next := ""
		switch {
		case seen:
			next = "open"
			// an empty version is a run without version detection, not a change
			if v := versionText(o); v != "" {
				if haveVer && v != lastVer {
					marks = append(marks, VersionMark{At: o.At, RunID: o.RunID, Before: lastVer, After: v})
				}
				lastVer, haveVer = v, true
			}
		case h.Up:
			next = "" // the host answered without the service: gone
		case state != "":
			next = "unknown" // the host was silent: the service may still be there
		}
		if next == state {
			if n := len(out); n > 0 && state != "" {
				out[n-1].To, out[n-1].ToRun = h.At, h.RunID
				out[n-1].Observations++
			}
			continue
		}
		closeAt(h.At)
		state = next
		if state != "" {
			out = append(out, Interval{State: state, From: h.At, To: h.At, FromRun: h.RunID, ToRun: h.RunID, Observations: 1})
		}
	}
	if n := len(out); n > 0 && state != "" {
		out[n-1].Ongoing = true
	}
	return out, marks
}

// fieldObs is the set of tracked field values of one service observation.
type fieldObs struct {
	RunID  int64
	At     time.Time
	Values map[string]string
}

// trackedFields is the fixed order of the fields of GET /timeline/services/{id}.
var trackedFields = []string{"name", "version", "title", "status", "certificate", "headers", "technologies"}

// fieldHistories splits the observations (oldest first) into the value
// stretches of each field. Fields with one value go to unchanged.
func fieldHistories(obs []fieldObs) (changed []FieldHistory, unchanged map[string]string) {
	unchanged = map[string]string{}
	for _, f := range trackedFields {
		var vals []FieldValue
		for _, o := range obs {
			v := o.Values[f]
			// An empty value is a field the run did not measure (no version
			// detection, no HTTP stage): the last known value stays.
			if v == "" && f != "name" {
				if n := len(vals); n > 0 {
					vals[n-1].To, vals[n-1].ToRun = o.At, o.RunID
				}
				continue
			}
			if n := len(vals); n > 0 && vals[n-1].Value == v {
				vals[n-1].To, vals[n-1].ToRun = o.At, o.RunID
				vals[n-1].Observations++
				continue
			}
			vals = append(vals, FieldValue{Value: v, From: o.At, To: o.At, FromRun: o.RunID, ToRun: o.RunID, Observations: 1})
		}
		switch {
		case len(vals) == 1:
			unchanged[f] = vals[0].Value
		case len(vals) > 1:
			changed = append(changed, FieldHistory{Field: f, Values: vals})
		}
	}
	return changed, unchanged
}

// volatileHeaders change from response to response and say nothing about the service.
var volatileHeaders = map[string]bool{"date": true, "content-length": true, "age": true, "expires": true, "last-modified": true,
	"etag": true, "x-request-id": true, "x-runtime": true, "transfer-encoding": true, "connection": true, "keep-alive": true,
	"x-response-time": true, "cf-ray": true, "x-amz-request-id": true, "report-to": true, "nel": true}

// headerSet returns the stable header names as one comparable text.
func headerSet(names []string) string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		l := strings.ToLower(strings.TrimSpace(n))
		if l == "" || volatileHeaders[l] {
			continue
		}
		out = append(out, l)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// certText is the comparable text of a certificate: fingerprint prefix and expiry day.
func certText(sha, notAfter string) string {
	if sha == "" && notAfter == "" {
		return ""
	}
	if len(sha) > 16 {
		sha = sha[:16]
	}
	day := notAfter
	if t, err := time.Parse(time.RFC3339, notAfter); err == nil {
		day = t.UTC().Format("2006-01-02")
	}
	return strings.TrimSpace("sha256:" + sha + " do " + day)
}

// ---------- the scrubber state machine ----------

// hostRunRow is one host in one analysed run.
type hostRunRow struct {
	HostID int64
	Run    int // index into the run list
	Up     bool
	Status string
}

// svcRunRow says that a service was observed in a run.
type svcRunRow struct {
	ServiceID int64
	HostID    int64
	Run       int
}

const (
	catNone = iota
	catUp
	catMissing
	catDown
)

func hostCat(up bool, status string) int {
	switch {
	case up:
		return catUp
	case status == "down":
		return catDown
	default:
		return catMissing
	}
}

// scrubCounts computes, for each of n runs, the hosts by state and the
// services open and unknown as of that run. hosts must be sorted by host and
// run; svcs by host, service and run. It works on deltas, so the cost is
// linear in the observations.
func scrubCounts(n int, hosts []hostRunRow, svcs []svcRunRow) (up, missing, down, open, unknown []int) {
	dh := make([][4]int, n+1)
	dsOpen := make([]int, n+1)
	dsUnknown := make([]int, n+1)

	// Host runs per host, for the service walk.
	type hr struct {
		run int
		up  bool
	}
	runsOf := map[int64][]hr{}
	for i := 0; i < len(hosts); {
		j := i
		cur := catNone
		for j < len(hosts) && hosts[j].HostID == hosts[i].HostID {
			c := hostCat(hosts[j].Up, hosts[j].Status)
			if c != cur {
				dh[hosts[j].Run][cur]--
				dh[hosts[j].Run][c]++
				cur = c
			}
			runsOf[hosts[i].HostID] = append(runsOf[hosts[i].HostID], hr{hosts[j].Run, hosts[j].Up})
			j++
		}
		i = j
	}
	for i := 0; i < len(svcs); {
		j := i
		seen := map[int]bool{}
		for j < len(svcs) && svcs[j].ServiceID == svcs[i].ServiceID {
			seen[svcs[j].Run] = true
			j++
		}
		first := svcs[i].Run
		state := 0 // 0 absent, 1 open, 2 unknown
		set := func(run, next int) {
			if next == state {
				return
			}
			switch state {
			case 1:
				dsOpen[run]--
			case 2:
				dsUnknown[run]--
			}
			switch next {
			case 1:
				dsOpen[run]++
			case 2:
				dsUnknown[run]++
			}
			state = next
		}
		hrs := runsOf[svcs[i].HostID]
		walked := map[int]bool{}
		for _, h := range hrs {
			if h.run < first {
				continue
			}
			walked[h.run] = true
			switch {
			case seen[h.run]:
				set(h.run, 1)
			case h.up:
				set(h.run, 0)
			case state != 0:
				set(h.run, 2)
			}
		}
		// Observations of runs without a host row (should not happen) still open the service.
		if len(walked) == 0 {
			set(first, 1)
		}
		i = j
	}
	up, missing, down = make([]int, n), make([]int, n), make([]int, n)
	open, unknown = make([]int, n), make([]int, n)
	var c [4]int
	o, u := 0, 0
	for r := 0; r < n; r++ {
		for k := 0; k < 4; k++ {
			c[k] += dh[r][k]
		}
		o += dsOpen[r]
		u += dsUnknown[r]
		up[r], missing[r], down[r], open[r], unknown[r] = c[catUp], c[catMissing], c[catDown], o, u
	}
	return up, missing, down, open, unknown
}

// findingsOpen returns, for each run id, the findings open as of that run:
// first seen in a run <= R, and not resolved before R.
func findingsOpen(runIDs []int64, firstByRun, resolvedLastByRun map[int64]int) []int {
	out := make([]int, len(runIDs))
	type kv struct {
		run int64
		n   int
	}
	sorted := func(m map[int64]int) []kv {
		s := make([]kv, 0, len(m))
		for k, v := range m {
			s = append(s, kv{k, v})
		}
		sort.Slice(s, func(i, j int) bool { return s[i].run < s[j].run })
		return s
	}
	fs, rs := sorted(firstByRun), sorted(resolvedLastByRun)
	fi, ri, opened, closed := 0, 0, 0, 0
	for i, r := range runIDs {
		for fi < len(fs) && fs[fi].run <= r {
			opened += fs[fi].n
			fi++
		}
		for ri < len(rs) && rs[ri].run < r {
			closed += rs[ri].n
			ri++
		}
		out[i] = opened - closed
	}
	return out
}

// ---------- Polish sentences ----------

// plural picks the Polish form for n: one (1), few (2-4, not 12-14), many.
func plural(n int, one, few, many string) string {
	if n == 1 {
		return one
	}
	m10, m100 := n%10, n%100
	if m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) {
		return few
	}
	return many
}

func count(n int, one, few, many string) string {
	return strconv.Itoa(n) + " " + plural(n, one, few, many)
}

// diffSentences writes the banner of a snapshot.
func diffSentences(d AtDiff) []string {
	var s []string
	if d.ServicesGoneSince > 0 {
		s = append(s, count(d.ServicesGoneSince, "usługa", "usługi", "usług")+", "+plural(d.ServicesGoneSince, "która", "które", "które")+
			" wtedy "+plural(d.ServicesGoneSince, "istniała", "istniały", "istniały")+", dziś nie "+plural(d.ServicesGoneSince, "odpowiada", "odpowiadają", "odpowiada")+".")
	}
	if d.ServicesNewSince > 0 {
		s = append(s, count(d.ServicesNewSince, "usługa", "usługi", "usług")+" "+plural(d.ServicesNewSince, "jest", "są", "jest")+
			" dziś otwarte, a wtedy "+plural(d.ServicesNewSince, "jej", "ich", "ich")+" nie było.")
	}
	if d.ServicesChanged > 0 {
		s = append(s, count(d.ServicesChanged, "usługa zmieniła", "usługi zmieniły", "usług zmieniło")+" od tamtej pory produkt, wersję albo tytuł.")
	}
	if d.HostsDownSince > 0 {
		s = append(s, count(d.HostsDownSince, "host", "hosty", "hostów")+" "+plural(d.HostsDownSince, "odpowiadał", "odpowiadały", "odpowiadało")+
			" wtedy, a dziś nie "+plural(d.HostsDownSince, "jest", "są", "jest")+" aktywn"+plural(d.HostsDownSince, "y", "e", "ych")+".")
	}
	if d.HostsNewSince > 0 {
		s = append(s, count(d.HostsNewSince, "host pojawił", "hosty pojawiły", "hostów pojawiło")+" się później.")
	}
	if d.FindingsOpenedSince > 0 || d.FindingsClosedSince > 0 {
		s = append(s, "Obserwacje od tamtej pory: "+strconv.Itoa(d.FindingsOpenedSince)+" nowych, "+strconv.Itoa(d.FindingsClosedSince)+" rozwiązanych.")
	}
	if len(s) == 0 {
		s = append(s, "Od tamtej pory inwentarz się nie zmienił.")
	}
	return s
}
