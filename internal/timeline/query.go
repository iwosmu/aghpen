package timeline

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// indexes are created by Start when missing. See docs/API.md (Time machine, Re-probing).
var indexes = []string{
	// GET /timeline/at: the latest observation of a service as of a run is a
	// LATERAL lookup by (service_id, run_id); the stock index orders by "at".
	`CREATE INDEX IF NOT EXISTS timeline_svc_obs_run_idx ON service_observations (service_id, run_id DESC)`,
	// The same lookup for hosts, and the "later run of this host" lookup.
	`CREATE INDEX IF NOT EXISTS timeline_host_obs_run_idx ON host_observations (host_id, run_id DESC)`,
}

// ErrNotFound means the run, host or service does not exist.
var ErrNotFound = errors.New("not found")

const runAt = `COALESCE(r.finished_at, r.started_at, r.created_at)`

// ---------- scrubber ----------

type scrubCache struct {
	key  string
	runs []RunPoint
}

// Scrubber returns every analysed run with its counts, oldest first.
func (t *Timeline) Scrubber(ctx context.Context, from, to *time.Time) (Scrubber, error) {
	start := time.Now()
	db := t.st.Pool()
	var key string
	if err := db.QueryRow(ctx, `SELECT concat_ws('|', count(*), max(r.id), max(`+runAt+`),
			(SELECT max(id) FROM host_observations), (SELECT max(id) FROM changes))
		FROM runs r WHERE r.summary IS NOT NULL`).Scan(&key); err != nil {
		return Scrubber{}, err
	}
	t.mu.Lock()
	c := t.cache
	t.mu.Unlock()
	var runs []RunPoint
	if c != nil && c.key == key {
		runs = c.runs
	} else {
		var err error
		if runs, err = t.buildScrubber(ctx); err != nil {
			return Scrubber{}, err
		}
		t.mu.Lock()
		t.cache = &scrubCache{key: key, runs: runs}
		t.mu.Unlock()
	}
	// Findings counts change with triage: compute them on every call (two small aggregates).
	ids := make([]int64, len(runs))
	for i, r := range runs {
		ids[i] = r.RunID
	}
	first, resolved := map[int64]int{}, map[int64]int{}
	rows, err := db.Query(ctx, `SELECT first_run_id, count(*) FILTER (WHERE true), 0 FROM findings GROUP BY first_run_id
		UNION ALL SELECT last_run_id, 0, count(*) FROM findings WHERE status = 'resolved' GROUP BY last_run_id`)
	if err != nil {
		return Scrubber{}, err
	}
	for rows.Next() {
		var run int64
		var f, r int
		if err := rows.Scan(&run, &f, &r); err != nil {
			rows.Close()
			return Scrubber{}, err
		}
		first[run] += f
		resolved[run] += r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Scrubber{}, err
	}
	open := findingsOpen(ids, first, resolved)
	out := Scrubber{Runs: make([]RunPoint, 0, len(runs))}
	for i, r := range runs {
		if (from != nil && r.At.Before(*from)) || (to != nil && r.At.After(*to)) {
			continue
		}
		r.FindingsOpen = open[i]
		out.Runs = append(out.Runs, r)
	}
	if n := len(out.Runs); n > 0 {
		a, b := out.Runs[0].At, out.Runs[n-1].At
		out.From, out.To = &a, &b
	}
	out.TookMs = time.Since(start).Milliseconds()
	return out, nil
}

func (t *Timeline) buildScrubber(ctx context.Context) ([]RunPoint, error) {
	db := t.st.Pool()
	rows, err := db.Query(ctx, `SELECT r.id, `+runAt+`, r.trigger, r.status, r.profile_name FROM runs r WHERE r.summary IS NOT NULL ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	var runs []RunPoint
	idx := map[int64]int{}
	for rows.Next() {
		var p RunPoint
		if err := rows.Scan(&p.RunID, &p.At, &p.Trigger, &p.Status, &p.ProfileName); err != nil {
			rows.Close()
			return nil, err
		}
		p.ChangesByKind = map[string]int{}
		idx[p.RunID] = len(runs)
		runs = append(runs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return runs, nil
	}
	ids := make([]int64, len(runs))
	for i, r := range runs {
		ids[i] = r.RunID
	}

	// 1. one row per host and run (several observations of one run merge)
	var hosts []hostRunRow
	rows, err = db.Query(ctx, `SELECT o.host_id, o.run_id, bool_or(o.up), (array_agg(o.status ORDER BY o.at DESC, o.id DESC))[1]
		FROM host_observations o WHERE o.run_id = ANY($1) GROUP BY o.host_id, o.run_id ORDER BY o.host_id, o.run_id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var h hostRunRow
		var run int64
		if err := rows.Scan(&h.HostID, &run, &h.Up, &h.Status); err != nil {
			rows.Close()
			return nil, err
		}
		h.Run = idx[run]
		hosts = append(hosts, h)
		runs[h.Run].Probed++
		if h.Up {
			runs[h.Run].ProbedUp++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 2. which service was observed in which run
	var svcs []svcRunRow
	rows, err = db.Query(ctx, `SELECT DISTINCT so.service_id, so.host_id, so.run_id FROM service_observations so
		WHERE so.run_id = ANY($1) ORDER BY so.service_id, so.run_id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s svcRunRow
		var run int64
		if err := rows.Scan(&s.ServiceID, &s.HostID, &run); err != nil {
			rows.Close()
			return nil, err
		}
		s.Run = idx[run]
		svcs = append(svcs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	up, missing, down, open, unknown := scrubCounts(len(runs), hosts, svcs)
	for i := range runs {
		runs[i].HostsUp, runs[i].HostsMissing, runs[i].HostsDown = up[i], missing[i], down[i]
		runs[i].ServicesOpen, runs[i].ServicesUnknown = open[i], unknown[i]
	}

	// 3. changes by run and kind
	rows, err = db.Query(ctx, `SELECT run_id, kind, count(*), count(*) FILTER (WHERE expected) FROM changes WHERE run_id = ANY($1) GROUP BY run_id, kind`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var run int64
		var kind string
		var n, exp int
		if err := rows.Scan(&run, &kind, &n, &exp); err != nil {
			rows.Close()
			return nil, err
		}
		p := &runs[idx[run]]
		p.ChangesByKind[kind] += n
		p.Changes += n
		p.ChangesExpected += exp
	}
	rows.Close()
	return runs, rows.Err()
}

// ---------- snapshot at a run ----------

// ResolveRun returns the run to show: runID when given, else the last
// analysed run at or before at, else the last analysed run.
func (t *Timeline) ResolveRun(ctx context.Context, runID int64, at *time.Time) (AtRun, error) {
	var r AtRun
	var err error
	q := `SELECT r.id, ` + runAt + `, r.trigger, r.status, r.profile_name FROM runs r WHERE r.summary IS NOT NULL`
	switch {
	case runID != 0:
		err = t.st.Pool().QueryRow(ctx, q+` AND r.id = $1`, runID).Scan(&r.ID, &r.At, &r.Trigger, &r.Status, &r.ProfileName)
	case at != nil:
		err = t.st.Pool().QueryRow(ctx, q+` AND `+runAt+` <= $1 ORDER BY `+runAt+` DESC, r.id DESC LIMIT 1`, *at).Scan(&r.ID, &r.At, &r.Trigger, &r.Status, &r.ProfileName)
	default:
		err = t.st.Pool().QueryRow(ctx, q+` ORDER BY r.id DESC LIMIT 1`).Scan(&r.ID, &r.At, &r.Trigger, &r.Status, &r.ProfileName)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// HostFilter are the filters of the hosts of a snapshot.
type HostFilter struct {
	Status  []string // then: up, unstable, expected-offline, down, unknown; "missing" = every silent status but down
	CIDR    string
	Q       string
	ScopeID int64
	Port    int // had this port open (or unknown) then
	Limit   int
	Offset  int
	Sort    string // ip (default), -ip, observed_at, -observed_at, status
}

// hostAsOf is the latest observation of each host as of run $1.
const hostAsOf = `FROM hosts h
	CROSS JOIN LATERAL (SELECT o.run_id, o.at, o.up, o.status FROM host_observations o
		WHERE o.host_id = h.id AND o.run_id <= $1 ORDER BY o.run_id DESC, o.at DESC LIMIT 1) o`

const hostStatusThen = `(CASE WHEN o.up THEN 'up' WHEN o.status <> '' THEN o.status ELSE 'unknown' END)`

// svcAsOf is the latest observation of each service as of run $1 and what
// its host did in later runs (still <= $1).
const svcAsOf = `FROM services s
	CROSS JOIN LATERAL (SELECT so.run_id, so.at, so.name, so.product, so.version, so.title, so.http_status, so.tls, so.result
		FROM service_observations so WHERE so.service_id = s.id AND so.run_id <= $1 ORDER BY so.run_id DESC, so.at DESC LIMIT 1) o
	CROSS JOIN LATERAL (SELECT bool_or(ho.up) AS up_after, count(*) AS n_after FROM host_observations ho
		WHERE ho.host_id = s.host_id AND ho.run_id > o.run_id AND ho.run_id <= $1) a`

const svcStateThen = `(CASE WHEN COALESCE(a.up_after, false) THEN 'gone' WHEN a.n_after > 0 THEN 'unknown' ELSE 'open' END)`

// args collects positional SQL arguments.
type args struct{ v []any }

func (a *args) add(x any) string { a.v = append(a.v, x); return fmt.Sprintf("$%d", len(a.v)) }

func clampPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// AtHosts returns a page of hosts as they were at run.
func (t *Timeline) AtHosts(ctx context.Context, run int64, f HostFilter) (Page[AtHost], error) {
	f.Limit, f.Offset = clampPage(f.Limit, f.Offset)
	a := &args{v: []any{run}}
	var where []string
	if len(f.Status) > 0 {
		var st []string
		missing := false
		for _, s := range f.Status {
			if s == "missing" {
				missing = true
				continue
			}
			st = append(st, s)
		}
		cond := hostStatusThen + " = ANY(" + a.add(st) + ")"
		if missing {
			cond = "(" + cond + " OR (NOT o.up AND " + hostStatusThen + " <> 'down'))"
		}
		where = append(where, cond)
	}
	if f.CIDR != "" {
		where = append(where, "h.ip <<= "+a.add(f.CIDR)+"::cidr")
	}
	if f.Q != "" {
		p := a.add("%" + strings.NewReplacer("%", "\\%", "_", "\\_").Replace(f.Q) + "%")
		where = append(where, "(host(h.ip) ILIKE "+p+" OR array_to_string(h.hostnames, ' ') ILIKE "+p+" OR h.label ILIKE "+p+")")
	}
	if f.ScopeID != 0 {
		where = append(where, a.add(f.ScopeID)+" = ANY(h.scope_ids)")
	}
	if f.Port != 0 {
		where = append(where, "EXISTS (SELECT 1 "+svcAsOf+" WHERE s.host_id = h.id AND s.port = "+a.add(f.Port)+" AND "+svcStateThen+" <> 'gone')")
	}
	order := "h.ip"
	switch f.Sort {
	case "-ip":
		order = "h.ip DESC"
	case "observed_at":
		order = "o.at, h.ip"
	case "-observed_at":
		order = "o.at DESC, h.ip"
	case "status":
		order = hostStatusThen + ", h.ip"
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + strings.Join(where, " AND ")
	}
	q := `SELECT h.id, host(h.ip), h.hostnames, h.label, ` + hostStatusThen + `, o.up, o.at, o.run_id, h.status, count(*) OVER () ` +
		hostAsOf + w + " ORDER BY " + order + " LIMIT " + a.add(f.Limit) + " OFFSET " + a.add(f.Offset)
	rows, err := t.st.Pool().Query(ctx, q, a.v...)
	if err != nil {
		return Page[AtHost]{}, err
	}
	page := Page[AtHost]{Items: []AtHost{}, Limit: f.Limit, Offset: f.Offset}
	var ids []int64
	for rows.Next() {
		var h AtHost
		if err := rows.Scan(&h.ID, &h.IP, &h.Hostnames, &h.Label, &h.Status, &h.Up, &h.ObservedAt, &h.RunID, &h.StatusNow, &page.Total); err != nil {
			rows.Close()
			return page, err
		}
		h.OpenPorts = []int{}
		ids = append(ids, h.ID)
		page.Items = append(page.Items, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(ids) == 0 {
		return page, nil
	}
	// Second statement: the ports of the page's hosts as of the run.
	rows, err = t.st.Pool().Query(ctx, `SELECT s.host_id, s.port `+svcAsOf+` WHERE s.host_id = ANY($2) AND `+svcStateThen+` <> 'gone' ORDER BY s.host_id, s.port`, run, ids)
	if err != nil {
		return page, err
	}
	ports := map[int64][]int{}
	for rows.Next() {
		var id int64
		var port int
		if err := rows.Scan(&id, &port); err != nil {
			rows.Close()
			return page, err
		}
		ports[id] = append(ports[id], port)
	}
	rows.Close()
	for i := range page.Items {
		if p := ports[page.Items[i].ID]; p != nil {
			page.Items[i].OpenPorts = p
		}
	}
	return page, rows.Err()
}

// ServiceFilter are the filters of the services of a snapshot.
type ServiceFilter struct {
	HostID int64
	Port   int
	Name   string
	Tech   string
	Class  string
	State  []string // then: open, unknown, gone; empty = open and unknown; "all" = every state
	TLS    *bool
	CIDR   string
	Q      string
	Limit  int
	Offset int
	Sort   string // ip (default: ip, port), port, -port, observed_at, -observed_at
}

// AtServices returns a page of services as they were at run.
func (t *Timeline) AtServices(ctx context.Context, run int64, f ServiceFilter) (Page[AtService], error) {
	f.Limit, f.Offset = clampPage(f.Limit, f.Offset)
	a := &args{v: []any{run}}
	var where []string
	states := f.State
	all := false
	for _, s := range states {
		if s == "all" {
			all = true
		}
	}
	if !all {
		if len(states) == 0 {
			states = []string{"open", "unknown"}
		}
		where = append(where, svcStateThen+" = ANY("+a.add(states)+")")
	}
	if f.HostID != 0 {
		where = append(where, "s.host_id = "+a.add(f.HostID))
	}
	if f.Port != 0 {
		where = append(where, "s.port = "+a.add(f.Port))
	}
	if f.Name != "" {
		where = append(where, "o.name = "+a.add(f.Name))
	}
	if f.Tech != "" {
		where = append(where, "o.result->'technologies' @> jsonb_build_array(jsonb_build_object('name', "+a.add(f.Tech)+"::text))")
	}
	if f.Class != "" {
		where = append(where, "o.result->'classes' ? "+a.add(f.Class))
	}
	if f.TLS != nil {
		where = append(where, "o.tls = "+a.add(*f.TLS))
	}
	if f.CIDR != "" {
		where = append(where, "s.ip <<= "+a.add(f.CIDR)+"::cidr")
	}
	if f.Q != "" {
		p := a.add("%" + strings.NewReplacer("%", "\\%", "_", "\\_").Replace(f.Q) + "%")
		where = append(where, "(host(s.ip) ILIKE "+p+" OR o.product ILIKE "+p+" OR o.title ILIKE "+p+" OR o.name ILIKE "+p+" OR o.version ILIKE "+p+")")
	}
	order := "s.ip, s.port"
	switch f.Sort {
	case "port":
		order = "s.port, s.ip"
	case "-port":
		order = "s.port DESC, s.ip"
	case "observed_at":
		order = "o.at, s.ip, s.port"
	case "-observed_at":
		order = "o.at DESC, s.ip, s.port"
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + strings.Join(where, " AND ")
	}
	q := `SELECT s.id, s.host_id, host(s.ip), s.port, s.proto, ` + svcStateThen + `, o.name, o.product, o.version, o.title, o.http_status, o.tls,
		ARRAY(SELECT DISTINCT x->>'name' FROM jsonb_array_elements(CASE WHEN jsonb_typeof(o.result->'technologies') = 'array' THEN o.result->'technologies' ELSE '[]'::jsonb END) x WHERE x->>'name' <> ''),
		ARRAY(SELECT x FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(o.result->'classes') = 'array' THEN o.result->'classes' ELSE '[]'::jsonb END) x),
		o.at, o.run_id, s.state, (s.product, s.version, s.title) IS DISTINCT FROM (o.product, o.version, o.title), count(*) OVER () ` +
		svcAsOf + w + " ORDER BY " + order + " LIMIT " + a.add(f.Limit) + " OFFSET " + a.add(f.Offset)
	rows, err := t.st.Pool().Query(ctx, q, a.v...)
	if err != nil {
		return Page[AtService]{}, err
	}
	defer rows.Close()
	page := Page[AtService]{Items: []AtService{}, Limit: f.Limit, Offset: f.Offset}
	for rows.Next() {
		var s AtService
		if err := rows.Scan(&s.ID, &s.HostID, &s.IP, &s.Port, &s.Proto, &s.State, &s.Name, &s.Product, &s.Version, &s.Title, &s.HTTPStatus, &s.TLS,
			&s.Technologies, &s.Classes, &s.ObservedAt, &s.RunID, &s.StateNow, &s.ChangedSince, &page.Total); err != nil {
			return page, err
		}
		page.Items = append(page.Items, s)
	}
	return page, rows.Err()
}

// FindingFilter are the filters of the findings of a snapshot.
type FindingFilter struct {
	Severity []string
	Type     string
	HostID   int64
	Limit    int
	Offset   int
}

const findingOpenThen = `f.first_run_id <= $1 AND f.first_seen <= $2 AND (f.status <> 'resolved' OR f.last_run_id >= $1)`

// AtFindings returns a page of the findings open at run, most interesting first.
func (t *Timeline) AtFindings(ctx context.Context, run AtRun, f FindingFilter) (Page[AtFinding], error) {
	f.Limit, f.Offset = clampPage(f.Limit, f.Offset)
	a := &args{v: []any{run.ID, run.At}}
	where := []string{findingOpenThen}
	if len(f.Severity) > 0 {
		where = append(where, "f.severity = ANY("+a.add(f.Severity)+")")
	}
	if f.Type != "" {
		where = append(where, "f.type = "+a.add(f.Type))
	}
	if f.HostID != 0 {
		where = append(where, "f.host_id = "+a.add(f.HostID))
	}
	q := `SELECT f.id, f.key, f.type, f.title, f.severity, f.interest, f.host_id, COALESCE(host(f.ip), ''), f.port, f.first_seen, f.last_seen,
		f.first_run_id, f.last_run_id, f.status, count(*) OVER () FROM findings f WHERE ` + strings.Join(where, " AND ") +
		" ORDER BY f.interest DESC, f.id DESC LIMIT " + a.add(f.Limit) + " OFFSET " + a.add(f.Offset)
	rows, err := t.st.Pool().Query(ctx, q, a.v...)
	if err != nil {
		return Page[AtFinding]{}, err
	}
	defer rows.Close()
	page := Page[AtFinding]{Items: []AtFinding{}, Limit: f.Limit, Offset: f.Offset}
	for rows.Next() {
		var x AtFinding
		if err := rows.Scan(&x.ID, &x.Key, &x.Type, &x.Title, &x.Severity, &x.Interest, &x.HostID, &x.IP, &x.Port, &x.FirstSeen, &x.LastSeen,
			&x.FirstRunID, &x.LastRunID, &x.StatusNow, &page.Total); err != nil {
			return page, err
		}
		page.Items = append(page.Items, x)
	}
	return page, rows.Err()
}

// Summary counts the inventory at run and compares it with today, in one statement.
func (t *Timeline) Summary(ctx context.Context, run AtRun) (AtSummary, error) {
	s := AtSummary{FindingsBySeverity: map[string]int{}}
	var d AtDiff
	err := t.st.Pool().QueryRow(ctx, `WITH hs AS (SELECT h.id, h.status AS st_now, o.up, `+hostStatusThen+` AS st_then FROM hosts h
			LEFT JOIN LATERAL (SELECT o.run_id, o.at, o.up, o.status FROM host_observations o
				WHERE o.host_id = h.id AND o.run_id <= $1 ORDER BY o.run_id DESC, o.at DESC LIMIT 1) o ON true),
		ss AS (SELECT s.id, s.state AS st_now, CASE WHEN o.run_id IS NULL THEN NULL ELSE `+svcStateThen+` END AS st_then,
				(s.product, s.version, s.title) IS DISTINCT FROM (o.product, o.version, o.title) AS changed
			FROM services s
			LEFT JOIN LATERAL (SELECT so.run_id, so.product, so.version, so.title FROM service_observations so
				WHERE so.service_id = s.id AND so.run_id <= $1 ORDER BY so.run_id DESC, so.at DESC LIMIT 1) o ON true
			LEFT JOIN LATERAL (SELECT bool_or(ho.up) AS up_after, count(*) AS n_after FROM host_observations ho
				WHERE ho.host_id = s.host_id AND ho.run_id > o.run_id AND ho.run_id <= $1) a ON o.run_id IS NOT NULL),
		fs AS (SELECT f.severity, f.status, (`+findingOpenThen+`) AS open_then, f.first_run_id > $1 AS later FROM findings f)
		SELECT
			(SELECT count(*) FILTER (WHERE st_then = 'up') FROM hs),
			(SELECT count(*) FILTER (WHERE st_then IS NOT NULL AND st_then NOT IN ('up', 'down') AND up IS NOT NULL) FROM hs),
			(SELECT count(*) FILTER (WHERE st_then = 'down') FROM hs),
			(SELECT count(*) FILTER (WHERE st_then = 'up' AND st_now <> 'up') FROM hs),
			(SELECT count(*) FILTER (WHERE st_now = 'up' AND (up IS NULL OR NOT up)) FROM hs),
			(SELECT count(*) FILTER (WHERE up IS NULL) FROM hs),
			(SELECT count(*) FILTER (WHERE st_then = 'open') FROM ss),
			(SELECT count(*) FILTER (WHERE st_then = 'unknown') FROM ss),
			(SELECT count(*) FILTER (WHERE st_then IN ('open', 'unknown') AND st_now <> 'open') FROM ss),
			(SELECT count(*) FILTER (WHERE st_now = 'open' AND (st_then IS NULL OR st_then = 'gone')) FROM ss),
			(SELECT count(*) FILTER (WHERE st_now = 'open' AND st_then IN ('open', 'unknown') AND changed) FROM ss),
			(SELECT count(*) FILTER (WHERE open_then) FROM fs),
			(SELECT COALESCE(jsonb_object_agg(severity, n), '{}') FROM (SELECT severity, count(*) AS n FROM fs WHERE open_then GROUP BY severity) x),
			(SELECT count(*) FILTER (WHERE later AND status <> 'resolved') FROM fs),
			(SELECT count(*) FILTER (WHERE open_then AND status = 'resolved') FROM fs)`,
		run.ID, run.At).Scan(&s.HostsUp, &s.HostsMissing, &s.HostsDown, &d.HostsDownSince, &d.HostsUpSince, &d.HostsNewSince,
		&s.ServicesOpen, &s.ServicesUnknown, &d.ServicesGoneSince, &d.ServicesNewSince, &d.ServicesChanged,
		&s.FindingsOpen, &s.FindingsBySeverity, &d.FindingsOpenedSince, &d.FindingsClosedSince)
	if err != nil {
		return s, err
	}
	d.Sentences = diffSentences(d)
	s.Diff = d
	return s, nil
}

// ---------- host life line and service history ----------

// HostLife returns the swim lanes of one host.
func (t *Timeline) HostLife(ctx context.Context, hostID int64) (HostLife, error) {
	start := time.Now()
	db := t.st.Pool()
	out := HostLife{HostID: hostID, Host: []Interval{}, Services: []ServiceLane{}}
	err := db.QueryRow(ctx, `SELECT host(ip), status FROM hosts WHERE id = $1`, hostID).Scan(&out.IP, &out.StatusNow)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	rows, err := db.Query(ctx, `SELECT run_id, at, up, status FROM host_observations WHERE host_id = $1 ORDER BY at, id`, hostID)
	if err != nil {
		return out, err
	}
	var hobs []hostObs
	for rows.Next() {
		var o hostObs
		if err := rows.Scan(&o.RunID, &o.At, &o.Up, &o.Status); err != nil {
			rows.Close()
			return out, err
		}
		hobs = append(hobs, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	if n := len(hobs); n > 0 {
		a, b := hobs[0].At, hobs[n-1].At
		out.FirstSeen, out.LastSeen = &a, &b
	}
	if iv := hostIntervals(hobs); iv != nil {
		out.Host = iv
	}

	rows, err = db.Query(ctx, `SELECT s.id, s.port, s.proto, s.name, s.state, so.run_id, so.at, so.product, so.version
		FROM services s LEFT JOIN service_observations so ON so.service_id = s.id
		WHERE s.host_id = $1 ORDER BY s.port, s.proto, s.id, so.at, so.id`, hostID)
	if err != nil {
		return out, err
	}
	type acc struct {
		lane ServiceLane
		obs  []svcObs
	}
	var lanes []*acc
	byID := map[int64]*acc{}
	for rows.Next() {
		var id int64
		var port int
		var proto, name, state string
		var run *int64
		var at *time.Time
		var product, version *string
		if err := rows.Scan(&id, &port, &proto, &name, &state, &run, &at, &product, &version); err != nil {
			rows.Close()
			return out, err
		}
		a := byID[id]
		if a == nil {
			a = &acc{lane: ServiceLane{ServiceID: id, Port: port, Proto: proto, Name: name, StateNow: state}}
			byID[id] = a
			lanes = append(lanes, a)
		}
		if run != nil {
			a.obs = append(a.obs, svcObs{ServiceID: id, RunID: *run, At: *at, Product: deref(product), Version: deref(version)})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	for _, a := range lanes {
		iv, marks := serviceLane(hobs, a.obs)
		a.lane.Intervals, a.lane.Versions = iv, marks
		if a.lane.Intervals == nil {
			a.lane.Intervals = []Interval{}
		}
		if a.lane.Versions == nil {
			a.lane.Versions = []VersionMark{}
		}
		out.Services = append(out.Services, a.lane)
	}
	out.TookMs = time.Since(start).Milliseconds()
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ServiceHistory returns the value history of the fields of one service that changed.
func (t *Timeline) ServiceHistory(ctx context.Context, serviceID int64) (ServiceHistory, error) {
	start := time.Now()
	db := t.st.Pool()
	out := ServiceHistory{ServiceID: serviceID, Changed: []FieldHistory{}, Unchanged: map[string]string{}}
	err := db.QueryRow(ctx, `SELECT host_id, host(ip), port, proto FROM services WHERE id = $1`, serviceID).Scan(&out.HostID, &out.IP, &out.Port, &out.Proto)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	rows, err := db.Query(ctx, `SELECT so.run_id, so.at, so.name, so.product, so.version, so.title, so.http_status,
			COALESCE(so.result->'tls'->>'sha256', ''), COALESCE(so.result->'tls'->>'not_after', ''),
			ARRAY(SELECT jsonb_object_keys(CASE WHEN jsonb_typeof(so.result->'http'->'headers') = 'object' THEN so.result->'http'->'headers' ELSE '{}'::jsonb END)),
			ARRAY(SELECT DISTINCT x->>'name' FROM jsonb_array_elements(CASE WHEN jsonb_typeof(so.result->'technologies') = 'array' THEN so.result->'technologies' ELSE '[]'::jsonb END) x
				WHERE x->>'name' <> '' ORDER BY 1)
		FROM service_observations so WHERE so.service_id = $1 ORDER BY so.at, so.id`, serviceID)
	if err != nil {
		return out, err
	}
	var obs []fieldObs
	for rows.Next() {
		var o fieldObs
		var name, product, version, title, sha, notAfter string
		var status int
		var headers, techs []string
		if err := rows.Scan(&o.RunID, &o.At, &name, &product, &version, &title, &status, &sha, &notAfter, &headers, &techs); err != nil {
			rows.Close()
			return out, err
		}
		st := ""
		if status != 0 {
			st = fmt.Sprint(status)
		}
		o.Values = map[string]string{
			"name": name, "version": strings.TrimSpace(product + " " + version), "title": title, "status": st,
			"certificate": certText(sha, notAfter), "headers": headerSet(headers), "technologies": strings.Join(techs, ", "),
		}
		obs = append(obs, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.Observations = len(obs)
	changed, unchanged := fieldHistories(obs)
	if changed != nil {
		out.Changed = changed
	}
	out.Unchanged = unchanged
	out.TookMs = time.Since(start).Milliseconds()
	return out, nil
}

// validCIDR accepts an address or a prefix.
func validCIDR(s string) (string, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String(), true
	}
	return "", false
}
