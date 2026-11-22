package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/targets"
	"net/netip"
)

func itoa(n int) string { return strconv.Itoa(n) }

// ---------- hosts ----------

const hostCols = `h.id, host(h.ip) AS ip, h.hostnames, h.scope_ids, h.status, h.p_alive, h.stability, h.consecutive_misses, h.pattern,
  h.first_seen, h.last_seen, h.last_up, h.os_guess, h.mac, h.vendor, h.label, h.owner, h.criticality, h.note_enc AS note, h.tags,
  h.interest, h.service_count, h.open_ports, h.technologies, h.overrides, h.source`

// Ordering by interest puts live hosts and open services first: a down host
// and a service that is not open count as interest 0 there (the stored value
// is unchanged and shown as it is).
const (
	hostLiveInterest    = "(CASE WHEN h.status = 'down' THEN 0 ELSE h.interest END)"
	serviceLiveInterest = "(CASE WHEN s.state = 'open' THEN s.interest ELSE 0 END)"
)

var hostSort = map[string]string{"id": "h.id", "ip": "h.ip", "status": "h.status", "interest": hostLiveInterest, "last_seen": "h.last_seen",
	"first_seen": "h.first_seen", "last_up": "h.last_up", "stability": "h.stability", "p_alive": "h.p_alive", "service_count": "h.service_count",
	"label": "h.label", "owner": "h.owner", "criticality": "h.criticality", "consecutive_misses": "h.consecutive_misses"}

// HostFilter are the filters of GET /hosts.
type HostFilter struct {
	ListOpts
	Status      []string
	Tag         string
	ScopeID     int64
	CIDR        string
	Tech        string
	Port        int
	MinInterest int
	Unstable    *bool
	IDs         []int64
}

func (f HostFilter) where() *where {
	w := &where{}
	if len(f.Status) > 0 {
		w.add("h.status = ANY(?)", f.Status)
	}
	if f.Tag != "" {
		w.add("h.tags @> ARRAY[?]::text[]", f.Tag)
	}
	if f.ScopeID != 0 {
		w.add("h.scope_ids @> ARRAY[?]::bigint[]", f.ScopeID)
	}
	if f.CIDR != "" {
		w.add("h.ip <<= ?::inet", f.CIDR)
	}
	if f.Tech != "" {
		w.add("h.technologies @> ARRAY[?]::text[]", f.Tech)
	}
	if f.Port != 0 {
		w.add("h.open_ports @> ARRAY[?]::int[]", f.Port)
	}
	if f.MinInterest > 0 {
		w.add("h.interest >= ?", f.MinInterest)
	}
	if f.Unstable != nil {
		if *f.Unstable {
			w.add("h.status IN ('unstable', 'expected-offline')")
		} else {
			w.add("h.status NOT IN ('unstable', 'expected-offline')")
		}
	}
	if len(f.IDs) > 0 {
		w.add("h.id = ANY(?)", f.IDs)
	}
	if f.Q != "" {
		q := like(f.Q)
		w.add("host(h.ip) ILIKE ? OR h.label ILIKE ? OR h.owner ILIKE ? OR h.os_guess ILIKE ? OR h.vendor ILIKE ? OR array_to_string(h.hostnames, ' ') ILIKE ?", q, q, q, q, q, q)
	}
	return w
}

func (s *Store) postHost(h *model.Host) error {
	note, err := s.kr.DecryptString(h.Note, "hosts|note|"+strconv.FormatInt(h.ID, 10))
	h.Note = note
	return err
}

// ListHosts returns a page of hosts.
func (s *Store) ListHosts(ctx context.Context, f HostFilter) (model.Page[model.Host], error) {
	return listPage[model.Host](ctx, s.db, hostCols, "hosts h", f.where(), orderBy(f.Sort, hostSort, hostLiveInterest+" DESC, h.interest DESC", "h.ip"), f.ListOpts, s.postHost)
}

// EachHost streams every host that matches the filter (for exports and analysis).
func (s *Store) EachHost(ctx context.Context, f HostFilter, fn func(*model.Host) error) error {
	return streamAll[model.Host](ctx, s.db, hostCols, "hosts h", f.where(), orderBy(f.Sort, hostSort, "h.ip ASC", "h.id"), s.postHost, fn)
}

// GetHost returns one host.
func (s *Store) GetHost(ctx context.Context, id int64) (model.Host, error) {
	h, err := jsonRow[model.Host](ctx, s.db, wrapJSON("SELECT "+hostCols+" FROM hosts h WHERE h.id = $1"), id)
	if err != nil {
		return h, err
	}
	return h, s.postHost(&h)
}

// DeleteHost removes a host with its services, observations, changes and findings.
func (s *Store) DeleteHost(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM hosts WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// HostHints returns what the inventory knows about the hosts of the given
// scopes. The engine scans known live blocks first and retries known hosts.
func (s *Store) HostHints(ctx context.Context, scopeIDs []int64) ([]model.HostHint, error) {
	return jsonRows[model.HostHint](ctx, s.db, wrapJSON(`SELECT host(h.ip) AS "IP", h.open_ports AS "OpenPorts", h.stability AS "Stability", h.last_up AS "LastUp"
		FROM hosts h WHERE h.scope_ids && $1::bigint[] AND h.last_up IS NOT NULL AND h.status <> 'down' ORDER BY h.ip`), nonNil(scopeIDs))
}

// HostHintsIn returns the hints of the known hosts inside the given addresses
// or CIDRs (an ad-hoc run), whatever their scope or status.
func (s *Store) HostHintsIn(ctx context.Context, addrs []string) ([]model.HostHint, error) {
	var nets []string
	for _, a := range addrs {
		if a = strings.TrimSpace(a); a != "" {
			if _, err := netip.ParsePrefix(a); err == nil {
				nets = append(nets, a)
			} else if ip, err := netip.ParseAddr(a); err == nil {
				nets = append(nets, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()).String())
			}
		}
	}
	if len(nets) == 0 {
		return []model.HostHint{}, nil
	}
	return jsonRows[model.HostHint](ctx, s.db, wrapJSON(`SELECT host(h.ip) AS "IP", h.open_ports AS "OpenPorts", h.stability AS "Stability", h.last_up AS "LastUp"
		FROM hosts h WHERE h.ip <<= ANY($1::cidr[]) AND h.last_up IS NOT NULL ORDER BY h.ip`), nets)
}

// Availability returns the hour-of-week histogram and the latest observations of a host.
func (s *Store) Availability(ctx context.Context, hostID int64) (model.AvailabilityProfile, error) {
	p := model.AvailabilityProfile{HostID: hostID}
	h, err := s.GetHost(ctx, hostID)
	if err != nil {
		return p, err
	}
	p.Pattern, p.PAlive = h.Pattern, h.PAlive
	rows, err := s.db.Query(ctx, `SELECT bucket, up, down FROM host_availability WHERE host_id = $1`, hostID)
	if err != nil {
		return p, mapErr(err)
	}
	for rows.Next() {
		var b, up, down int
		if err := rows.Scan(&b, &up, &down); err != nil {
			rows.Close()
			return p, err
		}
		if b >= 0 && b < len(p.Buckets) {
			p.Buckets[b] = model.AvailBucket{Up: up, Down: down}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, err
	}
	p.Recent, err = jsonRows[model.HostObservation](ctx, s.db, wrapJSON(`SELECT run_id, at, up, rtt_ms, attempts, reason FROM host_observations WHERE host_id = $1 ORDER BY at DESC LIMIT 100`), hostID)
	return p, err
}

// HostObservations returns the newest observations of several hosts in one query (for the stability model).
func (s *Store) HostObservations(ctx context.Context, hostIDs []int64, perHost int) (map[int64][]model.HostObservation, error) {
	type row struct {
		HostID int64 `json:"host_id"`
		model.HostObservation
	}
	out := map[int64][]model.HostObservation{}
	err := eachJSON(ctx, s.db, wrapJSON(`SELECT host_id, run_id, at, up, rtt_ms, attempts, reason FROM (
		SELECT o.*, row_number() OVER (PARTITION BY o.host_id ORDER BY o.at DESC) AS rn FROM host_observations o WHERE o.host_id = ANY($1)) x
		WHERE rn <= $2 ORDER BY host_id, at DESC`), []any{hostIDs, perHost}, func(r *row) error {
		out[r.HostID] = append(out[r.HostID], r.HostObservation)
		return nil
	})
	return out, err
}

// AvailabilityBuckets returns the histograms of several hosts in one query.
func (s *Store) AvailabilityBuckets(ctx context.Context, hostIDs []int64) (map[int64]*[168]model.AvailBucket, error) {
	rows, err := s.db.Query(ctx, `SELECT host_id, bucket, up, down FROM host_availability WHERE host_id = ANY($1)`, hostIDs)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[int64]*[168]model.AvailBucket{}
	for rows.Next() {
		var id int64
		var b, up, down int
		if err := rows.Scan(&id, &b, &up, &down); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = &[168]model.AvailBucket{}
		}
		if b >= 0 && b < 168 {
			out[id][b] = model.AvailBucket{Up: up, Down: down}
		}
	}
	return out, rows.Err()
}

// ---------- services ----------

const serviceCols = `s.id, s.host_id, host(s.ip) AS ip, s.hostname, s.port, s.proto, s.state, s.name, s.product, s.version, s.banner,
  s.confidence, s.tls, s.title, s.http_status, s.url, s.technologies, s.classes, s.interest, s.interest_why, s.group_key,
  (CASE WHEN s.group_key = '' THEN 0 ELSE (SELECT count(*) FROM services g WHERE g.group_key = s.group_key) END) AS group_size,
  s.note_enc AS note, s.tags, s.first_seen, s.last_seen, s.last_changed, s.overrides,
  (SELECT NULLIF(` + responseExpr + `, -1) FROM service_observations o WHERE o.service_id = s.id ORDER BY o.at DESC, o.id DESC LIMIT 1) AS response_ms,
  s.response_slow`

var serviceSort = map[string]string{"id": "s.id", "ip": "s.ip", "port": "s.port", "state": "s.state", "name": "s.name", "product": "s.product",
	"version": "s.version", "interest": serviceLiveInterest, "title": "s.title", "http_status": "s.http_status", "first_seen": "s.first_seen",
	"last_seen": "s.last_seen", "last_changed": "s.last_changed", "confidence": "s.confidence", "group_key": "s.group_key", "cert_not_after": "s.cert_not_after"}

// ServiceFilter are the filters of GET /services.
type ServiceFilter struct {
	ListOpts
	HostID      int64
	Port        int
	State       []string
	Name        string
	Tech        string
	Class       string
	Tag         string
	GroupKey    string
	MinInterest int
	TLS         *bool
	RunID       int64
	CertWithin  int // days; services whose certificate ends within this many days
	IDs         []int64
}

func (f ServiceFilter) where() *where {
	w := &where{}
	if f.HostID != 0 {
		w.add("s.host_id = ?", f.HostID)
	}
	if f.Port != 0 {
		w.add("s.port = ?", f.Port)
	}
	if len(f.State) > 0 {
		w.add("s.state = ANY(?)", f.State)
	}
	if f.Name != "" {
		w.add("s.name = ?", f.Name)
	}
	if f.Tech != "" {
		w.add("s.tech_names @> ARRAY[?]::text[]", f.Tech)
	}
	if f.Class != "" {
		w.add("s.classes @> ARRAY[?]::text[]", f.Class)
	}
	if f.Tag != "" {
		w.add("s.tags @> ARRAY[?]::text[]", f.Tag)
	}
	if f.GroupKey != "" {
		w.add("s.group_key = ?", f.GroupKey)
	}
	if f.MinInterest > 0 {
		w.add("s.interest >= ?", f.MinInterest)
	}
	if f.TLS != nil {
		w.add("s.tls = ?", *f.TLS)
	}
	if f.RunID != 0 {
		w.add("s.id IN (SELECT o.service_id FROM service_observations o WHERE o.run_id = ?)", f.RunID)
	}
	if f.CertWithin > 0 {
		w.add("s.cert_not_after IS NOT NULL AND s.cert_not_after < now() + make_interval(days => ?)", f.CertWithin)
	}
	if len(f.IDs) > 0 {
		w.add("s.id = ANY(?)", f.IDs)
	}
	if f.Q != "" {
		q := like(f.Q)
		w.add("host(s.ip) ILIKE ? OR s.hostname ILIKE ? OR s.name ILIKE ? OR s.product ILIKE ? OR s.version ILIKE ? OR s.title ILIKE ? OR s.banner ILIKE ? OR s.url ILIKE ?", q, q, q, q, q, q, q, q)
	}
	return w
}

func (s *Store) postService(v *model.Service) error {
	v.Hostname = targets.ShownHostname(v.Hostname, v.IP)
	note, err := s.kr.DecryptString(v.Note, "services|note|"+strconv.FormatInt(v.ID, 10))
	v.Note = note
	return err
}

// serviceColsFor adds "carried" for a list of one run: the run's
// observation of the service is a carried copy (the run did not scan it).
func serviceColsFor(f ServiceFilter) string {
	if f.RunID == 0 {
		return serviceCols
	}
	return serviceCols + fmt.Sprintf(`, EXISTS (SELECT 1 FROM service_observations co WHERE co.service_id = s.id AND co.run_id = %d
		AND COALESCE((co.result->>'carried')::boolean, false)) AS carried`, f.RunID)
}

// CountCarried returns how many services run runID did not scan and carried
// over from an earlier run (their state is kept).
func (s *Store) CountCarried(ctx context.Context, runID int64) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(DISTINCT service_id) FROM service_observations
		WHERE run_id = $1 AND COALESCE((result->>'carried')::boolean, false)`, runID).Scan(&n)
	return n, mapErr(err)
}

// ListServices returns a page of services.
func (s *Store) ListServices(ctx context.Context, f ServiceFilter) (model.Page[model.Service], error) {
	return listPage[model.Service](ctx, s.db, serviceColsFor(f), "services s", f.where(), orderBy(f.Sort, serviceSort, serviceLiveInterest+" DESC, s.interest DESC", "s.ip, s.port"), f.ListOpts, s.postService)
}

// EachService streams every service that matches the filter.
func (s *Store) EachService(ctx context.Context, f ServiceFilter, fn func(*model.Service) error) error {
	return streamAll[model.Service](ctx, s.db, serviceColsFor(f), "services s", f.where(), orderBy(f.Sort, serviceSort, "s.ip ASC", "s.port, s.id"), s.postService, fn)
}

// GetService returns one service; withLatest also loads its newest observation.
func (s *Store) GetService(ctx context.Context, id int64, withLatest bool) (model.Service, error) {
	v, err := jsonRow[model.Service](ctx, s.db, wrapJSON("SELECT "+serviceCols+" FROM services s WHERE s.id = $1"), id)
	if err != nil {
		return v, err
	}
	if err := s.postService(&v); err != nil {
		return v, err
	}
	if withLatest {
		page, err := s.ListObservations(ctx, id, ListOpts{Limit: 1})
		if err != nil {
			return v, err
		}
		if len(page.Items) > 0 {
			v.Latest = &page.Items[0]
		}
	}
	return v, nil
}

// HostServices returns every service of one host, ordered by port.
func (s *Store) HostServices(ctx context.Context, hostID int64) ([]model.Service, error) {
	out := []model.Service{}
	err := s.EachService(ctx, ServiceFilter{HostID: hostID, ListOpts: ListOpts{Sort: "port"}}, func(v *model.Service) error {
		out = append(out, *v)
		return nil
	})
	return out, err
}

// DeleteService removes a service with its observations.
func (s *Store) DeleteService(ctx context.Context, id int64) error {
	var hostID int64
	if err := s.db.QueryRow(ctx, `DELETE FROM services WHERE id = $1 RETURNING host_id`, id).Scan(&hostID); err != nil {
		return mapErr(err)
	}
	return s.refreshHostAggregates(ctx, []int64{hostID})
}

// ---------- service observations ----------

// obsSecret holds the sensitive parts of a ServiceResult. It is stored
// encrypted, beside the result that no longer contains them.
type obsSecret struct {
	Cookies  []string   `json:"c,omitempty"` // raw cookie values, by cookie index
	Body     string     `json:"b,omitempty"` // body excerpt
	Paths    []string   `json:"p,omitempty"` // excerpts of extra paths, by path index
	Snippets [][]string `json:"e,omitempty"` // evidence snippets, by match and evidence index
}

// splitSecrets returns a copy of r without its sensitive parts, and those parts.
func splitSecrets(r model.ServiceResult) (model.ServiceResult, obsSecret, bool) {
	var sec obsSecret
	has := false
	if r.HTTP != nil {
		h := *r.HTTP
		if len(h.Cookies) > 0 {
			h.Cookies = append([]model.Cookie(nil), h.Cookies...)
			sec.Cookies = make([]string, len(h.Cookies))
			for i := range h.Cookies {
				if h.Cookies[i].Value != "" {
					sec.Cookies[i], has = h.Cookies[i].Value, true
					h.Cookies[i].Value = ""
				}
			}
		}
		if h.BodyExcerpt != "" {
			sec.Body, has = h.BodyExcerpt, true
			h.BodyExcerpt = ""
		}
		if len(h.Paths) > 0 {
			h.Paths = append([]model.PathProbe(nil), h.Paths...)
			sec.Paths = make([]string, len(h.Paths))
			for i := range h.Paths {
				if h.Paths[i].Excerpt != "" {
					sec.Paths[i], has = h.Paths[i].Excerpt, true
					h.Paths[i].Excerpt = ""
				}
			}
		}
		r.HTTP = &h
	}
	if len(r.Matches) > 0 {
		r.Matches = append([]model.SigMatch(nil), r.Matches...)
		sec.Snippets = make([][]string, len(r.Matches))
		for i := range r.Matches {
			if len(r.Matches[i].Evidence) == 0 {
				continue
			}
			ev := append([]model.Evidence(nil), r.Matches[i].Evidence...)
			sec.Snippets[i] = make([]string, len(ev))
			for j := range ev {
				if ev[j].Snippet != "" {
					sec.Snippets[i][j], has = ev[j].Snippet, true
					ev[j].Snippet = ""
				}
			}
			r.Matches[i].Evidence = ev
		}
	}
	return r, sec, has
}

// mergeSecrets puts the sensitive parts back into a stored result.
func mergeSecrets(r *model.ServiceResult, sec obsSecret) {
	if r.HTTP != nil {
		for i := range r.HTTP.Cookies {
			if i < len(sec.Cookies) {
				r.HTTP.Cookies[i].Value = sec.Cookies[i]
			}
		}
		if sec.Body != "" {
			r.HTTP.BodyExcerpt = sec.Body
		}
		for i := range r.HTTP.Paths {
			if i < len(sec.Paths) {
				r.HTTP.Paths[i].Excerpt = sec.Paths[i]
			}
		}
	}
	for i := range r.Matches {
		if i >= len(sec.Snippets) {
			break
		}
		for j := range r.Matches[i].Evidence {
			if j < len(sec.Snippets[i]) {
				r.Matches[i].Evidence[j].Snippet = sec.Snippets[i][j]
			}
		}
	}
}

func obsAD(serviceID, runID int64) string {
	return fmt.Sprintf("service_observations|secret|%d|%d", serviceID, runID)
}

// ObservationRow is a stored observation with the address of its service.
type ObservationRow struct {
	model.ServiceObservation
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	HostID int64  `json:"host_id"`
	Secret string `json:"secret,omitempty"`
}

const obsCols = `o.id, o.service_id, o.run_id, o.at, o.result, o.secret, o.host_id, host(s.ip) AS ip, s.port`
const obsFrom = `service_observations o JOIN services s ON s.id = o.service_id`

func (s *Store) postObs(o *ObservationRow) error {
	if o.Secret == "" {
		return nil
	}
	raw, err := s.kr.Decrypt(o.Secret, obsAD(o.ServiceID, o.RunID))
	if err != nil {
		return err
	}
	var sec obsSecret
	if err := json.Unmarshal(raw, &sec); err != nil {
		return err
	}
	mergeSecrets(&o.Result, sec)
	o.Secret = ""
	return nil
}

// ListObservations returns a page of the observations of one service, newest first.
func (s *Store) ListObservations(ctx context.Context, serviceID int64, o ListOpts) (model.Page[model.ServiceObservation], error) {
	w := &where{}
	w.add("o.service_id = ?", serviceID)
	page, err := listPage[ObservationRow](ctx, s.db, obsCols, obsFrom, w, " ORDER BY o.at DESC, o.id DESC", o, s.postObs)
	out := model.Page[model.ServiceObservation]{Items: make([]model.ServiceObservation, 0, len(page.Items)), Total: page.Total, Limit: page.Limit, Offset: page.Offset}
	for _, it := range page.Items {
		out.Items = append(out.Items, it.ServiceObservation)
	}
	return out, err
}

// ObsFilter selects stored observations for retro-hunt and analysis.
type ObsFilter struct {
	RunID      int64 // 0 = every run
	LatestOnly bool  // only the newest observation of every service
	ServiceID  int64
	OpenOnly   bool // only services that are open now
}

// EachObservation streams stored observations, decrypted, without keeping them in memory.
func (s *Store) EachObservation(ctx context.Context, f ObsFilter, fn func(*ObservationRow) error) error {
	w := &where{}
	if f.RunID != 0 {
		w.add("o.run_id = ?", f.RunID)
	}
	if f.ServiceID != 0 {
		w.add("o.service_id = ?", f.ServiceID)
	}
	if f.OpenOnly {
		w.add("s.state = 'open'")
	}
	sql := "SELECT " + obsCols + " FROM " + obsFrom + w.sql() + " ORDER BY o.service_id, o.at DESC, o.id DESC"
	if f.LatestOnly {
		sql = "SELECT DISTINCT ON (o.service_id) " + obsCols + " FROM " + obsFrom + w.sql() + " ORDER BY o.service_id, o.at DESC, o.id DESC"
	}
	return eachJSON(ctx, s.db, wrapJSON(sql), w.args, func(o *ObservationRow) error {
		if err := s.postObs(o); err != nil {
			return err
		}
		return fn(o)
	})
}

// ---------- groups, technologies, tags ----------

// ListServiceGroups returns groups of look-alike open services. Sort "count"
// puts the rare groups first.
func (s *Store) ListServiceGroups(ctx context.Context, o ListOpts) (model.Page[model.ServiceGroup], error) {
	const from = `(SELECT g.key, CASE WHEN g.title <> '' THEN g.title WHEN g.product <> '' THEN g.product ELSE g.name END AS label, g.count,
		COALESCE((SELECT x.tech_names FROM services x WHERE x.id = g.sample_ids[1]), '{}') AS technologies, g.title, g.sample_ids, g.interest
		FROM (SELECT group_key AS key, count(*)::int AS count, max(interest) AS interest, (array_agg(id ORDER BY interest DESC, id))[1:5] AS sample_ids,
			COALESCE(mode() WITHIN GROUP (ORDER BY title), '') AS title, COALESCE(mode() WITHIN GROUP (ORDER BY product), '') AS product,
			COALESCE(mode() WITHIN GROUP (ORDER BY name), '') AS name
			FROM services WHERE group_key <> '' AND state = 'open' GROUP BY group_key) g) sg`
	w := &where{}
	if o.Q != "" {
		w.add("sg.label ILIKE ? OR sg.key ILIKE ?", like(o.Q), like(o.Q))
	}
	order := orderBy(o.Sort, map[string]string{"count": "sg.count", "interest": "sg.interest", "label": "sg.label", "key": "sg.key"}, "sg.count DESC", "sg.key")
	return listPage[model.ServiceGroup](ctx, s.db, "sg.key, sg.label, sg.count, sg.technologies, sg.title, sg.sample_ids, sg.interest", from, w, order, o, nil)
}

// TechnologyCounts returns every technology with the number of open services that run it.
func (s *Store) TechnologyCounts(ctx context.Context, limit int) ([]model.NameCount, error) {
	sql := `SELECT t.name, count(*)::int AS count, max(t.category) AS extra FROM technologies t JOIN services s ON s.id = t.service_id
		WHERE s.state = 'open' GROUP BY t.name ORDER BY count DESC, t.name`
	if limit > 0 {
		sql += " LIMIT " + itoa(limit)
	}
	return jsonRows[model.NameCount](ctx, s.db, wrapJSON(sql))
}

// TagCounts returns every tag with the number of tagged hosts, services and findings.
func (s *Store) TagCounts(ctx context.Context) ([]model.NameCount, error) {
	return jsonRows[model.NameCount](ctx, s.db, wrapJSON(`SELECT name, sum(n)::int AS count FROM (
		SELECT unnest(tags) AS name, 1 AS n FROM hosts UNION ALL SELECT unnest(tags), 1 FROM services UNION ALL
		SELECT unnest(tags), 1 FROM findings UNION ALL SELECT name, 0 FROM tags) x GROUP BY name ORDER BY count DESC, name`))
}

func (s *Store) rememberTags(ctx context.Context, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `INSERT INTO tags (name) SELECT unnest($1::text[]) ON CONFLICT DO NOTHING`, tags)
	return err
}

// ---------- analyst edits (PATCH) ----------

type patchField struct {
	col      string
	kind     string // text | int | text[]
	observed bool   // scanner-observed field: an edit is stored as an override
	check    func(v any) error
}

type patchSpec struct {
	table  string
	fields map[string]patchField
	noteAD string // associated-data prefix of the encrypted note column; "" when the table has no note
}

func decodeKind(kind string, raw json.RawMessage) (any, error) {
	null := len(raw) == 0 || string(raw) == "null"
	switch kind {
	case "int":
		if null {
			return 0, nil
		}
		var v int
		err := json.Unmarshal(raw, &v)
		return v, err
	case "text[]":
		out := []string{}
		if null {
			return out, nil
		}
		var v []string
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, x := range v {
			x = strings.TrimSpace(x)
			if x != "" && !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
		return out, nil
	default:
		if null {
			return "", nil
		}
		var v string
		err := json.Unmarshal(raw, &v)
		return v, err
	}
}

// applyPatch stores an analyst edit. Fields marked observed keep the scanner
// value in overrides[field].observed; a JSON null removes the override again.
func (s *Store) applyPatch(ctx context.Context, spec patchSpec, id int64, patch map[string]json.RawMessage, by string) error {
	if len(patch) == 0 {
		return nil
	}
	return s.Tx(ctx, func(tx *Store) error {
		cols := []string{"overrides"}
		for name := range patch {
			if f, ok := spec.fields[name]; ok && f.observed {
				cols = append(cols, f.col)
			}
		}
		var raw []byte
		if err := tx.db.QueryRow(ctx, "SELECT row_to_json(t) FROM (SELECT "+strings.Join(cols, ", ")+" FROM "+spec.table+" WHERE id = $1 FOR UPDATE) t", id).Scan(&raw); err != nil {
			return mapErr(err)
		}
		cur := map[string]json.RawMessage{}
		if err := json.Unmarshal(raw, &cur); err != nil {
			return err
		}
		overrides := map[string]model.Override{}
		if err := json.Unmarshal(cur["overrides"], &overrides); err != nil {
			return err
		}
		args := []any{id}
		var sets []string
		set := func(col string, v any, cast string) {
			args = append(args, v)
			sets = append(sets, col+" = $"+itoa(len(args))+cast)
		}
		now := time.Now().UTC()
		var tags []string
		for name, rawv := range patch {
			if name == "note" && spec.noteAD != "" {
				v, err := decodeKind("text", rawv)
				if err != nil {
					return fmt.Errorf("%w: note must be a string", ErrInvalid)
				}
				enc, err := tx.kr.EncryptString(v.(string), spec.noteAD+strconv.FormatInt(id, 10))
				if err != nil {
					return err
				}
				set("note_enc", enc, "")
				continue
			}
			f, ok := spec.fields[name]
			if !ok {
				return fmt.Errorf("%w: field %q cannot be changed", ErrInvalid, name)
			}
			isNull := string(rawv) == "null"
			if f.observed && isNull {
				ov, has := overrides[name]
				if !has {
					continue
				}
				v, err := decodeKind(f.kind, js(ov.Observed))
				if err != nil {
					return err
				}
				set(f.col, v, "")
				delete(overrides, name)
				continue
			}
			v, err := decodeKind(f.kind, rawv)
			if err != nil {
				return fmt.Errorf("%w: field %q has the wrong type", ErrInvalid, name)
			}
			if f.check != nil {
				if err := f.check(v); err != nil {
					return fmt.Errorf("%w: %s: %v", ErrInvalid, name, err)
				}
			}
			if f.observed {
				var observed any
				if ov, has := overrides[name]; has {
					observed = ov.Observed
				} else if err := json.Unmarshal(cur[f.col], &observed); err != nil {
					return err
				}
				overrides[name] = model.Override{Value: v, Observed: observed, By: by, At: now}
			}
			if name == "tags" {
				tags = v.([]string)
			}
			set(f.col, v, "")
		}
		set("overrides", js(overrides), "::jsonb")
		if _, err := tx.db.Exec(ctx, "UPDATE "+spec.table+" SET "+strings.Join(sets, ", ")+" WHERE id = $1", args...); err != nil {
			return mapErr(err)
		}
		return tx.rememberTags(ctx, tags)
	})
}

func oneOf(allowed ...string) func(any) error {
	return func(v any) error {
		for _, a := range allowed {
			if v == a {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(allowed, ", "))
	}
}

func intRange(lo, hi int) func(any) error {
	return func(v any) error {
		if n := v.(int); n < lo || n > hi {
			return fmt.Errorf("must be between %d and %d", lo, hi)
		}
		return nil
	}
}

var hostPatch = patchSpec{table: "hosts", noteAD: "hosts|note|", fields: map[string]patchField{
	"label":       {col: "label", kind: "text"},
	"owner":       {col: "owner", kind: "text"},
	"criticality": {col: "criticality", kind: "int", check: intRange(0, 5)},
	"tags":        {col: "tags", kind: "text[]"},
	"hostnames":   {col: "hostnames", kind: "text[]", observed: true},
	"os_guess":    {col: "os_guess", kind: "text", observed: true},
}}

var servicePatch = patchSpec{table: "services", noteAD: "services|note|", fields: map[string]patchField{
	"name":    {col: "name", kind: "text", observed: true},
	"product": {col: "product", kind: "text", observed: true},
	"version": {col: "version", kind: "text", observed: true},
	"classes": {col: "classes", kind: "text[]", observed: true},
	"tags":    {col: "tags", kind: "text[]"},
}}

// PatchHost applies an analyst edit to a host and returns the new state.
// by is the e-mail of the editor.
func (s *Store) PatchHost(ctx context.Context, id int64, patch map[string]json.RawMessage, by string) (model.Host, error) {
	if err := s.applyPatch(ctx, hostPatch, id, patch, by); err != nil {
		return model.Host{}, err
	}
	return s.GetHost(ctx, id)
}

// PatchService applies an analyst edit to a service and returns the new state.
func (s *Store) PatchService(ctx context.Context, id int64, patch map[string]json.RawMessage, by string) (model.Service, error) {
	if err := s.applyPatch(ctx, servicePatch, id, patch, by); err != nil {
		return model.Service{}, err
	}
	return s.GetService(ctx, id, false)
}
