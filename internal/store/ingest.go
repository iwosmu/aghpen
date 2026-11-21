package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// SinkOptions configure the store-backed result sink.
type SinkOptions struct {
	BatchSize int    // hosts per database batch; default 250
	Source    string // "scan" or "import"; stored on new hosts
	// MarkMissing sets services that a run did not report to "gone" (host up)
	// or "unknown" (host down). Use it for scans; imports of partial data leave it off.
	MarkMissing bool
}

// Sink is the store-backed model.ResultSink. OnHost only buffers; the buffer
// goes to the database in batches, a few statements per batch, so a run with
// 10 000 hosts needs some dozens of round trips and not tens of thousands.
type Sink struct {
	s       *Store
	opt     SinkOptions
	mu      sync.Mutex // guards buf
	buf     []model.HostResult
	flushMu sync.Mutex // one batch at a time
}

var _ model.ResultSink = (*Sink)(nil)

// NewSink returns a result sink that writes to this store.
func (s *Store) NewSink(opt SinkOptions) *Sink {
	if opt.BatchSize <= 0 {
		opt.BatchSize = 250
	}
	if opt.Source == "" {
		opt.Source = "scan"
	}
	return &Sink{s: s, opt: opt}
}

// OnPlan stores the planned chunks.
func (k *Sink) OnPlan(ctx context.Context, runID int64, chunks []model.Chunk) error {
	return k.s.SavePlan(ctx, runID, chunks)
}

// OnChunk stores a chunk state. Buffered hosts are written first, so a chunk
// marked done has its results in the database.
func (k *Sink) OnChunk(ctx context.Context, c model.Chunk) error {
	if c.Status != model.ChunkRunning && c.Status != model.ChunkPending {
		if err := k.Flush(ctx); err != nil {
			return err
		}
	}
	return k.s.UpsertChunk(ctx, c)
}

// OnHost buffers one host result and writes a batch when the buffer is full.
func (k *Sink) OnHost(ctx context.Context, res model.HostResult) error {
	k.mu.Lock()
	k.buf = append(k.buf, res)
	full := len(k.buf) >= k.opt.BatchSize
	k.mu.Unlock()
	if full {
		return k.Flush(ctx)
	}
	return nil
}

// OnProgress stores the run counters and writes the buffered hosts.
func (k *Sink) OnProgress(ctx context.Context, runID int64, stats model.RunStats) error {
	if err := k.Flush(ctx); err != nil {
		return err
	}
	return k.s.UpdateRunStats(ctx, runID, stats)
}

// Flush writes every buffered host result. Call it when the engine returns.
func (k *Sink) Flush(ctx context.Context) error {
	k.flushMu.Lock()
	defer k.flushMu.Unlock()
	k.mu.Lock()
	batch := k.buf
	k.buf = nil
	k.mu.Unlock()
	for len(batch) > 0 {
		n := min(len(batch), k.opt.BatchSize)
		if err := k.s.IngestHosts(ctx, batch[:n], k.opt); err != nil {
			return err
		}
		batch = batch[n:]
	}
	return nil
}

type hostIn struct {
	IP        string    `json:"ip"`
	Hostnames []string  `json:"hostnames"`
	ScopeIDs  []int64   `json:"scope_ids"`
	Up        bool      `json:"up"`
	At        time.Time `json:"at"`
	OSGuess   string    `json:"os_guess"`
	MAC       string    `json:"mac"`
	Vendor    string    `json:"vendor"`
	Source    string    `json:"source"`
	RunID     int64     `json:"run_id"`
}

type hostObsIn struct {
	HostID   int64     `json:"host_id"`
	RunID    int64     `json:"run_id"`
	At       time.Time `json:"at"`
	Up       bool      `json:"up"`
	RTTMs    float64   `json:"rtt_ms"`
	Attempts int       `json:"attempts"`
	Reason   string    `json:"reason"`
	Bucket   int       `json:"bucket"`
	UpN      int       `json:"up_n"`
	DownN    int       `json:"down_n"`
}

type serviceIn struct {
	HostID       int64              `json:"host_id"`
	IP           string             `json:"ip"`
	Hostname     string             `json:"hostname"`
	Port         int                `json:"port"`
	Proto        string             `json:"proto"`
	State        string             `json:"state"`
	Name         string             `json:"name"`
	Product      string             `json:"product"`
	Version      string             `json:"version"`
	Banner       string             `json:"banner"`
	Confidence   float64            `json:"confidence"`
	TLS          bool               `json:"tls"`
	Title        string             `json:"title"`
	HTTPStatus   int                `json:"http_status"`
	URL          string             `json:"url"`
	Technologies []model.Technology `json:"technologies"`
	TechNames    []string           `json:"tech_names"`
	Classes      []string           `json:"classes"`
	At           time.Time          `json:"at"`
	ObsHash      string             `json:"obs_hash"`
	RunID        int64              `json:"run_id"`
	CertNotAfter *time.Time         `json:"cert_not_after"`
}

type obsIn struct {
	ServiceID  int64               `json:"service_id"`
	HostID     int64               `json:"host_id"`
	RunID      int64               `json:"run_id"`
	At         time.Time           `json:"at"`
	State      string              `json:"state"`
	Name       string              `json:"name"`
	Product    string              `json:"product"`
	Version    string              `json:"version"`
	Title      string              `json:"title"`
	HTTPStatus int                 `json:"http_status"`
	TLS        bool                `json:"tls"`
	Result     model.ServiceResult `json:"result"`
	Secret     string              `json:"secret"`
}

type techIn struct {
	ServiceID  int64   `json:"service_id"`
	HostID     int64   `json:"host_id"`
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	Version    string  `json:"version"`
	Confidence float64 `json:"confidence"`
	CPE        string  `json:"cpe"`
}

type svcKey struct {
	host  int64
	port  int
	proto string
}

// hourBucket returns the hour-of-week bucket (weekday*24 + hour, Sunday = 0) of t in loc.
func hourBucket(t time.Time, loc *time.Location) int {
	l := t.In(loc)
	return int(l.Weekday())*24 + l.Hour()
}

func obsHash(sv *model.ServiceResult, title string, status int, tls bool, techs []string) string {
	cert := ""
	if sv.TLS != nil {
		cert = sv.TLS.SHA256
	}
	h := sha256.Sum256([]byte(strings.Join([]string{sv.State, sv.Name, sv.Product, sv.Version, title, itoa(status), fmt.Sprint(tls), strings.Join(techs, ","), cert}, "\x1f")))
	return hex.EncodeToString(h[:8])
}

const hostUpsert = `INSERT INTO hosts AS h (ip, hostnames, scope_ids, status, first_seen, last_seen, last_up, os_guess, mac, vendor, source,
	consecutive_misses, obs_total, obs_up, stability, last_run_id)
SELECT d.ip, d.hostnames, d.scope_ids, CASE WHEN d.up THEN 'up' ELSE 'unknown' END, d.at, d.at, CASE WHEN d.up THEN d.at END,
	d.os_guess, d.mac, d.vendor, d.source, CASE WHEN d.up THEN 0 ELSE 1 END, 1, CASE WHEN d.up THEN 1 ELSE 0 END,
	CASE WHEN d.up THEN 1 ELSE 0 END, d.run_id
FROM jsonb_to_recordset($1::jsonb) AS d(ip inet, hostnames text[], scope_ids bigint[], up boolean, at timestamptz, os_guess text, mac text,
	vendor text, source text, run_id bigint)
ON CONFLICT (ip) DO UPDATE SET
	-- observed fields: an analyst override wins, the new observed value is recorded beside it
	hostnames = CASE WHEN h.overrides ? 'hostnames' OR cardinality(EXCLUDED.hostnames) = 0 THEN h.hostnames ELSE EXCLUDED.hostnames END,
	os_guess = CASE WHEN h.overrides ? 'os_guess' OR EXCLUDED.os_guess = '' THEN h.os_guess ELSE EXCLUDED.os_guess END,
	overrides = czujka_observed(czujka_observed(h.overrides, 'hostnames', to_jsonb(EXCLUDED.hostnames), cardinality(EXCLUDED.hostnames) > 0),
		'os_guess', to_jsonb(EXCLUDED.os_guess), EXCLUDED.os_guess <> ''),
	scope_ids = EXCLUDED.scope_ids,
	mac = CASE WHEN EXCLUDED.mac <> '' THEN EXCLUDED.mac ELSE h.mac END,
	vendor = CASE WHEN EXCLUDED.mac <> '' OR EXCLUDED.vendor <> '' THEN EXCLUDED.vendor ELSE h.vendor END, -- an observed MAC brings its vendor, even none
	last_seen = GREATEST(h.last_seen, EXCLUDED.last_seen),
	last_up = COALESCE(GREATEST(h.last_up, EXCLUDED.last_up), h.last_up, EXCLUDED.last_up),
	status = CASE WHEN EXCLUDED.status = 'up' THEN 'up' WHEN h.status = 'up' THEN 'unstable' ELSE h.status END,
	consecutive_misses = CASE WHEN EXCLUDED.status = 'up' THEN 0 ELSE h.consecutive_misses + 1 END,
	obs_total = h.obs_total + 1,
	obs_up = h.obs_up + EXCLUDED.obs_up,
	stability = (h.obs_up + EXCLUDED.obs_up)::float8 / (h.obs_total + 1),
	last_run_id = EXCLUDED.last_run_id
	-- label, owner, criticality, note, tags are analyst-owned: never written here
RETURNING h.id, host(h.ip)`

const serviceUpsert = `INSERT INTO services AS s (host_id, ip, hostname, port, proto, state, name, product, version, banner, confidence, tls, title,
	http_status, url, technologies, tech_names, classes, first_seen, last_seen, obs_hash, last_run_id, cert_not_after)
SELECT d.host_id, d.ip, d.hostname, d.port, d.proto, d.state, d.name, d.product, d.version, d.banner, d.confidence, d.tls, d.title,
	d.http_status, d.url, d.technologies, d.tech_names, d.classes, d.at, d.at, d.obs_hash, d.run_id, d.cert_not_after
FROM jsonb_to_recordset($1::jsonb) AS d(host_id bigint, ip inet, hostname text, port int, proto text, state text, name text, product text,
	version text, banner text, confidence float8, tls boolean, title text, http_status int, url text, technologies jsonb, tech_names text[],
	classes text[], at timestamptz, obs_hash text, run_id bigint, cert_not_after timestamptz)
ON CONFLICT (host_id, port, proto) DO UPDATE SET
	ip = EXCLUDED.ip,
	hostname = CASE WHEN EXCLUDED.hostname <> '' THEN EXCLUDED.hostname ELSE s.hostname END,
	state = EXCLUDED.state,
	-- observed fields: an analyst override wins, the new observed value is recorded beside it
	name = CASE WHEN s.overrides ? 'name' OR EXCLUDED.name = '' THEN s.name ELSE EXCLUDED.name END,
	product = CASE WHEN s.overrides ? 'product' OR EXCLUDED.product = '' THEN s.product ELSE EXCLUDED.product END,
	version = CASE WHEN s.overrides ? 'version' OR (EXCLUDED.version = '' AND EXCLUDED.product = '') THEN s.version ELSE EXCLUDED.version END,
	classes = CASE WHEN s.overrides ? 'classes' OR (EXCLUDED.obs_hash = '' AND cardinality(EXCLUDED.classes) = 0) THEN s.classes ELSE EXCLUDED.classes END,
	overrides = czujka_observed(czujka_observed(czujka_observed(czujka_observed(s.overrides,
		'name', to_jsonb(EXCLUDED.name)), 'product', to_jsonb(EXCLUDED.product)), 'version', to_jsonb(EXCLUDED.version)),
		'classes', to_jsonb(EXCLUDED.classes)),
	-- obs_hash '' marks a partial result (HostResult.Interim): a field it has not described yet keeps the known value
	banner = CASE WHEN EXCLUDED.obs_hash = '' AND EXCLUDED.banner = '' THEN s.banner ELSE EXCLUDED.banner END,
	confidence = EXCLUDED.confidence, tls = EXCLUDED.tls OR (EXCLUDED.obs_hash = '' AND s.tls),
	title = CASE WHEN EXCLUDED.obs_hash = '' AND EXCLUDED.http_status = 0 THEN s.title ELSE EXCLUDED.title END,
	http_status = CASE WHEN EXCLUDED.obs_hash = '' AND EXCLUDED.http_status = 0 THEN s.http_status ELSE EXCLUDED.http_status END,
	url = CASE WHEN EXCLUDED.obs_hash = '' AND EXCLUDED.url = '' THEN s.url ELSE EXCLUDED.url END,
	technologies = CASE WHEN EXCLUDED.obs_hash = '' AND jsonb_array_length(EXCLUDED.technologies) = 0 THEN s.technologies ELSE EXCLUDED.technologies END,
	tech_names = CASE WHEN EXCLUDED.obs_hash = '' AND cardinality(EXCLUDED.tech_names) = 0 THEN s.tech_names ELSE EXCLUDED.tech_names END,
	cert_not_after = CASE WHEN EXCLUDED.obs_hash = '' AND EXCLUDED.cert_not_after IS NULL THEN s.cert_not_after ELSE EXCLUDED.cert_not_after END,
	last_seen = GREATEST(s.last_seen, EXCLUDED.last_seen),
	-- a change is a final result that differs from the last final one; a service first stored by a partial result has obs_hash ''
	last_changed = CASE WHEN EXCLUDED.obs_hash = '' OR s.obs_hash = '' OR s.obs_hash = EXCLUDED.obs_hash THEN s.last_changed ELSE EXCLUDED.last_seen END,
	obs_hash = CASE WHEN EXCLUDED.obs_hash = '' THEN s.obs_hash ELSE EXCLUDED.obs_hash END,
	last_run_id = EXCLUDED.last_run_id
	-- note, tags, interest, group_key are not written here
RETURNING s.id, s.host_id, s.port, s.proto`

// IngestHosts writes a batch of host results in one transaction: upsert hosts
// and services, insert observations, update the availability histogram and
// the technologies. It never overwrites an overridden field and never touches
// analyst-owned fields (docs/ARCHITECTURE.md §4.7).
func (s *Store) IngestHosts(ctx context.Context, results []model.HostResult, opt SinkOptions) error {
	if len(results) == 0 {
		return nil
	}
	if opt.Source == "" {
		opt.Source = "scan"
	}
	scopes, err := s.scopeIndex(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	// One row per address: a later result of the same batch replaces an earlier one.
	byIP := map[string]*model.HostResult{}
	order := make([]string, 0, len(results))
	for i := range results {
		r := &results[i]
		addr, err := netip.ParseAddr(strings.TrimSpace(r.IP))
		if err != nil {
			continue // not an address: nothing to store
		}
		key := addr.Unmap().String()
		if _, ok := byIP[key]; !ok {
			order = append(order, key)
		}
		byIP[key] = r
	}
	if len(order) == 0 {
		return nil
	}
	sort.Strings(order) // stable lock order
	return s.Tx(ctx, func(tx *Store) error { return tx.ingest(ctx, byIP, order, scopes, now, opt) })
}

// prevObs is the observation of a host that the same run already stored (a
// chunk reported again, a retry pass, a resumed run that probes the address again).
type prevObs struct {
	up bool
	at time.Time
}

// runRepeats returns, by address, the observations that the runs of the
// results already stored. One run keeps one observation per host
// (analyze.ObservationKey): a repeat never adds a second row, a second
// histogram count or a second obs_total.
func (s *Store) runRepeats(ctx context.Context, byIP map[string]*model.HostResult, order []string) (map[string]prevObs, error) {
	type key struct {
		IP    string `json:"ip"`
		RunID int64  `json:"run_id"`
	}
	keys := make([]key, 0, len(order))
	for _, ip := range order {
		if r := byIP[ip]; r.RunID != 0 {
			keys = append(keys, key{ip, r.RunID})
		}
	}
	out := map[string]prevObs{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `SELECT host(h.ip), bool_or(o.up), min(o.at) FROM jsonb_to_recordset($1::jsonb) AS d(ip inet, run_id bigint)
		JOIN hosts h ON h.ip = d.ip JOIN host_observations o ON o.host_id = h.id AND o.run_id = d.run_id GROUP BY h.ip`, js(keys))
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var p prevObs
		if err := rows.Scan(&ip, &p.up, &p.at); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.Unmap().String()
		}
		out[ip] = p
	}
	return out, mapErr(rows.Err())
}

func (tx *Store) ingest(ctx context.Context, byIP map[string]*model.HostResult, order []string, scopes *scopeMatcher, now time.Time, opt SinkOptions) error {
	repeats, err := tx.runRepeats(ctx, byIP, order)
	if err != nil {
		return err
	}
	if len(repeats) > 0 {
		// A repeat that answers nothing adds nothing: the run already has its observation.
		kept := order[:0]
		for _, ip := range order {
			if _, ok := repeats[ip]; ok && !byIP[ip].Up {
				continue
			}
			kept = append(kept, ip)
		}
		order = kept
		if len(order) == 0 {
			return nil
		}
	}

	hostsIn := make([]hostIn, 0, len(order))
	for _, ip := range order {
		r := byIP[ip]
		if r.ObservedAt.IsZero() {
			r.ObservedAt = now
		}
		addr, _ := netip.ParseAddr(ip)
		hostsIn = append(hostsIn, hostIn{IP: ip, Hostnames: nonNil(r.Hostnames), ScopeIDs: scopes.match(addr, r.Hostnames), Up: r.Up,
			At: r.ObservedAt.UTC(), OSGuess: r.OSGuess, MAC: r.MAC, Vendor: model.VendorForMAC(r.MAC, r.Vendor), Source: opt.Source, RunID: r.RunID})
	}

	{
		// 1. hosts
		rows, err := tx.db.Query(ctx, hostUpsert, js(hostsIn))
		if err != nil {
			return mapErr(err)
		}
		hostID := map[string]int64{}
		for rows.Next() {
			var id int64
			var ip string
			if err := rows.Scan(&id, &ip); err != nil {
				rows.Close()
				return err
			}
			hostID[ip] = id
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return mapErr(err)
		}

		// 2. host observations and the hour-of-week histogram
		hostObs := make([]hostObsIn, 0, len(order))
		type presence struct {
			HostID int64 `json:"host_id"`
			Up     bool  `json:"up"`
			RunID  int64 `json:"run_id"`
			// the port scan of the host did not finish: unlisted services are unknown, not gone
			PortsUnknown bool `json:"ports_unknown"`
			// the services this result lists (set after the service upsert)
			Listed []int64 `json:"listed"`
		}
		var present []presence
		hostIDs := make([]int64, 0, len(order))
		var svcIn []serviceIn
		type pending struct {
			key svcKey
			res *model.ServiceResult
			in  *serviceIn
		}
		var pend []pending
		type closedPort struct {
			HostID int64  `json:"host_id"`
			Port   int    `json:"port"`
			Proto  string `json:"proto"`
		}
		var closed []closedPort
		type repeatIn struct {
			HostID int64   `json:"host_id"`
			RunID  int64   `json:"run_id"`
			WasUp  bool    `json:"was_up"`
			Bucket int     `json:"bucket"`
			RTTMs  float64 `json:"rtt_ms"`
			Reason string  `json:"reason"`
		}
		var repeatFix []repeatIn

		for _, ip := range order {
			r := byIP[ip]
			id, ok := hostID[ip]
			if !ok {
				// PostgreSQL may print an IPv6 address in another form; look it up by value.
				for k, v := range hostID {
					if a, err := netip.ParseAddr(k); err == nil && a.String() == ip {
						id, ok = v, true
						break
					}
				}
				if !ok {
					return fmt.Errorf("store: host %s was not returned by the upsert", ip)
				}
			}
			hostIDs = append(hostIDs, id)
			if p, ok := repeats[ip]; ok {
				repeatFix = append(repeatFix, repeatIn{HostID: id, RunID: r.RunID, WasUp: p.up, Bucket: hourBucket(p.at, tx.loc), RTTMs: r.RTTMs, Reason: obsReason(r)})
			} else {
				o := hostObsIn{HostID: id, RunID: r.RunID, At: r.ObservedAt.UTC(), Up: r.Up, RTTMs: r.RTTMs, Attempts: max(r.Attempts, 1), Reason: obsReason(r),
					Bucket: hourBucket(r.ObservedAt, tx.loc)}
				if r.Up {
					o.UpN = 1
				} else {
					o.DownN = 1
				}
				hostObs = append(hostObs, o)
			}
			present = append(present, presence{HostID: id, Up: r.Up, RunID: r.RunID, PortsUnknown: r.HasUnknownPorts(), Listed: []int64{}})

			seen := map[svcKey]bool{}
			for i := range r.Services {
				sv := &r.Services[i]
				proto := strings.ToLower(sv.Proto)
				if proto == "" {
					proto = "tcp"
				}
				key := svcKey{id, sv.Port, proto}
				if sv.Port <= 0 || sv.Port > 65535 || seen[key] {
					continue
				}
				seen[key] = true
				state := strings.ToLower(sv.State)
				if state == "" {
					state = "open"
				}
				if state != "open" && state != "filtered" {
					closed = append(closed, closedPort{id, sv.Port, proto})
					continue
				}
				in := serviceIn{HostID: id, IP: ip, Port: sv.Port, Proto: proto, State: state, Name: sv.Name, Product: sv.Product, Version: sv.Version,
					Banner: sv.Banner, Confidence: sv.Confidence, TLS: sv.Tunnel == "ssl" || sv.TLS != nil, Technologies: nonNil(sv.Technologies),
					TechNames: []string{}, Classes: nonNil(sv.Classes), At: r.ObservedAt.UTC(), RunID: r.RunID}
				if len(r.Hostnames) > 0 {
					in.Hostname = r.Hostnames[0]
				}
				if sv.HTTP != nil {
					in.Title, in.HTTPStatus, in.URL = sv.HTTP.Title, sv.HTTP.Status, sv.HTTP.FinalURL
					if in.URL == "" {
						in.URL = sv.HTTP.URL
					}
					if sv.HTTP.Scheme == "https" {
						in.TLS = true
					}
					if in.Hostname == "" && sv.HTTP.Host != "" {
						if _, err := netip.ParseAddr(sv.HTTP.Host); err != nil {
							in.Hostname = sv.HTTP.Host
						}
					}
				}
				if sv.TLS != nil && !sv.TLS.NotAfter.IsZero() {
					t := sv.TLS.NotAfter.UTC()
					in.CertNotAfter = &t
				}
				tseen := map[string]bool{}
				for _, t := range sv.Technologies {
					if t.Name != "" && !tseen[t.Name] {
						tseen[t.Name] = true
						in.TechNames = append(in.TechNames, t.Name)
					}
				}
				sort.Strings(in.TechNames)
				in.ObsHash = obsHash(sv, in.Title, in.HTTPStatus, in.TLS, in.TechNames)
				if r.Interim {
					in.ObsHash = "" // a partial result: the service keeps its change hash and known fields (serviceUpsert)
				}
				svcIn = append(svcIn, in)
				pend = append(pend, pending{key: key, res: sv, in: &svcIn[len(svcIn)-1]})
			}
		}
		// pend[i].in pointed into a growing slice; rebind after the loop.
		for i := range pend {
			pend[i].in = &svcIn[i]
		}

		if len(hostObs) > 0 {
			if _, err := tx.db.Exec(ctx, `WITH d AS (SELECT * FROM jsonb_to_recordset($1::jsonb) AS d(host_id bigint, run_id bigint, at timestamptz, up boolean,
				rtt_ms float8, attempts int, reason text, bucket int, up_n int, down_n int)),
			ins AS (INSERT INTO host_observations (host_id, run_id, at, up, rtt_ms, attempts, reason)
				SELECT host_id, run_id, at, up, rtt_ms, attempts, reason FROM d)
			INSERT INTO host_availability (host_id, bucket, up, down)
			SELECT host_id, bucket, sum(up_n), sum(down_n) FROM d GROUP BY host_id, bucket
			ON CONFLICT (host_id, bucket) DO UPDATE SET up = host_availability.up + EXCLUDED.up, down = host_availability.down + EXCLUDED.down`, js(hostObs)); err != nil {
				return mapErr(err)
			}
		}

		if len(repeatFix) > 0 {
			// The host upsert counted the repeat as one more observation: undo
			// that, and turn a stored miss of this run into an answer.
			// A repeat is always an answer (a repeat without one was dropped
			// above). Its reason replaces the stored one: the final result of a
			// host replaces its partial result ("ports-unknown").
			if _, err := tx.db.Exec(ctx, `WITH d AS (SELECT * FROM jsonb_to_recordset($1::jsonb) AS d(host_id bigint, run_id bigint, was_up boolean, bucket int, rtt_ms float8, reason text)),
				h AS (UPDATE hosts x SET obs_total = GREATEST(x.obs_total - 1, 1), obs_up = GREATEST(x.obs_up - CASE WHEN d.was_up THEN 1 ELSE 0 END, 0),
					stability = GREATEST(x.obs_up - CASE WHEN d.was_up THEN 1 ELSE 0 END, 0)::float8 / GREATEST(x.obs_total - 1, 1)
					FROM d WHERE x.id = d.host_id),
				o AS (UPDATE host_observations x SET up = true, rtt_ms = CASE WHEN d.was_up THEN x.rtt_ms ELSE d.rtt_ms END, reason = d.reason
					FROM d WHERE x.host_id = d.host_id AND x.run_id = d.run_id)
				UPDATE host_availability x SET up = x.up + 1, down = GREATEST(x.down - 1, 0) FROM d
				WHERE NOT d.was_up AND x.host_id = d.host_id AND x.bucket = d.bucket`, js(repeatFix)); err != nil {
				return mapErr(err)
			}
		}

		// 3. services
		svcID := map[svcKey]int64{}
		if len(svcIn) > 0 {
			rows, err := tx.db.Query(ctx, serviceUpsert, js(svcIn))
			if err != nil {
				return mapErr(err)
			}
			for rows.Next() {
				var id, host int64
				var port int
				var proto string
				if err := rows.Scan(&id, &host, &port, &proto); err != nil {
					rows.Close()
					return err
				}
				svcID[svcKey{host, port, proto}] = id
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return mapErr(err)
			}
		}
		for i := range present {
			for k, id := range svcID {
				if k.host == present[i].HostID {
					present[i].Listed = append(present[i].Listed, id)
				}
			}
		}
		if len(closed) > 0 {
			if _, err := tx.db.Exec(ctx, `UPDATE services s SET state = 'gone' FROM jsonb_to_recordset($1::jsonb) AS d(host_id bigint, port int, proto text)
				WHERE s.host_id = d.host_id AND s.port = d.port AND s.proto = d.proto AND s.state <> 'gone'`, js(closed)); err != nil {
				return mapErr(err)
			}
		}
		if !opt.MarkMissing {
			// Partial data (an import, a manual entry, a re-probe): a host that is
			// down has services in an unknown state; an answering host keeps the
			// services the data does not list (absence is not proof).
			if _, err := tx.db.Exec(ctx, `UPDATE services s SET state = 'unknown'
				FROM jsonb_to_recordset($1::jsonb) AS d(host_id bigint, up boolean, run_id bigint)
				WHERE s.host_id = d.host_id AND NOT d.up AND s.state IN ('open', 'filtered')`, js(present)); err != nil {
				return mapErr(err)
			}
		}
		if opt.MarkMissing {
			// A complete result lists every open service of its host: a service
			// it does not list is gone, also one that only a partial result of
			// this run listed.
			if _, err := tx.db.Exec(ctx, `UPDATE services s SET state = CASE WHEN d.up THEN 'gone' ELSE 'unknown' END
				FROM jsonb_to_recordset($1::jsonb) AS d(host_id bigint, up boolean, run_id bigint, ports_unknown boolean, listed bigint[])
				WHERE s.host_id = d.host_id AND NOT (s.id = ANY(d.listed)) AND NOT d.ports_unknown
				AND ((d.up AND s.state IN ('open', 'filtered', 'unknown')) OR (NOT d.up AND s.state IN ('open', 'filtered')))`, js(present)); err != nil {
				return mapErr(err)
			}
			// The run keeps no observation of a service its complete result
			// does not list (one that only a partial result of the run listed).
			if _, err := tx.db.Exec(ctx, `DELETE FROM service_observations o USING jsonb_to_recordset($1::jsonb) AS d(host_id bigint, run_id bigint, ports_unknown boolean, listed bigint[])
				WHERE o.host_id = d.host_id AND o.run_id = d.run_id AND NOT d.ports_unknown AND NOT (o.service_id = ANY(d.listed))`, js(present)); err != nil {
				return mapErr(err)
			}
		}

		// 4. service observations (sensitive parts encrypted) and technologies
		if len(pend) > 0 {
			obs := make([]obsIn, 0, len(pend))
			var techs []techIn
			ids := make([]int64, 0, len(pend))
			for _, p := range pend {
				id, ok := svcID[p.key]
				if !ok {
					return fmt.Errorf("store: service %d/%s of host %d was not returned by the upsert", p.key.port, p.key.proto, p.key.host)
				}
				if p.in.ObsHash != "" || len(p.res.Technologies) > 0 {
					ids = append(ids, id) // a partial result without technologies keeps the known ones
				}
				clean, sec, has := splitSecrets(*p.res)
				clean.Proto, clean.State = p.in.Proto, p.in.State
				o := obsIn{ServiceID: id, HostID: p.key.host, RunID: p.in.RunID, At: p.in.At, State: p.in.State, Name: p.res.Name, Product: p.res.Product,
					Version: p.res.Version, Title: p.in.Title, HTTPStatus: p.in.HTTPStatus, TLS: p.in.TLS, Result: clean}
				if has {
					if o.Secret, err = tx.kr.Encrypt(js(sec), obsAD(id, p.in.RunID)); err != nil {
						return err
					}
				}
				obs = append(obs, o)
				tseen := map[string]bool{}
				for _, t := range p.res.Technologies {
					if t.Name == "" || tseen[t.Name] {
						continue
					}
					tseen[t.Name] = true
					techs = append(techs, techIn{id, p.key.host, t.Name, t.Category, t.Version, t.Confidence, t.CPE})
				}
			}
			// One observation per service and run: a later result of the run
			// (the final result after a partial one, a retried chunk) replaces it.
			if _, err := tx.db.Exec(ctx, `DELETE FROM service_observations o USING jsonb_to_recordset($1::jsonb) AS d(service_id bigint, run_id bigint)
				WHERE o.service_id = d.service_id AND o.run_id = d.run_id`, js(obs)); err != nil {
				return mapErr(err)
			}
			if _, err := tx.db.Exec(ctx, `INSERT INTO service_observations (service_id, host_id, run_id, at, state, name, product, version, title, http_status, tls, result, secret)
				SELECT d.service_id, d.host_id, d.run_id, d.at, d.state, d.name, d.product, d.version, d.title, d.http_status, d.tls, d.result, d.secret
				FROM jsonb_to_recordset($1::jsonb) AS d(service_id bigint, host_id bigint, run_id bigint, at timestamptz, state text, name text, product text,
					version text, title text, http_status int, tls boolean, result jsonb, secret text)`, js(obs)); err != nil {
				return mapErr(err)
			}
			if _, err := tx.db.Exec(ctx, `DELETE FROM technologies WHERE service_id = ANY($1)`, ids); err != nil {
				return mapErr(err)
			}
			if len(techs) > 0 {
				if _, err := tx.db.Exec(ctx, `INSERT INTO technologies (service_id, host_id, name, category, version, confidence, cpe)
					SELECT d.service_id, d.host_id, d.name, d.category, d.version, d.confidence, d.cpe
					FROM jsonb_to_recordset($1::jsonb) AS d(service_id bigint, host_id bigint, name text, category text, version text, confidence float8, cpe text)
					ON CONFLICT (service_id, name) DO NOTHING`, js(techs)); err != nil {
					return mapErr(err)
				}
			}
		}

		// 5. per-host aggregates used by the list filters
		return tx.refreshHostAggregates(ctx, hostIDs)
	}
}

// refreshHostAggregates recomputes service_count, open_ports and technologies of the given hosts.
func (s *Store) refreshHostAggregates(ctx context.Context, hostIDs []int64) error {
	if len(hostIDs) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `UPDATE hosts h SET service_count = a.cnt, open_ports = a.ports, technologies = a.techs
		FROM (SELECT x.host_id,
				count(s.id) FILTER (WHERE s.state = 'open')::int AS cnt,
				COALESCE(array_agg(DISTINCT s.port ORDER BY s.port) FILTER (WHERE s.state = 'open'), '{}') AS ports,
				COALESCE((SELECT array_agg(DISTINCT t.name ORDER BY t.name) FROM technologies t JOIN services ts ON ts.id = t.service_id
					WHERE t.host_id = x.host_id AND ts.state = 'open'), '{}') AS techs
			FROM unnest($1::bigint[]) AS x(host_id) LEFT JOIN services s ON s.host_id = x.host_id GROUP BY x.host_id) a
		WHERE h.id = a.host_id`, hostIDs)
	return mapErr(err)
}

// obsReason is the reason stored with a host observation. A result whose port
// scan did not finish (a partial result, a timed-out port scan) says so, so
// that the run rebuilt from the store (EachRunHost) is not taken as complete.
func obsReason(r *model.HostResult) string {
	if r.Reason == "" && r.HasUnknownPorts() {
		return model.ReasonPortsUnknown
	}
	return r.Reason
}
