package store

import (
	"context"
	"strconv"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// RunHost is one host as one run saw it, with the store ids that the analysis needs.
type RunHost struct {
	HostID    int64   `json:"host_id"`
	ScopeIDs  []int64 `json:"scope_ids"`
	ObsStatus string  `json:"obs_status"` // status that the stability model gave the host at this run; "" before the analysis
	model.HostResult
	ServiceIDs map[string]int64 `json:"-"` // "port/proto" → service id
}

// ServiceKey is the key of RunHost.ServiceIDs.
func ServiceKey(port int, proto string) string {
	if proto == "" {
		proto = "tcp"
	}
	return strconv.Itoa(port) + "/" + proto
}

// EachRunHost rebuilds the host results of one run from the stored
// observations and streams them in host-id order. Only hosts that the run
// probed are returned: an address the run did not reach has no observation.
func (s *Store) EachRunHost(ctx context.Context, runID int64, fn func(*RunHost) error) error {
	const batch = 500
	lastID := int64(0)
	for {
		hosts, err := jsonRows[RunHost](ctx, s.db, wrapJSON(`SELECT DISTINCT ON (h.id) h.id AS host_id, h.scope_ids, o.status AS obs_status, o.run_id, host(h.ip) AS ip,
			h.hostnames, o.up, o.reason, o.rtt_ms, o.attempts, h.mac, h.vendor, h.os_guess, o.at AS observed_at
			FROM host_observations o JOIN hosts h ON h.id = o.host_id WHERE o.run_id = $1 AND h.id > $2 ORDER BY h.id, o.at DESC LIMIT `+itoa(batch)), runID, lastID)
		if err != nil {
			return err
		}
		if len(hosts) == 0 {
			return nil
		}
		pairs := make(map[int64]int64, len(hosts))
		for _, h := range hosts {
			pairs[h.HostID] = runID
		}
		svcs, ids, err := s.RunServiceResults(ctx, pairs)
		if err != nil {
			return err
		}
		for i := range hosts {
			h := &hosts[i]
			h.Services = nonNil(svcs[h.HostID])
			h.Hostnames = nonNil(h.Hostnames)
			h.ServiceIDs = ids[h.HostID]
			if err := fn(h); err != nil {
				return err
			}
		}
		lastID = hosts[len(hosts)-1].HostID
	}
}

// EachRunResult streams the HostResult records of one run (for exports).
func (s *Store) EachRunResult(ctx context.Context, runID int64, fn func(*model.HostResult) error) error {
	return s.EachRunHost(ctx, runID, func(h *RunHost) error { return fn(&h.HostResult) })
}

// RunServiceResults returns the stored service results of (host, run) pairs,
// decrypted, with the service ids. pairs maps a host id to a run id.
func (s *Store) RunServiceResults(ctx context.Context, pairs map[int64]int64) (map[int64][]model.ServiceResult, map[int64]map[string]int64, error) {
	out := map[int64][]model.ServiceResult{}
	ids := map[int64]map[string]int64{}
	if len(pairs) == 0 {
		return out, ids, nil
	}
	type pair struct {
		HostID int64 `json:"host_id"`
		RunID  int64 `json:"run_id"`
	}
	in := make([]pair, 0, len(pairs))
	for h, r := range pairs {
		in = append(in, pair{h, r})
	}
	err := eachJSON(ctx, s.db, wrapJSON("SELECT DISTINCT ON (o.service_id) "+obsCols+", s.proto FROM "+obsFrom+
		" JOIN jsonb_to_recordset($1::jsonb) AS d(host_id bigint, run_id bigint) ON d.host_id = o.host_id AND d.run_id = o.run_id"+
		" ORDER BY o.service_id, o.at DESC, o.id DESC"), []any{js(in)}, func(o *ObservationRow) error {
		if err := s.postObs(o); err != nil {
			return err
		}
		if o.Result.Port == 0 {
			o.Result.Port = o.Port
		}
		out[o.HostID] = append(out[o.HostID], o.Result)
		if ids[o.HostID] == nil {
			ids[o.HostID] = map[string]int64{}
		}
		ids[o.HostID][ServiceKey(o.Result.Port, o.Result.Proto)] = o.ServiceID
		return nil
	})
	return out, ids, err
}

// PrevHost is what the inventory knew about a host before a run.
type PrevHost struct {
	HostID     int64     `json:"host_id"`
	RunID      int64     `json:"run_id"` // run of the newest earlier observation
	Up         bool      `json:"up"`
	Status     string    `json:"status"` // model status at that observation; "" when it was never analysed
	At         time.Time `json:"at"`
	ServiceRun int64     `json:"service_run"` // newest earlier run in which the host answered; 0 = never
}

// PrevHosts returns, for each given host, its newest observation in a run before runID.
// A host without an earlier observation is not in the map.
func (s *Store) PrevHosts(ctx context.Context, runID int64, hostIDs []int64) (map[int64]PrevHost, error) {
	out := map[int64]PrevHost{}
	if len(hostIDs) == 0 {
		return out, nil
	}
	err := eachJSON(ctx, s.db, wrapJSON(`SELECT p.host_id, p.run_id, p.up, p.status, p.at, COALESCE(u.run_id, 0) AS service_run
		FROM (SELECT DISTINCT ON (host_id) host_id, run_id, up, status, at FROM host_observations
			WHERE host_id = ANY($1) AND run_id < $2 ORDER BY host_id, run_id DESC, at DESC) p
		LEFT JOIN (SELECT host_id, max(run_id) AS run_id FROM host_observations WHERE host_id = ANY($1) AND run_id < $2 AND up GROUP BY host_id) u
			ON u.host_id = p.host_id`), []any{hostIDs, runID}, func(p *PrevHost) error {
		out[p.HostID] = *p
		return nil
	})
	return out, err
}

// ObsStatus is the model status of one host at one run.
type ObsStatus struct {
	HostID int64  `json:"host_id"`
	Status string `json:"status"`
}

// SetObservationStatus records the status that the stability model gave each host at a run.
func (s *Store) SetObservationStatus(ctx context.Context, runID int64, rows []ObsStatus) error {
	if len(rows) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `UPDATE host_observations o SET status = d.status
		FROM jsonb_to_recordset($2::jsonb) AS d(host_id bigint, status text) WHERE o.run_id = $1 AND o.host_id = d.host_id`, runID, js(rows))
	return mapErr(err)
}

// ServiceGroup is the grouping key of one service.
type ServiceGroupKey struct {
	ID       int64  `json:"id"`
	GroupKey string `json:"group_key"`
}

// UpdateServiceGroups stores new grouping keys without touching the interest score.
func (s *Store) UpdateServiceGroups(ctx context.Context, rows []ServiceGroupKey) error {
	if len(rows) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `UPDATE services s SET group_key = d.group_key
		FROM jsonb_to_recordset($1::jsonb) AS d(id bigint, group_key text) WHERE s.id = d.id AND s.group_key IS DISTINCT FROM d.group_key`, js(rows))
	return mapErr(err)
}

// OpenServiceGroups returns the grouping key of every open service (service id → key).
func (s *Store) OpenServiceGroups(ctx context.Context) (map[int64]string, error) {
	rows, err := s.db.Query(ctx, `SELECT id, group_key FROM services WHERE state = 'open'`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var key string
		if err := rows.Scan(&id, &key); err != nil {
			return nil, err
		}
		out[id] = key
	}
	return out, rows.Err()
}

// HostNames returns the names of every host that has one (host id → names).
func (s *Store) HostNames(ctx context.Context) (map[int64][]string, error) {
	rows, err := s.db.Query(ctx, `SELECT id, hostnames FROM hosts WHERE cardinality(hostnames) > 0`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var names []string
		if err := rows.Scan(&id, &names); err != nil {
			return nil, err
		}
		out[id] = names
	}
	return out, rows.Err()
}

// MarkServicesGone sets services to "gone" after the analysis of an imported
// run found that a file no longer lists them. Scan runs do this at ingest.
func (s *Store) MarkServicesGone(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `UPDATE services SET state = 'gone' WHERE id = ANY($1) AND state IN ('open', 'filtered', 'unknown')`, ids)
	return mapErr(err)
}

// KnownIPs reports which of the given addresses the inventory already holds.
func (s *Store) KnownIPs(ctx context.Context, ips []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(ips) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `SELECT host(ip) FROM hosts WHERE ip = ANY($1::inet[])`, ips)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = true
	}
	return out, rows.Err()
}

// ---------- scheduler seam ----------

// ScheduledProfiles returns the enabled profiles whose schedule is enabled.
func (s *Store) ScheduledProfiles(ctx context.Context) ([]model.ScanProfile, error) {
	return jsonRows[model.ScanProfile](ctx, s.db, "SELECT "+profileJSON+` FROM scan_profiles p
		WHERE p.enabled AND COALESCE((p.config->'schedule'->>'enabled')::boolean, false) ORDER BY p.id`)
}

// DueProfiles returns the scheduled profiles whose next_run_at has passed and
// that have no active run. A profile without next_run_at is not due: the
// scheduler computes the first start with SetProfileNextRun.
func (s *Store) DueProfiles(ctx context.Context, now time.Time) ([]model.ScanProfile, error) {
	return jsonRows[model.ScanProfile](ctx, s.db, "SELECT "+profileJSON+` FROM scan_profiles p
		WHERE p.enabled AND COALESCE((p.config->'schedule'->>'enabled')::boolean, false) AND p.next_run_at IS NOT NULL AND p.next_run_at <= $1
		AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.profile_id = p.id AND r.status IN ('queued', 'running', 'analyzing', 'paused'))
		ORDER BY p.next_run_at, p.id`, now)
}

// LastRunStart returns when the newest run of a profile started; nil when it never ran.
func (s *Store) LastRunStart(ctx context.Context, profileID int64) (*time.Time, error) {
	var t *time.Time
	err := s.db.QueryRow(ctx, `SELECT max(COALESCE(started_at, created_at)) FROM runs WHERE profile_id = $1`, profileID).Scan(&t)
	return t, mapErr(err)
}

// AddHostnames adds names to the known host with this address, unless an
// analyst set the hostnames by hand. changed is false when the host is
// unknown or already had every name.
func (s *Store) AddHostnames(ctx context.Context, ip string, names []string) (changed bool, err error) {
	tag, err := s.db.Exec(ctx, `UPDATE hosts SET hostnames = (SELECT array_agg(DISTINCT n ORDER BY n) FROM unnest(hostnames || $2::text[]) n)
		WHERE ip = $1::inet AND NOT (overrides ? 'hostnames') AND NOT (hostnames @> $2::text[])`, ip, names)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() > 0, nil
}

// WindowPausedRuns returns the runs that a closed scan window paused, with
// their resume_at, the earliest first.
func (s *Store) WindowPausedRuns(ctx context.Context) ([]model.ScanRun, error) {
	return jsonRows[model.ScanRun](ctx, s.db, wrapJSON("SELECT "+runCols+` FROM runs r
		WHERE r.status = 'paused' AND r.pause_reason = 'window_closed' ORDER BY r.resume_at NULLS LAST, r.id`))
}

// ---------- first start ----------

const keySeed = "seed"

// SeedDefaults stores what a new installation needs and nothing else: the
// default safety policy and one default scan profile without a scope. It runs
// once; a profile that an administrator deleted later is not created again.
func (s *Store) SeedDefaults(ctx context.Context) (created bool, err error) {
	err = s.Tx(ctx, func(tx *Store) error {
		var done struct {
			At time.Time `json:"at"`
		}
		if _, _, err := tx.getSetting(ctx, keySeed, &done); err == nil {
			return nil
		}
		var cur model.SafetyPolicy
		if _, _, err := tx.getSetting(ctx, keySafety, &cur); err != nil {
			if err := tx.putSetting(ctx, keySafety, DefaultSafetyPolicy(), ""); err != nil {
				return err
			}
		}
		var n int
		if err := tx.db.QueryRow(ctx, `SELECT count(*) FROM scan_profiles`).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := tx.CreateProfile(ctx, DefaultProfile()); err != nil {
				return err
			}
		}
		done.At = time.Now().UTC()
		created = true
		return tx.putSetting(ctx, keySeed, done, "")
	})
	return created, err
}

// DefaultProfile is the scan profile of a new installation: a light, safe
// discovery well under the caps of the default safety policy. It has no scope,
// so it sends nothing until an operator assigns one.
func DefaultProfile() model.ScanProfile {
	return model.ScanProfile{
		Name:             "Domyślny (bezpieczne rozpoznanie)",
		Description:      "Top 100 portów, wykrywanie usług, odcisk HTTP. Niskie limity ruchu. Przypisz zakres, aby uruchomić.",
		ScopeIDs:         []int64{},
		Ports:            "top-100",
		Discovery:        model.DiscoveryOpts{ICMPEcho: true, TCPSynPorts: []int{80, 443}, TCPAckPorts: []int{80}},
		ServiceDetection: true,
		VersionIntensity: 2,
		HTTP:             model.HTTPOpts{Enabled: true, MaxBodyBytes: 262144, TimeoutMs: 5000, MaxRedirects: 3, SignaturePaths: true, Favicon: true},
		Rate:             model.RateLimits{MaxPPS: 300, MaxParallelChunks: 2, MaxParallelHosts: 16, HTTPRPS: 10, PerHostConcurrency: 1},
		Chunking:         model.ChunkingOpts{Adaptive: true, InitialSize: 256, MinSize: 64, MaxSize: 4096, TargetSeconds: 60},
		Retry:            model.RetryOpts{UnstableRetries: 2, BackoffMs: 500},
		Schedule:         model.Schedule{Timezone: "Europe/Warsaw"},
		Enabled:          true,
	}
}
