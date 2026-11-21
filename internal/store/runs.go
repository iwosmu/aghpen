package store

import (
	"context"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// ---------- scan profiles ----------

const profileJSON = `p.config || jsonb_build_object('id', p.id, 'name', p.name, 'scope_ids', to_jsonb(p.scope_ids), 'enabled', p.enabled,
  'next_run_at', p.next_run_at, 'last_run_id', p.last_run_id, 'created_at', p.created_at, 'updated_at', p.updated_at)`

// ListProfiles returns a page of scan profiles.
func (s *Store) ListProfiles(ctx context.Context, o ListOpts) (model.Page[model.ScanProfile], error) {
	o = o.norm()
	w := &where{}
	if o.Q != "" {
		w.add("p.name ILIKE ?", like(o.Q))
	}
	page := model.Page[model.ScanProfile]{Limit: o.Limit, Offset: o.Offset}
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM scan_profiles p"+w.sql(), w.args...).Scan(&page.Total); err != nil {
		return page, mapErr(err)
	}
	order := orderBy(o.Sort, map[string]string{"id": "p.id", "name": "p.name", "next_run_at": "p.next_run_at", "updated_at": "p.updated_at"}, "p.name ASC", "p.id")
	items, err := jsonRows[model.ScanProfile](ctx, s.db, "SELECT "+profileJSON+" FROM scan_profiles p"+w.sql()+order+limitOffset(o), w.args...)
	page.Items = items
	return page, err
}

func limitOffset(o ListOpts) string {
	return " LIMIT " + itoa(o.Limit) + " OFFSET " + itoa(o.Offset)
}

// GetProfile returns one scan profile.
func (s *Store) GetProfile(ctx context.Context, id int64) (model.ScanProfile, error) {
	return jsonRow[model.ScanProfile](ctx, s.db, "SELECT "+profileJSON+" FROM scan_profiles p WHERE p.id = $1", id)
}

// CreateProfile inserts a scan profile.
func (s *Store) CreateProfile(ctx context.Context, p model.ScanProfile) (model.ScanProfile, error) {
	p.ScopeIDs = nonNil(p.ScopeIDs)
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO scan_profiles (name, scope_ids, config, enabled, next_run_at) VALUES ($1,$2,$3::jsonb,$4,$5) RETURNING id`,
		p.Name, p.ScopeIDs, js(p), p.Enabled, p.NextRunAt).Scan(&id)
	if err != nil {
		return p, mapErr(err)
	}
	return s.GetProfile(ctx, id)
}

// UpdateProfile stores a changed scan profile.
func (s *Store) UpdateProfile(ctx context.Context, p model.ScanProfile) (model.ScanProfile, error) {
	p.ScopeIDs = nonNil(p.ScopeIDs)
	tag, err := s.db.Exec(ctx, `UPDATE scan_profiles SET name = $2, scope_ids = $3, config = $4::jsonb, enabled = $5, next_run_at = $6, updated_at = now() WHERE id = $1`,
		p.ID, p.Name, p.ScopeIDs, js(p), p.Enabled, p.NextRunAt)
	if err != nil {
		return p, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return p, ErrNotFound
	}
	return s.GetProfile(ctx, p.ID)
}

// DeleteProfile removes a scan profile. Its runs stay, without a profile.
func (s *Store) DeleteProfile(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM scan_profiles WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetProfileNextRun stores the next scheduled start of a profile (used by the scheduler).
func (s *Store) SetProfileNextRun(ctx context.Context, id int64, at *time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE scan_profiles SET next_run_at = $2 WHERE id = $1`, id, at)
	return err
}

// SetProfileLastRun records the last run of a profile and folds its measured
// speed into the profile's moving average (0 leaves the average unchanged).
func (s *Store) SetProfileLastRun(ctx context.Context, id, runID int64, avgPPS float64) error {
	_, err := s.db.Exec(ctx, `UPDATE scan_profiles SET last_run_id = $2,
		measured_pps = CASE WHEN $3::float8 <= 0 THEN measured_pps WHEN measured_pps <= 0 THEN $3::float8 ELSE 0.5 * measured_pps + 0.5 * $3::float8 END
		WHERE id = $1`, id, runID, avgPPS)
	return err
}

// ProfileMeasuredPPS returns the speed measured in earlier runs of a profile; 0 when unknown.
func (s *Store) ProfileMeasuredPPS(ctx context.Context, id int64) (float64, error) {
	var v float64
	err := s.db.QueryRow(ctx, `SELECT measured_pps FROM scan_profiles WHERE id = $1`, id).Scan(&v)
	return v, mapErr(err)
}

// NextScheduledRun returns the earliest next_run_at of the enabled profiles.
func (s *Store) NextScheduledRun(ctx context.Context) (*time.Time, error) {
	var t *time.Time
	err := s.db.QueryRow(ctx, `SELECT min(next_run_at) FROM scan_profiles WHERE enabled AND next_run_at IS NOT NULL`).Scan(&t)
	return t, err
}

// ---------- runs ----------

const runCols = `r.id, r.profile_id, r.profile_name, r.status, r.pause_reason, r.trigger, r.created_by, r.created_at, r.started_at,
  r.finished_at, r.window_end, r.resume_at, r.stats, r.summary, r.error, r.import_file`

// ActiveStatuses are the run states that count as "active" for the one-run-per-profile rule.
var ActiveStatuses = []string{string(model.RunQueued), string(model.RunRunning), string(model.RunAnalyzing), string(model.RunPaused)}

// RunFilter are the filters of GET /runs.
type RunFilter struct {
	ListOpts
	ProfileID int64
	Status    []string
	Trigger   string
}

// ListRuns returns a page of runs, newest first by default.
func (s *Store) ListRuns(ctx context.Context, f RunFilter) (model.Page[model.ScanRun], error) {
	w := &where{}
	if f.ProfileID != 0 {
		w.add("r.profile_id = ?", f.ProfileID)
	}
	if len(f.Status) > 0 {
		w.add("r.status = ANY(?)", f.Status)
	}
	if f.Trigger != "" {
		w.add("r.trigger = ?", f.Trigger)
	}
	if f.Q != "" {
		w.add("r.profile_name ILIKE ? OR r.import_file ILIKE ?", like(f.Q), like(f.Q))
	}
	order := orderBy(f.Sort, map[string]string{"id": "r.id", "created_at": "r.created_at", "started_at": "r.started_at", "finished_at": "r.finished_at", "status": "r.status", "profile_name": "r.profile_name"}, "r.id DESC", "")
	return listPage[model.ScanRun](ctx, s.db, runCols, "runs r", w, order, f.ListOpts, nil)
}

// GetRun returns one run.
func (s *Store) GetRun(ctx context.Context, id int64) (model.ScanRun, error) {
	return jsonRow[model.ScanRun](ctx, s.db, wrapJSON("SELECT "+runCols+" FROM runs r WHERE r.id = $1"), id)
}

// CreateRun inserts a run. It returns ErrConflict when the profile already has an active run.
func (s *Store) CreateRun(ctx context.Context, r model.ScanRun) (model.ScanRun, error) {
	if r.Status == "" {
		r.Status = model.RunQueued
	}
	if r.Trigger == "" {
		r.Trigger = "manual"
	}
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO runs (profile_id, profile_name, status, pause_reason, trigger, created_by, started_at, window_end, stats, import_file)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10) RETURNING id`,
		r.ProfileID, r.ProfileName, string(r.Status), r.PauseReason, r.Trigger, r.CreatedBy, r.StartedAt, r.WindowEnd, js(r.Stats), r.ImportFile).Scan(&id)
	if err != nil {
		return r, mapErr(err)
	}
	return s.GetRun(ctx, id)
}

// SaveRun stores the mutable fields of a run: status, times, stats, summary and error.
func (s *Store) SaveRun(ctx context.Context, r model.ScanRun) error {
	var summary []byte
	if r.Summary != nil {
		summary = js(r.Summary)
	}
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = $2, pause_reason = $3, started_at = $4, finished_at = $5, window_end = $6, resume_at = $7,
		stats = $8::jsonb, summary = $9::jsonb, error = $10 WHERE id = $1`,
		r.ID, string(r.Status), r.PauseReason, r.StartedAt, r.FinishedAt, r.WindowEnd, r.ResumeAt, js(r.Stats), summary, r.Error)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateRunStats stores the progress counters of a run.
func (s *Store) UpdateRunStats(ctx context.Context, id int64, stats model.RunStats) error {
	_, err := s.db.Exec(ctx, `UPDATE runs SET stats = $2::jsonb WHERE id = $1`, id, js(stats))
	return err
}

// SetRunSummary stores the diff summary that the analysis produced.
func (s *Store) SetRunSummary(ctx context.Context, id int64, sum model.RunDiffSummary) error {
	_, err := s.db.Exec(ctx, `UPDATE runs SET summary = $2::jsonb WHERE id = $1`, id, js(sum))
	return err
}

// DeleteRun removes a run with its chunks. Observations stay in the inventory history.
func (s *Store) DeleteRun(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM runs WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RunsByStatus returns every run in one of the given states, oldest first.
func (s *Store) RunsByStatus(ctx context.Context, statuses ...model.RunStatus) ([]model.ScanRun, error) {
	st := make([]string, 0, len(statuses))
	for _, x := range statuses {
		st = append(st, string(x))
	}
	return jsonRows[model.ScanRun](ctx, s.db, wrapJSON("SELECT "+runCols+" FROM runs r WHERE r.status = ANY($1) ORDER BY r.id"), st)
}

// PrevCompletedRun returns the id of the last completed run before the given
// run: of the same profile when the run has one, of any profile otherwise. 0 when there is none.
func (s *Store) PrevCompletedRun(ctx context.Context, runID int64) (int64, error) {
	var id *int64
	err := s.db.QueryRow(ctx, `SELECT max(p.id) FROM runs p, runs r WHERE r.id = $1 AND p.id < r.id AND p.status = 'completed'
		AND (r.profile_id IS NULL OR p.profile_id = r.profile_id)`, runID).Scan(&id)
	if err != nil || id == nil {
		return 0, mapErr(err)
	}
	return *id, nil
}

// ---------- chunks ----------

const chunkCols = `c.id, c.run_id, c.seq, c.spec, c.size, c.priority, c.status, c.started_at, c.finished_at, c.duration_ms, c.hosts_up, c.pps, c.error`

type chunkIn struct {
	RunID      int64      `json:"run_id"`
	Seq        int        `json:"seq"`
	Spec       []string   `json:"spec"`
	Size       int        `json:"size"`
	Priority   int        `json:"priority"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	DurationMs int64      `json:"duration_ms"`
	HostsUp    int        `json:"hosts_up"`
	PPS        float64    `json:"pps"`
	Error      string     `json:"error"`
}

func toChunkIn(runID int64, c model.Chunk) chunkIn {
	st := string(c.Status)
	if st == "" {
		st = string(model.ChunkPending)
	}
	if c.RunID != 0 {
		runID = c.RunID
	}
	return chunkIn{runID, c.Seq, nonNil(c.Spec), c.Size, c.Priority, st, c.StartedAt, c.FinishedAt, c.DurationMs, c.HostsUp, c.PPS, c.Error}
}

const chunkUpsert = `INSERT INTO chunks (run_id, seq, spec, size, priority, status, started_at, finished_at, duration_ms, hosts_up, pps, error)
	SELECT d.run_id, d.seq, d.spec, d.size, d.priority, d.status, d.started_at, d.finished_at, d.duration_ms, d.hosts_up, d.pps, d.error
	FROM jsonb_to_recordset($1::jsonb) AS d(run_id bigint, seq int, spec text[], size int, priority int, status text, started_at timestamptz,
		finished_at timestamptz, duration_ms bigint, hosts_up int, pps float8, error text)
	ON CONFLICT (run_id, seq) DO UPDATE SET spec = EXCLUDED.spec, size = EXCLUDED.size, priority = EXCLUDED.priority, status = EXCLUDED.status,
		started_at = EXCLUDED.started_at, finished_at = EXCLUDED.finished_at, duration_ms = EXCLUDED.duration_ms, hosts_up = EXCLUDED.hosts_up,
		pps = EXCLUDED.pps, error = EXCLUDED.error`

// SavePlan stores the planned chunks of a run in one statement. A chunk is
// identified by (run, seq), so a resumed run updates its remaining chunks.
func (s *Store) SavePlan(ctx context.Context, runID int64, chunks []model.Chunk) error {
	if len(chunks) == 0 {
		return nil
	}
	in := make([]chunkIn, 0, len(chunks))
	seen := map[int]bool{}
	for _, c := range chunks {
		if seen[c.Seq] {
			continue
		}
		seen[c.Seq] = true
		in = append(in, toChunkIn(runID, c))
	}
	_, err := s.db.Exec(ctx, chunkUpsert, js(in))
	return mapErr(err)
}

// UpsertChunk stores the new state of one chunk.
func (s *Store) UpsertChunk(ctx context.Context, c model.Chunk) error {
	_, err := s.db.Exec(ctx, chunkUpsert, js([]chunkIn{toChunkIn(c.RunID, c)}))
	return mapErr(err)
}

// ListChunks returns every chunk of a run in sequence order.
func (s *Store) ListChunks(ctx context.Context, runID int64) ([]model.Chunk, error) {
	return jsonRows[model.Chunk](ctx, s.db, wrapJSON("SELECT "+chunkCols+" FROM chunks c WHERE c.run_id = $1 ORDER BY c.seq"), runID)
}

// RemainingChunks marks chunks that were left "running" as deferred and
// returns the chunks that still have to be scanned (pending and deferred).
func (s *Store) RemainingChunks(ctx context.Context, runID int64) ([]model.Chunk, error) {
	if _, err := s.db.Exec(ctx, `UPDATE chunks SET status = 'deferred' WHERE run_id = $1 AND status = 'running'`, runID); err != nil {
		return nil, mapErr(err)
	}
	return jsonRows[model.Chunk](ctx, s.db, wrapJSON("SELECT "+chunkCols+" FROM chunks c WHERE c.run_id = $1 AND c.status IN ('pending', 'deferred') ORDER BY c.priority DESC, c.seq"), runID)
}

// RunHostsUpByBlock counts the hosts that answered in a run per /24 block (for the address-space map).
func (s *Store) RunHostsUpByBlock(ctx context.Context, runID int64) (map[string]int, error) {
	rows, err := s.db.Query(ctx, `SELECT network(set_masklen(h.ip, 24))::text, count(DISTINCT h.id) FROM host_observations o JOIN hosts h ON h.id = o.host_id
		WHERE o.run_id = $1 AND o.up AND family(h.ip) = 4 GROUP BY 1`, runID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var cidr string
		var n int
		if err := rows.Scan(&cidr, &n); err != nil {
			return nil, err
		}
		out[cidr] = n
	}
	return out, rows.Err()
}
