package reprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// Target is one address of a targeted run and its known ports.
type Target struct {
	HostID int64  `json:"host_id"`
	IP     string `json:"ip"`
	Ports  []int  `json:"ports"` // known TCP ports; empty: discovery only
}

// Request asks the runner for a targeted run.
type Request struct {
	ProfileID *int64   // profile whose rates, detection and HTTP options the run uses; nil: the default profile
	Targets   []Target // addresses with their ports
	Reason    string   // Polish, for the run record and the audit log
	Trigger   string   // always "reprobe"
}

// Starter is the runner capability the backend needs: start, in the
// background, a run on exactly these addresses and ports that goes through
// the normal engine (safety policy, rate limits, window guard, emergency
// stop), the normal store sink (MarkMissing) and the normal analysis, with
// run.trigger = req.Trigger and profile_id NULL. Every target must be a hint
// of the plan, so a silent address still gets an observation (up = false).
type Starter func(ctx context.Context, req Request) (model.ScanRun, error)

// Backend is what the executor needs.
type Backend interface {
	// Snapshot reads the planner input: settings, policy, candidates, budget used.
	Snapshot(ctx context.Context, now time.Time) (Input, error)
	// Start starts one targeted run.
	Start(ctx context.Context, req Request) (model.ScanRun, error)
	// Record stores the probes a run carries (budget and step counting).
	Record(ctx context.Context, run model.ScanRun, probes []Probe, at time.Time) error
}

// ErrNotWired means no Starter was given.
var ErrNotWired = errors.New("reprobe: the runner has no targeted-run capability wired")

// StoreBackend is the Backend over the Czujka store.
type StoreBackend struct {
	st      *store.Store
	loc     *time.Location
	starter Starter
	log     *slog.Logger
}

// NewStoreBackend returns the store-backed Backend. loc is the timezone of
// the availability histogram (store.Options.Location); starter may be nil
// (then the plan is shown but nothing starts).
func NewStoreBackend(st *store.Store, loc *time.Location, starter Starter, logger *slog.Logger) *StoreBackend {
	if loc == nil {
		loc = time.UTC
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &StoreBackend{st: st, loc: loc, starter: starter, log: logger}
}

// SetStarter wires the runner capability after construction.
func (b *StoreBackend) SetStarter(s Starter) { b.starter = s }

// Init creates the reprobe_log table with the access method of the hosts
// table (tde_heap when the store encrypts at rest).
func (b *StoreBackend) Init(ctx context.Context) error {
	am := ""
	var name *string
	_ = b.st.Pool().QueryRow(ctx, `SELECT a.amname::text FROM pg_class c JOIN pg_am a ON a.oid = c.relam
		WHERE c.relname = 'hosts' AND c.relnamespace = current_schema()::regnamespace`).Scan(&name)
	if name != nil && *name == "tde_heap" {
		am = " USING tde_heap"
	}
	ddl := `CREATE TABLE IF NOT EXISTS reprobe_log (
		id      BIGSERIAL PRIMARY KEY,
		at      TIMESTAMPTZ NOT NULL DEFAULT now(),
		run_id  BIGINT NOT NULL,
		host_id BIGINT NOT NULL,
		ip      TEXT NOT NULL,
		kind    TEXT NOT NULL,
		step    INT NOT NULL DEFAULT 0,
		reason  TEXT NOT NULL DEFAULT ''
	)`
	if _, err := b.st.Pool().Exec(ctx, ddl+am); err != nil {
		if am == "" {
			return fmt.Errorf("reprobe: create reprobe_log: %w", err)
		}
		if _, err := b.st.Pool().Exec(ctx, ddl); err != nil {
			return fmt.Errorf("reprobe: create reprobe_log: %w", err)
		}
	}
	for _, q := range []string{
		`CREATE INDEX IF NOT EXISTS reprobe_log_host_idx ON reprobe_log (host_id, at DESC)`,
		`CREATE INDEX IF NOT EXISTS reprobe_log_at_idx ON reprobe_log (at DESC)`,
	} {
		if _, err := b.st.Pool().Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

const settingsKey = "reprobe"

// Settings returns the stored settings, or the defaults.
func (b *StoreBackend) Settings(ctx context.Context) (Settings, error) {
	s := DefaultSettings()
	var raw []byte
	err := b.st.Pool().QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, settingsKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return DefaultSettings(), nil
	}
	if err := s.Validate(); err != nil {
		return DefaultSettings(), nil
	}
	return s, nil
}

// PutSettings validates and stores the settings.
func (b *StoreBackend) PutSettings(ctx context.Context, s Settings) (Settings, error) {
	if err := s.Validate(); err != nil {
		return s, err
	}
	raw, _ := json.Marshal(s)
	_, err := b.st.Pool().Exec(ctx, `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::jsonb, now())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, settingsKey, raw)
	return s, err
}

// candidateSQL lists the hosts that do not answer now and are not reported
// inactive, with their streak, ports, histogram, recorded reprobes and profile.
const candidateSQL = `SELECT h.id, host(h.ip), h.status, h.last_up, st.streak_start, lo.at,
	COALESCE((SELECT array_agg(DISTINCT s.port ORDER BY s.port) FROM services s
		WHERE s.host_id = h.id AND s.proto = 'tcp' AND s.state IN ('open', 'unknown')), '{}'),
	COALESCE((SELECT jsonb_agg(jsonb_build_array(a.bucket, a.up, a.down)) FROM host_availability a WHERE a.host_id = h.id), '[]'),
	(SELECT count(*) FROM reprobe_log l WHERE l.host_id = h.id AND l.at >= st.streak_start),
	(SELECT max(l.at) FROM reprobe_log l WHERE l.host_id = h.id),
	pr.profile_id
FROM hosts h
CROSS JOIN LATERAL (SELECT o.at, o.up FROM host_observations o WHERE o.host_id = h.id ORDER BY o.at DESC, o.id DESC LIMIT 1) lo
CROSS JOIN LATERAL (SELECT COALESCE(min(o.at), lo.at) AS streak_start FROM host_observations o
	WHERE o.host_id = h.id AND NOT o.up AND o.at > COALESCE(h.last_up, '-infinity'::timestamptz)) st
LEFT JOIN LATERAL (SELECT r.profile_id FROM host_observations o JOIN runs r ON r.id = o.run_id
	WHERE o.host_id = h.id AND r.profile_id IS NOT NULL ORDER BY o.at DESC LIMIT 1) pr ON true
WHERE h.status IN ('unstable', 'expected-offline') AND NOT lo.up
ORDER BY h.id`

// Snapshot implements Backend.
func (b *StoreBackend) Snapshot(ctx context.Context, now time.Time) (Input, error) {
	in := Input{Now: now, Loc: b.loc}
	var err error
	if in.Settings, err = b.Settings(ctx); err != nil {
		return in, err
	}
	if in.Policy, err = b.st.GetSafetyPolicy(ctx); err != nil {
		return in, err
	}
	db := b.st.Pool()
	if err := db.QueryRow(ctx, `SELECT count(*) FROM reprobe_log WHERE at > $1`, now.Add(-time.Hour)).Scan(&in.UsedLastHour); err != nil {
		return in, err
	}
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM runs WHERE trigger = $1 AND status IN ('queued', 'running', 'analyzing'))`, Trigger).Scan(&in.ActiveReprobe); err != nil {
		return in, err
	}
	rows, err := db.Query(ctx, candidateSQL)
	if err != nil {
		return in, err
	}
	profiles := map[int64]*model.ScanProfile{}
	for rows.Next() {
		var c Candidate
		var status string
		var buckets []byte
		if err := rows.Scan(&c.HostID, &c.IP, &status, &c.LastUp, &c.StreakStart, &c.LastObsAt, &c.Ports, &buckets, &c.Attempts, &c.LastAttempt, &c.ProfileID); err != nil {
			rows.Close()
			return in, err
		}
		c.Status = model.HostStatus(status)
		var cells [][3]int
		_ = json.Unmarshal(buckets, &cells)
		for _, x := range cells {
			if x[0] >= 0 && x[0] < 168 {
				c.Buckets[x[0]] = model.AvailBucket{Up: x[1], Down: x[2]}
			}
		}
		if c.ProfileID != nil {
			profiles[*c.ProfileID] = nil
		}
		in.Candidates = append(in.Candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, err
	}
	for id := range profiles {
		if p, err := b.st.GetProfile(ctx, id); err == nil {
			pp := p
			profiles[id] = &pp
		}
	}
	for i := range in.Candidates {
		c := &in.Candidates[i]
		if c.ProfileID != nil {
			if p := profiles[*c.ProfileID]; p != nil {
				c.Windows, c.Timezone = p.Schedule.Windows, p.Schedule.Timezone
			}
		}
	}
	return in, nil
}

// Start implements Backend.
func (b *StoreBackend) Start(ctx context.Context, req Request) (model.ScanRun, error) {
	if b.starter == nil {
		return model.ScanRun{}, ErrNotWired
	}
	return b.starter(ctx, req)
}

// Record implements Backend.
func (b *StoreBackend) Record(ctx context.Context, run model.ScanRun, probes []Probe, at time.Time) error {
	if len(probes) == 0 {
		return nil
	}
	type row struct {
		HostID int64  `json:"host_id"`
		IP     string `json:"ip"`
		Kind   string `json:"kind"`
		Step   int    `json:"step"`
		Reason string `json:"reason"`
	}
	rows := make([]row, len(probes))
	for i, p := range probes {
		rows[i] = row{p.HostID, p.IP, p.Kind, p.Step, p.Reason}
	}
	raw, _ := json.Marshal(rows)
	_, err := b.st.Pool().Exec(ctx, `INSERT INTO reprobe_log (at, run_id, host_id, ip, kind, step, reason)
		SELECT $1, $2, d.host_id, d.ip, d.kind, d.step, d.reason FROM jsonb_to_recordset($3::jsonb) AS d(host_id bigint, ip text, kind text, step int, reason text)`,
		at, run.ID, raw)
	return err
}
