// Package store is the PostgreSQL persistence layer of Czujka: schema
// migrations, repositories for every type of internal/model, and the
// store-backed model.ResultSink.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/iwosmu/aghpen/internal/crypto"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

var (
	// ErrNotFound means the row does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict means a unique or foreign-key rule rejected the write.
	ErrConflict = errors.New("conflict")
	// ErrInvalid means the input is not acceptable.
	ErrInvalid = errors.New("invalid")
)

// Options configure a Store.
type Options struct {
	Keyring  *crypto.Keyring // field-level encryption; required
	TDE      string          // auto | require | off
	Location *time.Location  // timezone of the hour-of-week histogram
	MaxConns int32
	// OperatorNetworks is the operator lock (CZUJKA_ALLOWED_NETWORKS). It is
	// reported in every safety policy the store returns and never stored.
	OperatorNetworks []string
}

// querier is the part of pgx that pool and transaction share.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store gives access to the database. A Store made by Tx runs inside one transaction.
type Store struct {
	db   querier
	pool *pgxpool.Pool
	kr   *crypto.Keyring
	loc  *time.Location
	sh   *shared
}

type shared struct {
	operator []string
	tdeMode  string
	mu       sync.Mutex
	tde      TDEStatus
	tdeAt    time.Time
	scopes   *scopeMatcher
	scopeAt  time.Time
}

// Open connects to PostgreSQL. It does not change the schema; call Migrate.
func Open(ctx context.Context, url string, opt Options) (*Store, error) {
	if opt.Keyring == nil {
		return nil, errors.New("store: a keyring is required")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("store: bad database URL: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	cfg.ConnConfig.RuntimeParams["application_name"] = "czujka"
	if opt.MaxConns > 0 {
		cfg.MaxConns = opt.MaxConns
	} else if cfg.MaxConns < 10 {
		cfg.MaxConns = 10
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	loc := opt.Location
	if loc == nil {
		loc = time.UTC
	}
	mode := opt.TDE
	if mode == "" {
		mode = "auto"
	}
	return &Store{db: pool, pool: pool, kr: opt.Keyring, loc: loc, sh: &shared{tdeMode: mode, operator: append([]string{}, opt.OperatorNetworks...)}}, nil
}

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks that the database answers.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Pool exposes the connection pool for integration code and tests.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Keyring returns the field-encryption keyring.
func (s *Store) Keyring() *crypto.Keyring { return s.kr }

// WaitReady pings until the database answers or the timeout passes.
func (s *Store) WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := s.pool.Ping(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("store: database not ready after %s: %w", timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// Tx runs fn inside one transaction. fn gets a Store bound to it.
func (s *Store) Tx(ctx context.Context, fn func(tx *Store) error) error {
	if _, ok := s.db.(pgx.Tx); ok {
		return fn(s)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := fn(&Store{db: tx, pool: s.pool, kr: s.kr, loc: s.loc, sh: s.sh}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------- migrations and TDE ----------

// TDEStatus describes layer 1 of the encryption at rest.
type TDEStatus struct {
	Active       bool   `json:"active"`        // every table of the schema uses tde_heap
	Available    bool   `json:"available"`     // pg_tde is loaded and has a principal key
	Tables       int    `json:"tables"`        // tables of the schema
	Encrypted    int    `json:"encrypted"`     // tables for which pg_tde_is_encrypted is true
	WALEncrypted bool   `json:"wal_encrypted"` // pg_tde.wal_encrypt is on
	Reason       string `json:"reason,omitempty"`
}

// tdeUsable reports whether a tde_heap table can be created right now.
func (s *Store) tdeUsable(ctx context.Context) (bool, string) {
	if s.sh.tdeMode == "off" {
		return false, "disabled by CZUJKA_TDE=off"
	}
	var has bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_am WHERE amname = 'tde_heap')`).Scan(&has); err != nil {
		return false, err.Error()
	}
	if !has {
		// Works only for a superuser on a server that preloads pg_tde; harmless otherwise.
		_, _ = s.pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pg_tde`)
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_am WHERE amname = 'tde_heap')`).Scan(&has); err != nil || !has {
			return false, "the pg_tde extension is not installed in this database"
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err.Error()
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `CREATE TABLE czujka_tde_probe (x int) USING tde_heap`); err != nil {
		return false, "tde_heap table cannot be created: " + err.Error()
	}
	var enc bool
	if err := tx.QueryRow(ctx, `SELECT pg_tde_is_encrypted('czujka_tde_probe')`).Scan(&enc); err != nil || !enc {
		return false, "pg_tde_is_encrypted is not true for a new tde_heap table"
	}
	return true, ""
}

// Migrate applies the embedded SQL migrations that are not applied yet. When
// pg_tde is usable every table is created with the tde_heap access method.
func (s *Store) Migrate(ctx context.Context) error {
	usable, reason := s.tdeUsable(ctx)
	if !usable && s.sh.tdeMode == "require" {
		return fmt.Errorf("store: CZUJKA_TDE=require but pg_tde is not usable: %s", reason)
	}
	am, setAM := "", ""
	if usable {
		am, setAM = "USING tde_heap", "SET LOCAL default_table_access_method = tde_heap"
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// One migrator at a time, also when several processes start together.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(741100221)`); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(741100221)`) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now()) `+am); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	for _, name := range names {
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, name).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		raw, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		sql := strings.ReplaceAll(string(raw), "{{AM}}", am)
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if setAM != "" {
			if _, err := tx.Exec(ctx, setAM); err != nil {
				tx.Rollback(ctx) //nolint:errcheck
				return err
			}
		}
		if _, err := tx.Exec(ctx, sql); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	s.sh.mu.Lock()
	s.sh.tdeAt = time.Time{}
	s.sh.mu.Unlock()
	return nil
}

// TDE returns the state of the transparent data encryption. The answer is cached for 30 seconds.
func (s *Store) TDE(ctx context.Context) TDEStatus {
	s.sh.mu.Lock()
	defer s.sh.mu.Unlock()
	if time.Since(s.sh.tdeAt) < 30*time.Second {
		return s.sh.tde
	}
	st := TDEStatus{}
	var hasAM bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_am WHERE amname = 'tde_heap')`).Scan(&hasAM); err != nil {
		st.Reason = err.Error()
		return st
	}
	const tables = `FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind = 'r' AND n.nspname = current_schema()`
	if !hasAM {
		_ = s.pool.QueryRow(ctx, `SELECT count(*) `+tables).Scan(&st.Tables)
		st.Reason = "the pg_tde extension is not installed in this database"
	} else {
		st.Available = true
		if err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE pg_tde_is_encrypted(c.oid::regclass)) `+tables).Scan(&st.Tables, &st.Encrypted); err != nil {
			st.Reason = err.Error()
		}
		var wal *string
		_ = s.pool.QueryRow(ctx, `SELECT current_setting('pg_tde.wal_encrypt', true)`).Scan(&wal)
		st.WALEncrypted = wal != nil && *wal == "on"
		st.Active = st.Tables > 0 && st.Encrypted == st.Tables
		if !st.Active && st.Reason == "" {
			st.Reason = fmt.Sprintf("%d of %d tables are not encrypted", st.Tables-st.Encrypted, st.Tables)
		}
	}
	s.sh.tde, s.sh.tdeAt = st, time.Now()
	return st
}

// mapErr turns PostgreSQL constraint errors into the package errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return fmt.Errorf("%w: %s", ErrConflict, pg.ConstraintName)
		case "23503":
			return fmt.Errorf("%w: referenced row is missing or still in use (%s)", ErrConflict, pg.ConstraintName)
		case "22P02", "22003", "23514", "23502", "22007", "22008":
			return fmt.Errorf("%w: %s", ErrInvalid, pg.Message)
		}
	}
	return err
}
