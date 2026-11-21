package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/crypto"
	"github.com/iwosmu/aghpen/internal/doctor"
	"github.com/iwosmu/aghpen/internal/store"
)

// backupManifest is the first line of the decrypted archive; the custom-format
// pg_dump output follows it to the end.
type backupManifest struct {
	Format    string           `json:"format"` // "czujka-db-dump"
	Version   string           `json:"version"`
	CreatedAt time.Time        `json:"created_at"`
	Schema    string           `json:"schema"` // highest applied migration
	Counts    map[string]int64 `json:"counts"`
	TDE       store.TDEStatus  `json:"tde"`
	KeyID     string           `json:"key_id"`
}

var countTables = []string{"hosts", "services", "findings", "runs", "changes", "users", "signatures", "targets", "scopes"}

// pgEnv turns a database URL into libpq environment variables, so the
// password never shows up in a process list.
func pgEnv(dbURL string) ([]string, error) {
	u, err := url.Parse(dbURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, fmt.Errorf("CZUJKA_DB_URL must be a postgres:// URL")
	}
	env := os.Environ()
	add := func(k, v string) {
		if v != "" {
			env = append(env, k+"="+v)
		}
	}
	add("PGHOST", u.Hostname())
	add("PGPORT", u.Port())
	add("PGUSER", u.User.Username())
	if p, ok := u.User.Password(); ok {
		add("PGPASSWORD", p)
	}
	add("PGDATABASE", strings.TrimPrefix(u.Path, "/"))
	add("PGSSLMODE", u.Query().Get("sslmode"))
	add("PGCONNECT_TIMEOUT", "10")
	return env, nil
}

func counts(ctx context.Context, st *store.Store) map[string]int64 {
	out := map[string]int64{}
	for _, t := range countTables {
		var n int64
		if err := st.Pool().QueryRow(ctx, "SELECT count(*) FROM "+t).Scan(&n); err == nil {
			out[t] = n
		}
	}
	return out
}

func schemaVersion(ctx context.Context, st *store.Store) string {
	var v string
	_ = st.Pool().QueryRow(ctx, `SELECT COALESCE(max(version), '') FROM schema_migrations`).Scan(&v)
	return v
}

// backupCmd writes one encrypted archive with a pg_dump of the database. The
// archive key is derived from the master key: without the master key the
// archive does not open (and the encrypted fields would not read anyway).
func backupCmd(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("o", "", "archive file (default: <data dir>/backups/czujka-<time>.czbk; - for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	cfg, st, log, err := open(ctx, false)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.VerifyKeyring(ctx); err != nil {
		return fmt.Errorf("the master key does not match the database: %w", err)
	}
	pgDump, err := exec.LookPath("pg_dump")
	if err != nil {
		return errors.New("pg_dump not found: install the PostgreSQL 17 client (apk add postgresql17-client / apt install postgresql-client-17); the product image has it")
	}
	env, err := pgEnv(cfg.DBURL)
	if err != nil {
		return err
	}
	path := *out
	if path == "" {
		dir := filepath.Join(doctor.DataDir(cfg.MasterKeyFile), "backups")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		path = filepath.Join(dir, "czujka-"+time.Now().UTC().Format("20060102-150405")+".czbk")
	}
	var dst io.Writer = os.Stdout
	var f *os.File
	if path != "-" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if f, err = os.OpenFile(path+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err != nil {
			return err
		}
		defer os.Remove(path + ".part")
		dst = f
	}
	bw := bufio.NewWriterSize(dst, 1<<20)
	man := backupManifest{Format: "czujka-db-dump", Version: version, CreatedAt: time.Now().UTC(), Schema: schemaVersion(ctx, st), Counts: counts(ctx, st), TDE: st.TDE(ctx), KeyID: st.Keyring().CurrentID()}
	enc, err := st.Keyring().BackupWriter(bw, map[string]string{"czujka_version": version, "schema": man.Schema})
	if err != nil {
		return err
	}
	line, _ := json.Marshal(man)
	if _, err := enc.Write(append(line, '\n')); err != nil {
		return err
	}
	t0 := time.Now()
	// The dump leaves out the pg_tde extension: the target database has its own
	// (deploy/db), and every table carries its access method (tde_heap).
	cmd := exec.CommandContext(ctx, pgDump, "--format=custom", "--compress=6", "--no-owner", "--no-privileges", "--exclude-extension=pg_tde")
	cmd.Env, cmd.Stdout = env, enc
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_dump failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if f != nil {
		if err := f.Sync(); err != nil {
			return err
		}
		size, _ := f.Seek(0, io.SeekCurrent)
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Rename(path+".part", path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "backup: %s (%.1f MiB, %s), master key %s, schema %s, %v\n", path, float64(size)/(1<<20), time.Since(t0).Round(time.Millisecond), man.KeyID, man.Schema, man.Counts)
	}
	log.Info("backup written", "file", path, "key_id", man.KeyID, "schema", man.Schema)
	return nil
}

// restoreCmd restores an archive of czujka backup into the configured
// database. The database must be empty, or --force drops every Czujka object
// first. Stop czujka serve while it runs.
func restoreCmd(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	in := fs.String("i", "", "archive file (- for stdin)")
	force := fs.Bool("force", false, "drop the existing Czujka tables of the database first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("usage: czujka restore -i <archive> [--force]")
	}
	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.RequireDB(); err != nil {
		return err
	}
	kr, _, err := crypto.LoadKeyring(cfg.MasterKey, cfg.MasterKeyFile, cfg.OldMasterKeys)
	if err != nil {
		return err
	}
	var src io.Reader = os.Stdin
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer f.Close()
		src = f
	}
	plain, hdr, err := kr.BackupReader(src)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(plain, 1<<20)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("the archive has no manifest: %w", err)
	}
	var man backupManifest
	if err := json.Unmarshal(line, &man); err != nil || man.Format != "czujka-db-dump" {
		return errors.New("the archive manifest is damaged")
	}
	fmt.Fprintf(os.Stderr, "restore: archive of %s (Czujka %s, schema %s, master key %s): %v\n", man.CreatedAt.Format(time.RFC3339), man.Version, man.Schema, hdr.KeyID, man.Counts)
	pgRestore, err := exec.LookPath("pg_restore")
	if err != nil {
		return errors.New("pg_restore not found: install the PostgreSQL 17 client (apk add postgresql17-client / apt install postgresql-client-17)")
	}
	env, err := pgEnv(cfg.DBURL)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DBURL, store.Options{Keyring: kr, TDE: cfg.TDE, OperatorNetworks: cfg.AllowedNetworks})
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := dropCzujka(ctx, st, *force)
	if err != nil {
		return err
	}
	if n > 0 {
		fmt.Fprintf(os.Stderr, "restore: dropped %d existing objects (--force)\n", n)
	}
	t0 := time.Now()
	cmd := exec.CommandContext(ctx, pgRestore, "--no-owner", "--no-privileges", "--exit-on-error", "--single-transaction", "--dbname="+envValue(env, "PGDATABASE"))
	cmd.Env, cmd.Stdin = env, br
	var stderr strings.Builder
	cmd.Stdout, cmd.Stderr = os.Stderr, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_restore failed (the database is unchanged: one transaction): %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	// The stream must end with the authenticated last chunk.
	if _, err := io.Copy(io.Discard, br); err != nil {
		return fmt.Errorf("the archive is damaged after the dump: %w", err)
	}
	if err := st.VerifyKeyring(ctx); err != nil {
		return fmt.Errorf("restored, but the master key does not open the encrypted fields: %w", err)
	}
	got := counts(ctx, st)
	for k, v := range man.Counts {
		if got[k] != v {
			return fmt.Errorf("restored, but %s has %d rows, the archive %d", k, got[k], v)
		}
	}
	tde := st.TDE(ctx)
	fmt.Fprintf(os.Stderr, "restore: done in %s; rows %v; pg_tde: %d of %d tables encrypted; master key verified\n", time.Since(t0).Round(time.Millisecond), got, tde.Encrypted, tde.Tables)
	if cfg.TDE == "require" && !tde.Active {
		return fmt.Errorf("restored, but not every table is encrypted by pg_tde (%d of %d)", tde.Encrypted, tde.Tables)
	}
	return nil
}

func envValue(env []string, key string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], key+"="); ok {
			return v
		}
	}
	return ""
}

// dropCzujka removes the objects of the public schema that do not belong to
// an extension (pg_tde stays). Without force it only refuses a non-empty database.
func dropCzujka(ctx context.Context, st *store.Store, force bool) (int, error) {
	notExt := `NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e')`
	var tables int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND `+notExt).Scan(&tables); err != nil {
		return 0, err
	}
	if tables == 0 {
		return 0, nil
	}
	if !force {
		return 0, fmt.Errorf("the database already has %d Czujka tables: restore into an empty database, or add --force to drop them (all current data is lost)", tables)
	}
	tx, err := st.Pool().Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n := 0
	for _, q := range []string{
		`SELECT format('DROP TABLE IF EXISTS %s CASCADE', c.oid::regclass) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND ` + notExt,
		`SELECT format('DROP VIEW IF EXISTS %s CASCADE', c.oid::regclass) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'v' AND ` + notExt,
		`SELECT format('DROP MATERIALIZED VIEW IF EXISTS %s CASCADE', c.oid::regclass) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'm' AND ` + notExt,
		`SELECT format('DROP SEQUENCE IF EXISTS %s CASCADE', c.oid::regclass) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'S' AND ` + notExt,
		`SELECT format('DROP FUNCTION IF EXISTS %s CASCADE', p.oid::regprocedure) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')`,
		`SELECT format('DROP TYPE IF EXISTS %s CASCADE', t.oid::regtype) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typtype IN ('e', 'd', 'c') AND (t.typrelid = 0 OR (SELECT relkind FROM pg_class WHERE oid = t.typrelid) = 'c') AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = t.oid AND d.deptype = 'e')`,
	} {
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return n, err
		}
		var stmts []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				rows.Close()
				return n, err
			}
			stmts = append(stmts, s)
		}
		rows.Close()
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return n, fmt.Errorf("%s: %w", s, err)
			}
			n++
		}
	}
	return n, tx.Commit(ctx)
}
