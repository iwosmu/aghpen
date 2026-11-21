// Command czujka is the single binary of Czujka: API server, run manager and CLI tools.
//
//	czujka serve                 start the API server (migrates the database first)
//	czujka migrate               apply database migrations and print the encryption state
//	czujka user create ...       create a user or reset a password
//	czujka rotate-key            re-wrap all data keys under the current master key
//	czujka genkey                print a new random master key
//	czujka healthcheck           ask the local server for /healthz (container health check)
//	czujka doctor [--json]       check the database, pg_tde, the key, nmap, raw sockets, DNS, disk, routes
//	czujka backup [-o FILE]      write one encrypted archive (pg_dump, key derived from the master key)
//	czujka restore -i FILE       restore an archive into an empty database (--force drops the current data)
//	czujka kcap apply|status|show|remove  the kernel packet cap of this network namespace (internal/kcap)
//	czujka version
package main

import (
	// The zone database inside the binary: a bare host or a minimal image
	// without tzdata still knows Europe/Warsaw (CZUJKA_TZ, schedule windows).
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/iwosmu/aghpen/internal/api"
	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/config"
	"github.com/iwosmu/aghpen/internal/crypto"
	"github.com/iwosmu/aghpen/internal/doctor"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/runner"
	"github.com/iwosmu/aghpen/internal/store"
	"github.com/iwosmu/aghpen/internal/targets"
)

var version = "dev"

const usage = `czujka - Attack Surface Intelligence

Usage:
  czujka serve
  czujka migrate
  czujka user create --email E [--name N] [--role admin|editor|analyst|viewer|<slug>] [--password P] [--reset]
  czujka user unlock EMAIL     clear the login lock of an account (the password stays)
  czujka rotate-key
  czujka genkey
  czujka healthcheck
  czujka doctor [--json]       check the installation; prints a fix for every failure
  czujka backup [-o FILE]      one encrypted archive of the database (key derived from the master key)
  czujka restore -i FILE [--force]  restore an archive into an empty database (--force drops the current data)
  czujka kcap apply --pps N | status | show --pps N | remove
                               the kernel packet cap (nftables) of this network namespace
  czujka version

Configuration comes from CZUJKA_* environment variables; see deploy/.env.example.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("czujka", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	case "genkey":
		var k string
		if k, err = crypto.GenerateKey(); err == nil {
			fmt.Println(k)
		}
	case "serve":
		err = serve()
	case "migrate":
		err = migrate()
	case "user":
		err = userCmd(os.Args[2:])
	case "rotate-key":
		err = rotateKey()
	case "healthcheck":
		err = healthcheck()
	case "doctor":
		err = doctorCmd(os.Args[2:])
	case "backup":
		err = backupCmd(os.Args[2:])
	case "restore":
		err = restoreCmd(os.Args[2:])
	case "kcap":
		err = kcapCmd(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "czujka: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "czujka:", err)
		os.Exit(1)
	}
}

func newLogger(cfg config.Config) *slog.Logger {
	var h slog.Handler
	if cfg.LogFormat == "text" {
		h = slog.NewTextHandler(os.Stderr, nil)
	} else {
		h = slog.NewJSONHandler(os.Stderr, nil)
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

// open loads the configuration and the keyring, connects to the database and waits until it answers.
func open(ctx context.Context, withOldKeys bool) (config.Config, *store.Store, *slog.Logger, error) {
	return openWith(ctx, withOldKeys, nil)
}

// openWith is open with a hook that may change the configuration first.
func openWith(ctx context.Context, withOldKeys bool, mutate func(*config.Config) error) (config.Config, *store.Store, *slog.Logger, error) {
	cfg, err := config.Load()
	if err != nil {
		return cfg, nil, nil, err
	}
	if mutate != nil {
		if err := mutate(&cfg); err != nil {
			return cfg, nil, nil, err
		}
	}
	log := newLogger(cfg)
	if err := cfg.RequireDB(); err != nil {
		return cfg, nil, log, err
	}
	var old []string
	if withOldKeys {
		old = cfg.OldMasterKeys
	}
	kr, created, err := crypto.LoadKeyring(cfg.MasterKey, cfg.MasterKeyFile, old)
	if err != nil {
		return cfg, nil, log, err
	}
	if created {
		log.Warn("a new master key was generated; keep this file safe, without it the encrypted fields are lost", "file", cfg.MasterKeyFile, "key_id", kr.CurrentID())
	}
	loc, _ := time.LoadLocation(cfg.Timezone)
	st, err := store.Open(ctx, cfg.DBURL, store.Options{Keyring: kr, TDE: cfg.TDE, Location: loc, OperatorNetworks: cfg.AllowedNetworks})
	if err != nil {
		return cfg, nil, log, err
	}
	if err := st.WaitReady(ctx, 90*time.Second); err != nil {
		st.Close()
		return cfg, nil, log, err
	}
	return cfg, st, log, nil
}

func logTDE(ctx context.Context, st *store.Store, log *slog.Logger) {
	tde := st.TDE(ctx)
	if tde.Active {
		log.Info("encryption at rest: pg_tde is active", "tables", tde.Tables, "encrypted", tde.Encrypted, "wal_encrypted", tde.WALEncrypted)
		return
	}
	log.Warn("encryption at rest: pg_tde is NOT active; only field-level encryption protects sensitive fields",
		"reason", tde.Reason, "tables", tde.Tables, "encrypted", tde.Encrypted)
}

func migrate() error {
	ctx := context.Background()
	_, st, log, err := open(ctx, true)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	logTDE(ctx, st, log)
	log.Info("migrations applied")
	return nil
}

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, st, log, err := open(ctx, true)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	if err := st.VerifyKeyring(ctx); err != nil {
		return err
	}
	logTDE(ctx, st, log)
	// A policy saved before the operator lock (or under a wider one) is
	// brought inside it; what changed is logged and audited.
	if c, err := st.ClampAllowedToLock(ctx); err != nil {
		return err
	} else if c.Changed() {
		log.Warn("allowed_networks clamped to the operator lock (CZUJKA_ALLOWED_NETWORKS)", "lock", c.Lock, "before", c.Before, "after", c.After, "dropped", c.Dropped, "narrowed", c.Narrowed)
	}

	authSvc := auth.New(st, auth.Config{SessionTTL: cfg.SessionTTL, MaxFails: cfg.LoginMaxFails, Lockout: cfg.LoginLockout, PerMinute: cfg.LoginPerMin})
	generated, err := authSvc.Seed(ctx, cfg.AdminEmail, cfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("seed roles and administrator: %w", err)
	}
	if generated != "" {
		// Shown once, on the first start only. It is not stored anywhere in clear text.
		fmt.Fprintf(os.Stderr, "\n  Czujka: first administrator created\n    e-mail:   %s\n    password: %s\n  Change it after the first login.\n\n", cfg.AdminEmail, generated)
	}
	if cfg.AdminEmail == "" {
		log.Warn("CZUJKA_ADMIN_EMAIL is not set: no administrator is created at start; use 'czujka user create'")
	}

	if seeded, err := st.SeedDefaults(ctx); err != nil {
		return fmt.Errorf("seed defaults: %w", err)
	} else if seeded {
		log.Info("first start: stored the default safety policy and the default scan profile")
	}

	startHostGateway(ctx, cfg.HostGateway, log)

	// The kernel packet cap: a second limit under nmap's pacing (internal/kcap).
	kc, err := newKernelCap(cfg.DBURL, log)
	if err != nil {
		return err
	}
	if p, err := st.GetSafetyPolicy(ctx); err == nil {
		kc.Sync(ctx, p.MaxPPS)
	}

	bus := runner.NewBus()
	w := wire2(cfg, st, log)
	mgr := runner.New(st, runner.Options{Engine: w.Engine, Analyzer: w.RunAnalyzer, Window: w.Window, PauseCause: w.PauseCause, Bus: bus, IngestBatch: cfg.IngestBatch, Logger: log, KernelCap: kc})
	// Seed and load the signatures before a recovered run resumes; start the scheduler loop.
	if err := w.Start(ctx, mgr); err != nil {
		return err
	}
	if recovered, err := mgr.Recover(ctx, cfg.AutoResume); err != nil {
		log.Error("recover interrupted runs", "err", err)
	} else if len(recovered) > 0 {
		log.Warn("recovered runs that a restart interrupted", "runs", recovered)
	}

	loc, _ := time.LoadLocation(cfg.Timezone)
	if loc == nil {
		loc = time.UTC
	}
	tmRoutes, err := timeMachine(ctx, st, mgr, loc, log)
	if err != nil {
		return err
	}
	deps := w.API
	deps.Routes = append(deps.Routes, tmRoutes)
	deps.Doctor = func(ctx context.Context) any {
		return doctor.Run(ctx, doctor.Deps{Version: version, Store: st, NmapPath: cfg.NmapPath, DataDir: doctor.DataDir(cfg.MasterKeyFile), TDEMode: cfg.TDE,
			KeyInfo: fmt.Sprintf("klucz %s, kluczy poprzednich: %d", st.Keyring().CurrentID(), len(st.Keyring().IDs())-1)})
	}
	deps.Store, deps.Auth, deps.Runner, deps.Bus, deps.Logger, deps.Version = st, authSvc, mgr, bus, log, version
	deps.CookieSecure, deps.TrustProxy, deps.WebDir = cfg.CookieSecure, cfg.TrustProxy, cfg.WebDir
	deps.KernelCap = kc
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.New(deps).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,  // large result imports
		WriteTimeout:      10 * time.Minute, // large exports; SSE streams clear their deadline
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 16,
	}

	go func() { // housekeeping
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.PurgeExpiredSessions(ctx); err != nil {
					log.Error("purge sessions", "err", err)
				}
			}
		}
	}()

	errc := make(chan error, 1)
	go func() {
		log.Info("czujka is listening", "addr", cfg.Listen, "version", version, "engine_wired", mgr.EngineWired(), "web_dir", cfg.WebDir)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.Shutdown(sctx) // running scans become paused with reason "restart" and resume at the next start
	_ = srv.Shutdown(sctx)
	mgr.Wait()
	return nil
}

func userCmd(args []string) error {
	if len(args) == 2 && args[0] == "unlock" {
		return userUnlock(args[1])
	}
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: czujka user create --email E [--name N] [--role R] [--password P] [--reset]\n       czujka user unlock EMAIL")
	}
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)
	email := fs.String("email", "", "e-mail address (login)")
	name := fs.String("name", "", "display name")
	role := fs.String("role", model.RoleViewer, "role slug: admin, editor, analyst, viewer or a custom role")
	password := fs.String("password", os.Getenv("CZUJKA_USER_PASSWORD"), "password; default from CZUJKA_USER_PASSWORD, else a random one is printed")
	reset := fs.Bool("reset", false, "set a new password for an existing user")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("--email is required")
	}
	ctx := context.Background()
	_, st, _, err := open(ctx, true)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	svc := auth.New(st, auth.Config{})
	if _, err := svc.Seed(ctx, "", ""); err != nil {
		return err
	}
	generated := false
	if *password == "" {
		if *password, err = auth.GeneratePassword(); err != nil {
			return err
		}
		generated = true
	}
	if *reset {
		if err := svc.SetPasswordByEmail(ctx, *email, *password); err != nil {
			return err
		}
		fmt.Printf("password of %s was reset\n", strings.ToLower(*email))
	} else {
		r, err := st.GetRoleBySlug(ctx, *role)
		if err != nil {
			return fmt.Errorf("role %q: %w", *role, err)
		}
		// The CLI runs on the server host: it acts with every permission.
		u, err := svc.CreateUser(ctx, auth.NewPrincipal(model.User{}, model.AllPermissions, ""), *email, *name, *password, r.ID)
		if err != nil {
			return err
		}
		_ = st.InsertAudit(ctx, model.AuditEntry{Action: "user.create", Entity: "user", EntityID: fmt.Sprint(u.ID), UserEmail: "cli", Detail: map[string]any{"email": u.Email, "role": u.RoleSlug, "via": "cli"}})
		fmt.Printf("user %s created with role %s (id %d)\n", u.Email, u.RoleSlug, u.ID)
	}
	if generated {
		fmt.Printf("password: %s\n", *password)
	}
	return nil
}

// userUnlock clears the login lock of an account without changing its
// password: the way back in for the first administrator when someone keeps
// the account locked with wrong passwords.
func userUnlock(email string) error {
	ctx := context.Background()
	_, st, _, err := open(ctx, true)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := auth.New(st, auth.Config{}).UnlockByEmail(ctx, email); err != nil {
		return fmt.Errorf("unlock %s: %w", email, err)
	}
	_ = st.InsertAudit(ctx, model.AuditEntry{Action: "user.unlock", Entity: "user", UserEmail: "cli", Detail: map[string]any{"email": strings.ToLower(strings.TrimSpace(email)), "via": "cli"}})
	fmt.Printf("account %s unlocked\n", strings.ToLower(strings.TrimSpace(email)))
	return nil
}

// rotateKey re-wraps every data key under a new master key.
//
//   - CZUJKA_MASTER_KEY set: that is the new key; the old ones come from
//     CZUJKA_MASTER_KEY_OLD. With CZUJKA_MASTER_KEY_FILE also set, the new key
//     is written to the file after the rotation, so a restart that reads the
//     file works without a manual step.
//   - Only CZUJKA_MASTER_KEY_FILE set: the key in the file is the old key, a
//     new key is generated, the data keys are re-wrapped and the file is
//     replaced (atomically) with the new key.
func rotateKey() error {
	ctx := context.Background()
	var newKey, fileKey string
	cfg, st, log, err := openWith(ctx, true, func(c *config.Config) error {
		if c.MasterKeyFile != "" {
			if b, err := os.ReadFile(c.MasterKeyFile); err == nil {
				fileKey = strings.TrimSpace(string(b))
			} else if !errors.Is(err, os.ErrNotExist) || c.MasterKey == "" {
				return fmt.Errorf("read the key file %s: %w", c.MasterKeyFile, err)
			}
		}
		if c.MasterKey != "" || c.MasterKeyFile == "" {
			newKey = c.MasterKey
			if fileKey != "" && fileKey != newKey {
				c.OldMasterKeys = append(c.OldMasterKeys, fileKey)
			}
			return nil
		}
		var err error
		if newKey, err = crypto.GenerateKey(); err != nil {
			return err
		}
		c.MasterKey, c.OldMasterKeys = newKey, append(c.OldMasterKeys, fileKey)
		return nil
	})
	if err != nil {
		return err
	}
	defer st.Close()
	if len(cfg.OldMasterKeys) == 0 {
		log.Warn("no old master key (CZUJKA_MASTER_KEY_OLD, the key file or its .old file): only values that are already under the current key can be read")
	}
	// The key files change before the data does: the retired key goes to
	// <file>.old first, then the new key replaces the file. A crash at any point,
	// or a server that still runs with the old key and writes under it, leaves
	// every value readable after a restart (LoadKeyring reads both files).
	if cfg.MasterKeyFile != "" && newKey != "" && fileKey != newKey {
		if fileKey != "" {
			if err := crypto.AppendOldKey(cfg.MasterKeyFile, fileKey); err != nil {
				return fmt.Errorf("keep the old key in %s.old: %w", cfg.MasterKeyFile, err)
			}
		}
		if err := writeKeyFile(cfg.MasterKeyFile, newKey); err != nil {
			return fmt.Errorf("write the new key to %s (nothing was re-wrapped): %w", cfg.MasterKeyFile, err)
		}
		fmt.Printf("key file %s now holds the new master key; the old one is kept in %s.old\n", cfg.MasterKeyFile, cfg.MasterKeyFile)
	}
	before, err := st.KeyUsage(ctx)
	if err != nil {
		return err
	}
	done, err := st.RotateKeys(ctx)
	if err != nil {
		return fmt.Errorf("rotation stopped (it is safe to run again): %w", err)
	}
	after, err := st.KeyUsage(ctx)
	if err != nil {
		return err
	}
	_ = st.InsertAudit(ctx, model.AuditEntry{Action: "crypto.rotate_key", Entity: "crypto", UserEmail: "cli", Detail: map[string]any{"rewrapped": done, "key_id": st.Keyring().CurrentID()}})
	fmt.Printf("current master key id: %s\n", st.Keyring().CurrentID())
	names := make([]string, 0, len(done))
	for n := range done {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("  re-wrapped %-32s %d\n", n, done[n])
	}
	fmt.Printf("ciphertexts per key id before: %v\nciphertexts per key id after:  %v\n", before, after)
	if len(after) > 1 {
		return errors.New("some values are still under an old key")
	}
	fmt.Println("done: restart czujka so it encrypts with the new key (run rotate-key again after the restart to re-wrap what the old process wrote meanwhile)")
	return nil
}

func healthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}

// writeKeyFile replaces a key file atomically: a temporary file in the same
// directory with mode 0600, fsync, then rename.
func writeKeyFile(path, key string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".master-key-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(strings.TrimSpace(key) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// startHostGateway sets the address loopback targets are scanned as
// (targets.SetHostGateway). In a container the docker host's DNS name may
// answer a little after the start: it is retried for a minute.
func startHostGateway(ctx context.Context, setting string, log *slog.Logger) {
	in := targets.InContainer()
	try := func() bool {
		gw, err := targets.ResolveHostGateway(ctx, setting, in, nil)
		if err != nil {
			log.Warn("host gateway not resolved: localhost targets scan this container", "setting", setting, "err", err)
			return false
		}
		targets.SetHostGateway(gw)
		if gw.IsValid() {
			log.Info("loopback targets (localhost, 127.x, ::1) are scanned as the docker host", "host_gateway", gw.String())
		}
		return true
	}
	if try() {
		return
	}
	go func() {
		for i := 0; i < 12; i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			if try() {
				return
			}
		}
	}()
}
