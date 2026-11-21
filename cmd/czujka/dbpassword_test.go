package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/iwosmu/aghpen/internal/store/storetest"
)

// L5 of the security review: an install from before the secrets volume used
// a fixed database password. The stack now writes a random one and keeps the
// old one in <file>_legacy; Czujka moves the role to the random one.
func TestAdoptLegacyDBPassword(t *testing.T) {
	admin := storetest.URL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	role := "czt_legacy_" + hex.EncodeToString(b)
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	const legacy = "czujka-internal-network-only"
	if _, err := conn.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+legacy+"'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(context.Background(), "DROP ROLE IF EXISTS "+role) })

	at := func(pw string) string {
		u, _ := url.Parse(admin)
		u.User = url.UserPassword(role, pw)
		return u.String()
	}
	works := func(pw string) bool {
		c, err := pgx.Connect(ctx, at(pw))
		if err == nil {
			_ = c.Close(ctx)
		}
		return err == nil
	}
	const fresh = "a1b2c3-random-'quote"
	if works(fresh) || !works(legacy) {
		t.Skip("the test server does not check passwords on this connection (trust); cannot test the password move")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	file := filepath.Join(t.TempDir(), "db_password_legacy")
	// No legacy file: nothing happens.
	if err := adoptLegacyDBPassword(ctx, at(fresh), file, log); err != nil || works(fresh) {
		t.Fatalf("without a legacy file: err=%v", err)
	}
	if err := os.WriteFile(file, []byte(legacy+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := adoptLegacyDBPassword(ctx, at(fresh), file, log); err != nil {
		t.Fatal(err)
	}
	if !works(fresh) || works(legacy) {
		t.Fatalf("after the move: new works=%v, legacy works=%v", works(fresh), works(legacy))
	}
	// Idempotent: the next start finds the new password working.
	if err := adoptLegacyDBPassword(ctx, at(fresh), file, log); err != nil {
		t.Fatal(err)
	}
	// Both wrong: an error, no silent start.
	if err := adoptLegacyDBPassword(ctx, at("other-wrong"), file, log); err == nil {
		t.Fatal("neither password works: must be an error")
	}
}
