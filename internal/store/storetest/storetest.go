// Package storetest gives integration tests a migrated Store on a database of
// their own. Tests are skipped when CZUJKA_TEST_DB_URL is not set.
//
// Start the test database with:  make test-db   (PostgreSQL 17 + pg_tde on 127.0.0.1:55432)
// Run the tests with:            make test-integration
package storetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/iwosmu/aghpen/internal/crypto"
	"github.com/iwosmu/aghpen/internal/store"
)

// Key is the master key of test stores.
var Key = bytes.Repeat([]byte{0x42}, crypto.KeySize)

// URL returns the admin URL of the test server, or skips the test.
func URL(t testing.TB) string {
	t.Helper()
	u := os.Getenv("CZUJKA_TEST_DB_URL")
	if u == "" {
		t.Skip("CZUJKA_TEST_DB_URL is not set; start the database with 'make test-db' and run 'make test-integration'")
	}
	return u
}

// New creates a fresh database, migrates it and returns a Store on it. The
// database is dropped when the test ends.
func New(t testing.TB) *store.Store {
	t.Helper()
	st, _ := NewWithURL(t)
	return st
}

// NewWithURL is New that also returns the URL of the fresh database.
func NewWithURL(t testing.TB) (*store.Store, string) {
	t.Helper()
	admin := URL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "czt_" + hex.EncodeToString(b)
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect to test database server: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	conn.Close(ctx)
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	kr, err := crypto.NewKeyring(Key)
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Europe/Warsaw")
	st, err := store.Open(ctx, u.String(), store.Options{Keyring: kr, TDE: os.Getenv("CZUJKA_TEST_TDE"), Location: loc})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(c, admin)
		if err != nil {
			return
		}
		defer conn.Close(c)
		_, _ = conn.Exec(c, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	return st, u.String()
}
