package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// legacyDBPassword is the fixed database password of installs from before
// the secrets volume. The compose stack no longer keeps it: for such an
// install it writes a new random password to CZUJKA_DB_PASSWORD_FILE and the
// old one to <file>_legacy, and Czujka moves the role to the new password at
// its first connection (security review L5).

// adoptLegacyDBPassword sets the password of the database role to the one in
// dbURL when the database still accepts only the legacy password from
// legacyFile. It does nothing when the file does not exist or dbURL works.
func adoptLegacyDBPassword(ctx context.Context, dbURL, legacyFile string, log *slog.Logger) error {
	raw, err := os.ReadFile(legacyFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", legacyFile, err)
	}
	legacy := strings.TrimSpace(string(raw))
	u, err := url.Parse(dbURL)
	if err != nil || u.User == nil {
		return errors.New("CZUJKA_DB_URL needs the form postgres://user:password@host/db")
	}
	next, ok := u.User.Password()
	if !ok || next == "" || legacy == "" || next == legacy {
		return nil
	}
	lu := *u
	lu.User = url.UserPassword(u.User.Username(), legacy)
	deadline := time.Now().Add(90 * time.Second)
	for {
		c, err := pgx.Connect(ctx, dbURL)
		if err == nil {
			_ = c.Close(ctx)
			return nil // the new password works already
		}
		if isAuthError(err) {
			old, lerr := pgx.Connect(ctx, lu.String())
			if lerr != nil {
				return fmt.Errorf("the database accepts neither the password file nor the legacy password: %w", err)
			}
			defer old.Close(ctx)
			// ALTER ROLE takes no parameters: the literal is quoted here.
			q := "ALTER ROLE CURRENT_USER PASSWORD '" + strings.ReplaceAll(next, "'", "''") + "'"
			if _, err := old.Exec(ctx, q); err != nil {
				return fmt.Errorf("move the database role to the new password: %w", err)
			}
			log.Warn("the database role used the fixed password of an older version; it now uses the generated password from the secrets volume")
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("database not reachable to check the legacy password: %w", err)
		}
		time.Sleep(time.Second)
	}
}

func isAuthError(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && (pe.Code == "28P01" || pe.Code == "28000")
}
