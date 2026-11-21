package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// M4 of the security review: the failure counter starts again when a lock
// expires, so one wrong password every lockout period does not keep an
// account locked for ever.
func TestLockExpiryResetsTheFailureCounter(t *testing.T) {
	ctx := context.Background()
	svc, st, admin := setup(t, Config{MaxFails: 3, Lockout: time.Second, PerMinute: 1000})
	if _, err := svc.CreateUser(ctx, admin, "ola@example.org", "Ola", "haslo-analityka-1", roleID(t, st, model.RoleAnalyst)); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		_, _, _ = svc.Login(ctx, "ola@example.org", "zle-haslo", "198.51.100.2", "")
	}
	if _, _, err := svc.Login(ctx, "ola@example.org", "haslo-analityka-1", "198.51.100.2", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("after 3 failures the account is locked: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, _, err := svc.Login(ctx, "ola@example.org", "zle-haslo", "198.51.100.2", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("one failure after the lock expired must not lock again: %v", err)
	}
	if _, _, err := svc.Login(ctx, "ola@example.org", "haslo-analityka-1", "198.51.100.2", ""); err != nil {
		t.Fatalf("the right password after the lock expired: %v", err)
	}
}

// M4: an operator unlocks an account (also the first administrator) without
// changing its password: czujka user unlock <email>.
func TestUnlockByEmail(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := setup(t, Config{MaxFails: 2, Lockout: time.Hour, PerMinute: 1000})
	gen := "haslo-admina-12345"
	if err := svc.SetPasswordByEmail(ctx, "admin@example.org", gen); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_, _, _ = svc.Login(ctx, "admin@example.org", "zle-haslo", "198.51.100.2", "")
	}
	if _, _, err := svc.Login(ctx, "admin@example.org", gen, "198.51.100.2", ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	if err := svc.UnlockByEmail(ctx, " Admin@Example.org "); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Login(ctx, "admin@example.org", gen, "198.51.100.2", ""); err != nil {
		t.Fatalf("login after unlock: %v", err)
	}
	if err := svc.UnlockByEmail(ctx, "nikt@example.org"); err == nil {
		t.Fatal("unlocking an unknown account must fail")
	}
}
