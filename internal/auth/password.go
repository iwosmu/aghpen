// Package auth implements authentication and role-based access control:
// argon2id password hashes, sessions with hashed random tokens, CSRF tokens,
// login rate limiting and account lockout, permission checks and the rules for
// managing users and roles.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (OWASP: m = 19 MiB, t = 2, p = 1 as the minimum; we use more memory).
const (
	argonTime    = 2
	argonMemory  = 32 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16

	// MinPasswordLen is the shortest password that is accepted.
	MinPasswordLen = 10
)

// HashPassword returns the argon2id hash of a password in the PHC string format.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a hash made by HashPassword. The
// parameters come from the hash, so old hashes stay valid when defaults change.
func VerifyPassword(hash, password string) bool {
	p := strings.Split(hash, "$")
	if len(p) != 6 || p[1] != "argon2id" {
		return false
	}
	var version int
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(p[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(p[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil || memory == 0 || time == 0 || threads == 0 || memory > 1<<21 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(p[4])
	want, err2 := base64.RawStdEncoding.DecodeString(p[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ValidatePassword applies the password policy.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordLen {
		return fmt.Errorf("the password must have at least %d characters", MinPasswordLen)
	}
	if len(password) > 256 {
		return errors.New("the password must have at most 256 characters")
	}
	return nil
}

// NewToken returns a random 256-bit token and the hash that is stored for it.
func NewToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken returns the SHA-256 of a session token. Only this hash is stored,
// so a copy of the database does not give working sessions.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// GeneratePassword returns a random password for the first administrator.
func GeneratePassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
