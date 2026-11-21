package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

var (
	// ErrInvalidCredentials is the answer for an unknown user and for a wrong password alike.
	ErrInvalidCredentials = errors.New("invalid e-mail or password")
	// ErrLocked means the account is locked after too many failed logins.
	ErrLocked = errors.New("the account is locked after too many failed logins; try again later")
	// ErrRateLimited means too many login attempts came from one address.
	ErrRateLimited = errors.New("too many login attempts; try again later")
	// ErrNoSession means there is no valid session.
	ErrNoSession = errors.New("not signed in")
	// ErrForbidden means a role rule rejected the change.
	ErrForbidden = errors.New("forbidden")
	// ErrLastAdmin protects the last enabled administrator.
	ErrLastAdmin = errors.New("the last administrator cannot be removed, disabled or demoted")
	// ErrBuiltinRole protects the built-in roles.
	ErrBuiltinRole = errors.New("built-in roles are read only")
	// ErrValidation means the input is not acceptable.
	ErrValidation = errors.New("validation")
)

// Config holds the tunables of the auth service.
type Config struct {
	SessionTTL time.Duration // lifetime of a session
	MaxFails   int           // failed logins before the account is locked
	Lockout    time.Duration // how long a locked account stays locked
	PerMinute  int           // login attempts per minute from one address
}

func (c Config) withDefaults() Config {
	if c.SessionTTL <= 0 {
		c.SessionTTL = 12 * time.Hour
	}
	if c.MaxFails <= 0 {
		c.MaxFails = 5
	}
	if c.Lockout <= 0 {
		c.Lockout = 15 * time.Minute
	}
	if c.PerMinute <= 0 {
		c.PerMinute = 20
	}
	return c
}

// Service is the authentication and RBAC service.
type Service struct {
	st  *store.Store
	cfg Config

	mu       sync.Mutex
	limiters map[string]*ipLimiter
	dummy    string // hash used to spend the same time for unknown users
}

type ipLimiter struct {
	lim  *rate.Limiter
	seen time.Time
}

// New returns the auth service.
func New(st *store.Store, cfg Config) *Service {
	dummy, _ := HashPassword("czujka-dummy-password-for-timing")
	return &Service{st: st, cfg: cfg.withDefaults(), limiters: map[string]*ipLimiter{}, dummy: dummy}
}

// Principal is the signed-in user of one request.
type Principal struct {
	User      model.User
	Perms     []model.Permission
	CSRFToken string
	tokenHash []byte
	set       map[model.Permission]bool
}

// NewPrincipal builds a principal from a user and a permission list.
func NewPrincipal(u model.User, perms []model.Permission, csrf string) *Principal {
	p := &Principal{User: u, Perms: ordered(perms), CSRFToken: csrf, set: map[model.Permission]bool{}}
	for _, x := range perms {
		p.set[x] = true
	}
	return p
}

// Can reports whether the principal holds a permission.
func (p *Principal) Can(perm model.Permission) bool { return p != nil && p.set[perm] }

// Session returns the wire form of the session (POST /auth/login, GET /me).
func (p *Principal) Session() model.Session {
	return model.Session{User: p.User, Permissions: p.Perms, CSRFToken: p.CSRFToken}
}

// CheckCSRF compares the token of a request with the session token in constant time.
func (p *Principal) CheckCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(p.CSRFToken)) == 1
}

// Seed creates or refreshes the built-in roles and creates the first
// administrator when the e-mail is given and no such user exists. When the
// password is empty a random one is generated and returned, to be shown once.
func (s *Service) Seed(ctx context.Context, adminEmail, adminPassword string) (generated string, err error) {
	for _, r := range BuiltinRoles() {
		if err := s.st.UpsertBuiltinRole(ctx, r); err != nil {
			return "", fmt.Errorf("seed role %s: %w", r.Slug, err)
		}
	}
	adminEmail = normEmail(adminEmail)
	if adminEmail == "" {
		return "", nil
	}
	if _, err := s.st.GetUserAuthByEmail(ctx, adminEmail); err == nil {
		return "", nil // exists: never reset a password at start
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	if adminPassword == "" {
		if adminPassword, err = GeneratePassword(); err != nil {
			return "", err
		}
		generated = adminPassword
	}
	if err := ValidatePassword(adminPassword); err != nil {
		return "", fmt.Errorf("CZUJKA_ADMIN_PASSWORD: %w", err)
	}
	role, err := s.st.GetRoleBySlug(ctx, model.RoleAdmin)
	if err != nil {
		return "", err
	}
	hash, err := HashPassword(adminPassword)
	if err != nil {
		return "", err
	}
	if _, err := s.st.CreateUser(ctx, model.User{Email: adminEmail, Name: "Administrator", RoleID: role.ID}, hash); err != nil {
		return "", err
	}
	return generated, nil
}

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

// allow applies the per-address login rate limit.
func (s *Service) allow(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.limiters) > 10000 {
		for k, l := range s.limiters {
			if now.Sub(l.seen) > 10*time.Minute {
				delete(s.limiters, k)
			}
		}
	}
	l, ok := s.limiters[ip]
	if !ok {
		l = &ipLimiter{lim: rate.NewLimiter(rate.Limit(float64(s.cfg.PerMinute)/60), s.cfg.PerMinute)}
		s.limiters[ip] = l
	}
	l.seen = now
	return l.lim.Allow()
}

// Login checks the credentials and opens a session. It returns the principal
// and the session token for the cookie. Callers log every outcome to the audit log.
func (s *Service) Login(ctx context.Context, email, password, ip, userAgent string) (*Principal, string, error) {
	if !s.allow(ip) {
		return nil, "", ErrRateLimited
	}
	email = normEmail(email)
	u, err := s.st.GetUserAuthByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		VerifyPassword(s.dummy, password) // same work as for a known user
		return nil, "", ErrInvalidCredentials
	}
	if err != nil {
		return nil, "", err
	}
	if u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
		return nil, "", ErrLocked
	}
	if !VerifyPassword(u.PasswordHash, password) || u.Disabled {
		if !u.Disabled {
			if locked, err := s.st.RecordLoginFailure(ctx, u.ID, s.cfg.MaxFails, s.cfg.Lockout); err == nil && locked {
				return nil, "", ErrLocked
			}
		}
		return nil, "", ErrInvalidCredentials
	}
	token, hash, err := NewToken()
	if err != nil {
		return nil, "", err
	}
	csrf, _, err := NewToken()
	if err != nil {
		return nil, "", err
	}
	if len(userAgent) > 300 {
		userAgent = userAgent[:300]
	}
	if err := s.st.CreateSession(ctx, hash, u.ID, csrf, time.Now().Add(s.cfg.SessionTTL), ip, userAgent); err != nil {
		return nil, "", err
	}
	if err := s.st.RecordLoginSuccess(ctx, u.ID); err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	u.User.LastLoginAt = &now
	p := NewPrincipal(u.User, u.Permissions, csrf)
	p.tokenHash = hash
	return p, token, nil
}

// AuthenticateToken resolves a session token to a principal. Permissions are read
// from the database on every request, so a role change works at once.
func (s *Service) AuthenticateToken(ctx context.Context, token string) (*Principal, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	hash := HashToken(token)
	si, err := s.st.GetSession(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	if time.Since(si.LastSeen) > time.Minute {
		_ = s.st.TouchSession(ctx, hash)
	}
	p := NewPrincipal(si.User, si.Permissions, si.CSRFToken)
	p.tokenHash = hash
	return p, nil
}

// Logout ends the session of the principal.
func (s *Service) Logout(ctx context.Context, p *Principal) error {
	if p == nil || p.tokenHash == nil {
		return nil
	}
	return s.st.DeleteSession(ctx, p.tokenHash)
}

// SessionTTL returns the session lifetime (for the cookie).
func (s *Service) SessionTTL() time.Duration { return s.cfg.SessionTTL }

// ---------- user management ----------

// canGrant checks the rule "a user can never grant a permission they do not hold".
func canGrant(actor *Principal, role model.Role) error {
	if miss := missing(actor.set, role.Permissions); len(miss) > 0 {
		return fmt.Errorf("%w: you cannot grant role %q: you do not hold %v", ErrForbidden, role.Slug, miss)
	}
	return nil
}

func validEmail(e string) error {
	if a, err := mail.ParseAddress(e); err != nil || a.Address != e || len(e) > 254 {
		return fmt.Errorf("%w: %q is not a valid e-mail address", ErrValidation, e)
	}
	return nil
}

// CreateUser creates a user. The actor must hold every permission of the role.
func (s *Service) CreateUser(ctx context.Context, actor *Principal, email, name, password string, roleID int64) (model.User, error) {
	email = normEmail(email)
	if err := validEmail(email); err != nil {
		return model.User{}, err
	}
	if err := ValidatePassword(password); err != nil {
		return model.User{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	role, err := s.st.GetRole(ctx, roleID)
	if errors.Is(err, store.ErrNotFound) {
		return model.User{}, fmt.Errorf("%w: role %d does not exist", ErrValidation, roleID)
	}
	if err != nil {
		return model.User{}, err
	}
	if err := canGrant(actor, role); err != nil {
		return model.User{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return model.User{}, err
	}
	return s.st.CreateUser(ctx, model.User{Email: email, Name: strings.TrimSpace(name), RoleID: roleID}, hash)
}

// UserPatch is a partial update of a user; nil fields stay as they are.
type UserPatch struct {
	Email    *string `json:"email"`
	Name     *string `json:"name"`
	RoleID   *int64  `json:"role_id"`
	Disabled *bool   `json:"disabled"`
	Password *string `json:"password"`
}

// UpdateUser changes a user under the RBAC rules: the actor must hold every
// permission of the user's current role and of the new role, and the last
// enabled administrator cannot be disabled or demoted.
func (s *Service) UpdateUser(ctx context.Context, actor *Principal, id int64, patch UserPatch) (model.User, error) {
	var out model.User
	err := s.st.Tx(ctx, func(tx *store.Store) error {
		if err := tx.LockAdmins(ctx); err != nil {
			return err
		}
		u, err := tx.GetUser(ctx, id)
		if err != nil {
			return err
		}
		curRole, err := tx.GetRole(ctx, u.RoleID)
		if err != nil {
			return err
		}
		// Without this rule a user manager could take over a stronger account by setting its password.
		if err := canGrant(actor, curRole); err != nil {
			return fmt.Errorf("%w (the account has a stronger role than yours)", err)
		}
		wasAdmin := curRole.Slug == model.RoleAdmin && !u.Disabled
		if patch.Email != nil {
			u.Email = normEmail(*patch.Email)
			if err := validEmail(u.Email); err != nil {
				return err
			}
		}
		if patch.Name != nil {
			u.Name = strings.TrimSpace(*patch.Name)
		}
		newRole := curRole
		if patch.RoleID != nil && *patch.RoleID != u.RoleID {
			newRole, err = tx.GetRole(ctx, *patch.RoleID)
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%w: role %d does not exist", ErrValidation, *patch.RoleID)
			}
			if err != nil {
				return err
			}
			if err := canGrant(actor, newRole); err != nil {
				return err
			}
			u.RoleID = newRole.ID
		}
		if patch.Disabled != nil {
			u.Disabled = *patch.Disabled
		}
		if wasAdmin && (newRole.Slug != model.RoleAdmin || u.Disabled) {
			n, err := tx.CountOtherAdmins(ctx, u.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		if out, err = tx.UpdateUser(ctx, u); err != nil {
			return err
		}
		if patch.Password != nil {
			if err := ValidatePassword(*patch.Password); err != nil {
				return fmt.Errorf("%w: %v", ErrValidation, err)
			}
			hash, err := HashPassword(*patch.Password)
			if err != nil {
				return err
			}
			if err := tx.SetPassword(ctx, u.ID, hash); err != nil {
				return err
			}
		}
		if patch.Password != nil || u.Disabled {
			return tx.DeleteUserSessions(ctx, u.ID) // old sessions end with the old password
		}
		return nil
	})
	return out, err
}

// DeleteUser removes a user. The last enabled administrator cannot be removed.
func (s *Service) DeleteUser(ctx context.Context, actor *Principal, id int64) error {
	return s.st.Tx(ctx, func(tx *store.Store) error {
		if err := tx.LockAdmins(ctx); err != nil {
			return err
		}
		u, err := tx.GetUser(ctx, id)
		if err != nil {
			return err
		}
		role, err := tx.GetRole(ctx, u.RoleID)
		if err != nil {
			return err
		}
		if err := canGrant(actor, role); err != nil {
			return fmt.Errorf("%w (the account has a stronger role than yours)", err)
		}
		if role.Slug == model.RoleAdmin && !u.Disabled {
			n, err := tx.CountOtherAdmins(ctx, u.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		return tx.DeleteUser(ctx, id)
	})
}

// SetPasswordByEmail sets a password without an actor (the CLI command "user create --reset").
func (s *Service) SetPasswordByEmail(ctx context.Context, email, password string) error {
	if err := ValidatePassword(password); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	u, err := s.st.GetUserAuthByEmail(ctx, normEmail(email))
	if err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if err := s.st.SetPassword(ctx, u.ID, hash); err != nil {
		return err
	}
	return s.st.DeleteUserSessions(ctx, u.ID)
}

// ---------- role management ----------

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,48}$`)

func slugify(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func (s *Service) checkRole(actor *Principal, r *model.Role) error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return fmt.Errorf("%w: the role needs a name", ErrValidation)
	}
	seen := map[model.Permission]bool{}
	for _, p := range r.Permissions {
		if !ValidPermission(p) {
			return fmt.Errorf("%w: unknown permission %q", ErrValidation, p)
		}
		seen[p] = true
	}
	perms := make([]model.Permission, 0, len(seen))
	for p := range seen {
		perms = append(perms, p)
	}
	r.Permissions = ordered(perms)
	return canGrant(actor, *r)
}

// CreateRole creates a custom role from the permission list. The actor must hold every permission of it.
func (s *Service) CreateRole(ctx context.Context, actor *Principal, r model.Role) (model.Role, error) {
	if err := s.checkRole(actor, &r); err != nil {
		return r, err
	}
	if r.Slug == "" {
		r.Slug = slugify(r.Name)
	}
	if !slugRe.MatchString(r.Slug) {
		return r, fmt.Errorf("%w: the slug must be 2-49 characters of a-z, 0-9 and '-'", ErrValidation)
	}
	r.Builtin = false
	return s.st.CreateRole(ctx, r)
}

// RolePatch is a partial update of a custom role.
type RolePatch struct {
	Name        *string             `json:"name"`
	Description *string             `json:"description"`
	Permissions *[]model.Permission `json:"permissions"`
}

// UpdateRole changes a custom role. Built-in roles are read only.
func (s *Service) UpdateRole(ctx context.Context, actor *Principal, id int64, patch RolePatch) (model.Role, error) {
	r, err := s.st.GetRole(ctx, id)
	if err != nil {
		return r, err
	}
	if r.Builtin {
		return r, ErrBuiltinRole
	}
	if patch.Name != nil {
		r.Name = *patch.Name
	}
	if patch.Description != nil {
		r.Description = *patch.Description
	}
	if patch.Permissions != nil {
		r.Permissions = *patch.Permissions
	}
	if err := s.checkRole(actor, &r); err != nil {
		return r, err
	}
	return s.st.UpdateRole(ctx, r)
}

// DeleteRole removes a custom role that no user has.
func (s *Service) DeleteRole(ctx context.Context, actor *Principal, id int64) error {
	r, err := s.st.GetRole(ctx, id)
	if err != nil {
		return err
	}
	if r.Builtin {
		return ErrBuiltinRole
	}
	if r.UserCount > 0 {
		return fmt.Errorf("%w: %d users still have this role", store.ErrConflict, r.UserCount)
	}
	return s.st.DeleteRole(ctx, id)
}
