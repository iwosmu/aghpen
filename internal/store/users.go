package store

import (
	"context"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// ---------- roles ----------

const roleCols = `r.id, r.slug, r.name, r.description, r.builtin, r.permissions,
  (SELECT count(*) FROM users u WHERE u.role_id = r.id) AS user_count`

// ListRoles returns every role, built-in roles first.
func (s *Store) ListRoles(ctx context.Context) ([]model.Role, error) {
	return jsonRows[model.Role](ctx, s.db, wrapJSON("SELECT "+roleCols+" FROM roles r ORDER BY r.builtin DESC, r.id"))
}

// GetRole returns one role by id.
func (s *Store) GetRole(ctx context.Context, id int64) (model.Role, error) {
	return jsonRow[model.Role](ctx, s.db, wrapJSON("SELECT "+roleCols+" FROM roles r WHERE r.id = $1"), id)
}

// GetRoleBySlug returns one role by slug.
func (s *Store) GetRoleBySlug(ctx context.Context, slug string) (model.Role, error) {
	return jsonRow[model.Role](ctx, s.db, wrapJSON("SELECT "+roleCols+" FROM roles r WHERE r.slug = $1"), slug)
}

func perms(p []model.Permission) []string {
	out := make([]string, 0, len(p))
	for _, x := range p {
		out = append(out, string(x))
	}
	return out
}

// CreateRole inserts a custom role.
func (s *Store) CreateRole(ctx context.Context, r model.Role) (model.Role, error) {
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO roles (slug, name, description, builtin, permissions) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		r.Slug, r.Name, r.Description, r.Builtin, perms(r.Permissions)).Scan(&id)
	if err != nil {
		return r, mapErr(err)
	}
	return s.GetRole(ctx, id)
}

// UpsertBuiltinRole creates or refreshes a built-in role.
func (s *Store) UpsertBuiltinRole(ctx context.Context, r model.Role) error {
	_, err := s.db.Exec(ctx, `INSERT INTO roles (slug, name, description, builtin, permissions) VALUES ($1,$2,$3,true,$4)
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, builtin = true, permissions = EXCLUDED.permissions`,
		r.Slug, r.Name, r.Description, perms(r.Permissions))
	return mapErr(err)
}

// UpdateRole changes name, description and permissions of a role.
func (s *Store) UpdateRole(ctx context.Context, r model.Role) (model.Role, error) {
	tag, err := s.db.Exec(ctx, `UPDATE roles SET name = $2, description = $3, permissions = $4 WHERE id = $1`, r.ID, r.Name, r.Description, perms(r.Permissions))
	if err != nil {
		return r, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return r, ErrNotFound
	}
	return s.GetRole(ctx, r.ID)
}

// DeleteRole removes a role. It fails with ErrConflict while users still have it.
func (s *Store) DeleteRole(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- users ----------

const userCols = `u.id, u.email, u.name, u.role_id, r.slug AS role_slug, r.name AS role_name, u.disabled, u.created_at, u.last_login_at`
const userFrom = `users u JOIN roles r ON r.id = u.role_id`

// UserAuth is a user with the fields that only authentication needs.
type UserAuth struct {
	model.User
	PasswordHash string             `json:"password_hash"`
	FailedLogins int                `json:"failed_logins"`
	LockedUntil  *time.Time         `json:"locked_until"`
	Permissions  []model.Permission `json:"permissions"`
}

// ListUsers returns a page of users.
func (s *Store) ListUsers(ctx context.Context, o ListOpts) (model.Page[model.User], error) {
	w := &where{}
	if o.Q != "" {
		w.add("u.email ILIKE ? OR u.name ILIKE ?", like(o.Q), like(o.Q))
	}
	order := orderBy(o.Sort, map[string]string{"id": "u.id", "email": "u.email", "name": "u.name", "created_at": "u.created_at", "last_login_at": "u.last_login_at", "role_slug": "r.slug"}, "u.id ASC", "u.id")
	return listPage[model.User](ctx, s.db, userCols, userFrom, w, order, o, nil)
}

// GetUser returns one user.
func (s *Store) GetUser(ctx context.Context, id int64) (model.User, error) {
	return jsonRow[model.User](ctx, s.db, wrapJSON("SELECT "+userCols+" FROM "+userFrom+" WHERE u.id = $1"), id)
}

// GetUserAuthByEmail returns the user with password hash, lockout state and permissions.
func (s *Store) GetUserAuthByEmail(ctx context.Context, email string) (UserAuth, error) {
	return jsonRow[UserAuth](ctx, s.db, wrapJSON("SELECT "+userCols+", u.password_hash, u.failed_logins, u.locked_until, r.permissions FROM "+userFrom+" WHERE u.email = $1"), email)
}

// CreateUser inserts a user with an already hashed password.
func (s *Store) CreateUser(ctx context.Context, u model.User, passwordHash string) (model.User, error) {
	var id int64
	err := s.db.QueryRow(ctx, `INSERT INTO users (email, name, password_hash, role_id, disabled) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		u.Email, u.Name, passwordHash, u.RoleID, u.Disabled).Scan(&id)
	if err != nil {
		return u, mapErr(err)
	}
	return s.GetUser(ctx, id)
}

// UpdateUser changes email, name, role and the disabled flag.
func (s *Store) UpdateUser(ctx context.Context, u model.User) (model.User, error) {
	tag, err := s.db.Exec(ctx, `UPDATE users SET email = $2, name = $3, role_id = $4, disabled = $5 WHERE id = $1`, u.ID, u.Email, u.Name, u.RoleID, u.Disabled)
	if err != nil {
		return u, mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return u, ErrNotFound
	}
	return s.GetUser(ctx, u.ID)
}

// SetPassword stores a new password hash and clears the lockout.
func (s *Store) SetPassword(ctx context.Context, id int64, hash string) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1`, id, hash)
	return mapErr(err)
}

// DeleteUser removes a user and the user's sessions.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// LockAdmins serialises changes that could remove the last administrator.
// Call it inside Tx before CountOtherAdmins.
func (s *Store) LockAdmins(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `SELECT pg_advisory_xact_lock(741100222)`)
	return err
}

// CountOtherAdmins counts enabled users with the built-in admin role, without the given user.
func (s *Store) CountOtherAdmins(ctx context.Context, exceptUserID int64) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM users u JOIN roles r ON r.id = u.role_id WHERE r.slug = $1 AND NOT u.disabled AND u.id <> $2`, model.RoleAdmin, exceptUserID).Scan(&n)
	return n, err
}

// RecordLoginFailure counts a failed login and locks the account after maxFails failures.
func (s *Store) RecordLoginFailure(ctx context.Context, userID int64, maxFails int, lockout time.Duration) (locked bool, err error) {
	err = s.db.QueryRow(ctx, `UPDATE users SET failed_logins = failed_logins + 1,
		locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(secs => $3) ELSE locked_until END
		WHERE id = $1 RETURNING locked_until IS NOT NULL AND locked_until > now()`, userID, maxFails, lockout.Seconds()).Scan(&locked)
	return locked, mapErr(err)
}

// RecordLoginSuccess clears the failure counter and stores the login time.
func (s *Store) RecordLoginSuccess(ctx context.Context, userID int64) error {
	_, err := s.db.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`, userID)
	return err
}

// ---------- sessions ----------

// SessionInfo is a live session with its user and permissions.
type SessionInfo struct {
	model.User
	Permissions []model.Permission `json:"permissions"`
	CSRFToken   string             `json:"csrf_token"`
	ExpiresAt   time.Time          `json:"expires_at"`
	LastSeen    time.Time          `json:"last_seen"`
}

// CreateSession stores the hash of a session token.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID int64, csrf string, expires time.Time, ip, userAgent string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, ip, user_agent) VALUES ($1,$2,$3,$4,$5,$6)`,
		tokenHash, userID, csrf, expires, ip, userAgent)
	return mapErr(err)
}

// GetSession returns the session of a token hash when it is not expired and the user is enabled.
func (s *Store) GetSession(ctx context.Context, tokenHash []byte) (SessionInfo, error) {
	return jsonRow[SessionInfo](ctx, s.db, wrapJSON("SELECT "+userCols+`, r.permissions, se.csrf_token, se.expires_at, se.last_seen
		FROM sessions se JOIN users u ON u.id = se.user_id JOIN roles r ON r.id = u.role_id
		WHERE se.token_hash = $1 AND se.expires_at > now() AND NOT u.disabled`), tokenHash)
}

// TouchSession records activity of a session.
func (s *Store) TouchSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.Exec(ctx, `UPDATE sessions SET last_seen = now() WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteSession ends one session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteUserSessions ends every session of a user (after a password or role change).
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

// PurgeExpiredSessions deletes sessions that are past their expiry.
func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	return err
}

// ---------- audit log ----------

// InsertAudit appends one entry to the audit log.
func (s *Store) InsertAudit(ctx context.Context, e model.AuditEntry) error {
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	_, err := s.db.Exec(ctx, `INSERT INTO audit_log (user_id, user_email, action, entity, entity_id, detail, ip) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)`,
		e.UserID, e.UserEmail, e.Action, e.Entity, e.EntityID, js(e.Detail), e.IP)
	return mapErr(err)
}

// AuditFilter are the filters of GET /audit.
type AuditFilter struct {
	ListOpts
	UserID   int64
	Action   string
	Entity   string
	From, To *time.Time
}

// ListAudit returns a page of audit entries, newest first by default.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) (model.Page[model.AuditEntry], error) {
	w := &where{}
	if f.UserID != 0 {
		w.add("a.user_id = ?", f.UserID)
	}
	if f.Action != "" {
		w.add("a.action = ? OR a.action LIKE ?", f.Action, f.Action+".%")
	}
	if f.Entity != "" {
		w.add("a.entity = ?", f.Entity)
	}
	if f.From != nil {
		w.add("a.at >= ?", *f.From)
	}
	if f.To != nil {
		w.add("a.at <= ?", *f.To)
	}
	if f.Q != "" {
		w.add("a.user_email ILIKE ? OR a.action ILIKE ? OR a.entity_id ILIKE ?", like(f.Q), like(f.Q), like(f.Q))
	}
	order := orderBy(f.Sort, map[string]string{"at": "a.at", "id": "a.id", "action": "a.action", "user_email": "a.user_email"}, "a.id DESC", "")
	return listPage[model.AuditEntry](ctx, s.db, "a.id, a.at, a.user_id, a.user_email, a.action, a.entity, a.entity_id, a.detail, a.ip", "audit_log a", w, order, f.ListOpts, nil)
}
