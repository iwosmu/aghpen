package api

import (
	"errors"
	"net/http"

	"github.com/iwosmu/aghpen/internal/auth"
	"github.com/iwosmu/aghpen/internal/model"
	"github.com/iwosmu/aghpen/internal/store"
)

// maxLoginBody bounds a login request: an e-mail and a password fit easily.
const maxLoginBody = 8 << 10

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if !decode(w, r, &in) {
		return
	}
	in.Email = clip(in.Email, 254) // the audited value stays small (RFC 5321 limit)
	p, token, err := s.d.Auth.Login(r.Context(), in.Email, in.Password, s.clientIP(r), r.UserAgent())
	if err != nil {
		reason := "invalid_credentials"
		status, code := http.StatusUnauthorized, "unauthorized"
		switch {
		case errors.Is(err, auth.ErrLocked):
			// The same answer as an unknown account or a wrong password: a
			// different one would confirm that the account exists (security
			// review M4). The audit log keeps the reason.
			reason = "locked"
			err = auth.ErrInvalidCredentials
		case errors.Is(err, auth.ErrRateLimited):
			reason, status, code = "rate_limited", http.StatusTooManyRequests, "rate_limited"
		case !errors.Is(err, auth.ErrInvalidCredentials):
			auditSet(r, "auth.login_failed", "auth", nil, map[string]any{"email": in.Email, "reason": "error"})
			s.fail(w, r, err)
			return
		}
		// Every login attempt goes to the audit log, with the e-mail that was tried.
		auditSet(r, "auth.login_failed", "auth", nil, map[string]any{"email": in.Email, "reason": reason})
		writeErr(w, status, code, err.Error())
		return
	}
	if a := auditOf(r); a != nil {
		a.user = p
	}
	auditSet(r, "auth.login", "auth", p.User.ID, nil)
	auth.SetCookie(w, token, s.d.Auth.SessionTTL(), s.secure(r))
	writeJSON(w, http.StatusOK, p.Session())
}

// changePassword is the self-service password change of the signed-in user.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	auditSet(r, "auth.password_change", "user", nil, nil)
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	if p != nil {
		auditSet(r, "", "", p.User.ID, nil)
	}
	if err := s.d.Auth.ChangePassword(r.Context(), p, in.Current, in.New); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	auditSet(r, "auth.logout", "auth", nil, nil)
	if err := s.d.Auth.Logout(r.Context(), principal(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.ClearCookie(w, s.secure(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, principal(r).Session())
}

func (s *Server) permissions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, auth.PermissionCatalog())
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.st.ListRoles(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, roles)
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	var in model.Role
	if !decode(w, r, &in) {
		return
	}
	role, err := s.d.Auth.CreateRole(r.Context(), principal(r), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", role.ID, map[string]any{"slug": role.Slug, "permissions": role.Permissions})
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in auth.RolePatch
	if !decode(w, r, &in) {
		return
	}
	role, err := s.d.Auth.UpdateRole(r.Context(), principal(r), id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", nil, map[string]any{"slug": role.Slug, "permissions": role.Permissions})
	writeJSON(w, http.StatusOK, role)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.Auth.DeleteRole(r.Context(), principal(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	o := q.opts()
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListUsers(r.Context(), o)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
		RoleID   int64  `json:"role_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := s.d.Auth.CreateUser(r.Context(), principal(r), in.Email, in.Name, in.Password, in.RoleID)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "conflict", "Użytkownik z tym adresem e-mail już istnieje.")
			return
		}
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", u.ID, map[string]any{"email": u.Email, "role": u.RoleSlug})
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in auth.UserPatch
	if !decode(w, r, &in) {
		return
	}
	u, err := s.d.Auth.UpdateUser(r.Context(), principal(r), id, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auditSet(r, "", "", nil, map[string]any{"email": u.Email, "role": u.RoleSlug, "disabled": u.Disabled, "password_changed": in.Password != nil})
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.d.Auth.DeleteUser(r.Context(), principal(r), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := query(r)
	f := store.AuditFilter{ListOpts: q.opts(), UserID: q.int64("user_id"), Action: q.str("action"), Entity: q.str("entity"), From: q.time("from"), To: q.time("to")}
	if !q.ok(w) {
		return
	}
	page, err := s.st.ListAudit(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
