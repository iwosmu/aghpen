package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/iwosmu/aghpen/internal/model"
)

// CookieName is the name of the session cookie.
const CookieName = "czujka_session"

// CSRFHeader is the header that mutating requests must send.
const CSRFHeader = "X-CSRF-Token"

type ctxKey struct{}

// WithPrincipal stores the principal in a context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the principal of a request, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// ErrorWriter writes an API error in the format of docs/API.md.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, status int, code, message string)

// SetCookie writes the session cookie: HttpOnly, SameSite=Strict, Secure when asked.
func SetCookie(w http.ResponseWriter, token string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: secure, MaxAge: int(ttl.Seconds())})
}

// ClearCookie removes the session cookie.
func ClearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure, MaxAge: -1})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// Authenticate is the middleware that resolves the session cookie. With a
// valid session the principal is put in the request context. Mutating requests
// of a session must carry the CSRF token. Requests without a session pass on;
// RequireSession and Require reject them where a session is needed.
func (s *Service) Authenticate(next http.Handler, fail ErrorWriter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		p, err := s.authenticate(r.Context(), c.Value)
		if errors.Is(err, ErrNoSession) {
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			fail(w, r, http.StatusInternalServerError, "internal", "session lookup failed")
			return
		}
		r = r.WithContext(WithPrincipal(r.Context(), p))
		if !safeMethod(r.Method) && !p.CheckCSRF(r.Header.Get(CSRFHeader)) {
			fail(w, r, http.StatusForbidden, "forbidden", "missing or wrong CSRF token: send the csrf_token of the session in the X-CSRF-Token header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) authenticate(ctx context.Context, token string) (*Principal, error) {
	return s.AuthenticateToken(ctx, token)
}

// RequireSession rejects requests without a session with 401.
func RequireSession(fail ErrorWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if FromContext(r.Context()) == nil {
				fail(w, r, http.StatusUnauthorized, "unauthorized", "sign in first")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Require rejects requests whose principal lacks the permission: 401 without a session, 403 otherwise.
func Require(perm model.Permission, fail ErrorWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := FromContext(r.Context())
			if p == nil {
				fail(w, r, http.StatusUnauthorized, "unauthorized", "sign in first")
				return
			}
			if !p.Can(perm) {
				fail(w, r, http.StatusForbidden, "forbidden", "this action needs the permission "+string(perm))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
