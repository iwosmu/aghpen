package auth

import (
	"context"
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

// SafeMethod reports whether an HTTP method does not change state.
func SafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
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
