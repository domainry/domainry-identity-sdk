package httpmiddleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type ErrorWriter func(http.ResponseWriter, *http.Request, int, string)

type Option func(*Middleware)

func WithErrorWriter(writer ErrorWriter) Option {
	return func(middleware *Middleware) {
		if writer != nil {
			middleware.writeError = writer
		}
	}
}

// WithAuthorization enables online, fail-closed reauthorization for
// high-risk operations. Ordinary requests should use cached AccessBundles.
func WithAuthorization(authorization identitysdk.Authorization) Option {
	return func(middleware *Middleware) {
		middleware.authorization = authorization
	}
}

type Middleware struct {
	authenticator identitysdk.PrincipalAuthenticator
	authorization identitysdk.Authorization
	writeError    ErrorWriter
}

func (m *Middleware) RequireReauthorization(access identitysdk.AccessRequest, facts func(*http.Request) identitysdk.ResourceFacts, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := identitysdk.RequestIdentityFromContext(r.Context())
		if !ok {
			m.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		if m.authorization == nil {
			m.writeError(w, r, http.StatusServiceUnavailable, "identity.reauthorization_unavailable")
			return
		}
		if next == nil {
			m.writeError(w, r, http.StatusInternalServerError, "identity.middleware_handler_required")
			return
		}
		resourceFacts := identitysdk.ResourceFacts{}
		if facts != nil {
			resourceFacts = facts(r)
		}
		decision, err := m.authorization.Reauthorize(r.Context(), identitysdk.DecisionRequest{Identity: identity, Access: access, Facts: resourceFacts})
		if err != nil {
			m.writeError(w, r, http.StatusServiceUnavailable, "identity.reauthorization_failed")
			return
		}
		if !decision.Allowed {
			m.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func New(authenticator identitysdk.PrincipalAuthenticator, options ...Option) (*Middleware, error) {
	if authenticator == nil {
		return nil, errors.New("identity authenticator is required")
	}
	middleware := &Middleware{authenticator: authenticator, writeError: writeJSONError}
	for _, option := range options {
		if option != nil {
			option(middleware)
		}
	}
	return middleware, nil
}

// Authenticate validates the bearer credential once and publishes the
// resulting RequestIdentity in the request context.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next == nil {
			m.writeError(w, r, http.StatusInternalServerError, "identity.middleware_handler_required")
			return
		}
		if _, ok := identitysdk.RequestIdentityFromContext(r.Context()); ok {
			next.ServeHTTP(w, r)
			return
		}
		accessToken, ok := BearerToken(r)
		if !ok {
			m.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		principal, err := m.authenticator.Authenticate(r.Context(), accessToken)
		if err != nil {
			status, code := authenticationError(err)
			m.writeError(w, r, status, code)
			return
		}
		if !principal.Known || strings.TrimSpace(principal.UserID) == "" {
			m.writeError(w, r, http.StatusUnauthorized, "auth.token_invalid")
			return
		}
		identity := identitysdk.RequestIdentity{Principal: principal, AccessToken: accessToken}
		next.ServeHTTP(w, r.WithContext(identitysdk.WithRequestIdentity(r.Context(), identity)))
	})
}

// RequireAuthenticated protects a route after Authenticate has populated the
// SDK RequestIdentity. It intentionally checks the SDK context rather than a
// host-owned principal projection so every embedding Runtime shares the same
// authentication semantics.
func (m *Middleware) RequireAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := identitysdk.RequestIdentityFromContext(r.Context())
		if !ok || !identity.Principal.Known {
			m.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		if next == nil {
			m.writeError(w, r, http.StatusInternalServerError, "identity.middleware_handler_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePasswordChanged denies business access for sessions created with a
// temporary password. Identity credential endpoints can omit this guard so
// the user can complete the required password handoff; embedding Runtimes
// should place it immediately after Authenticate.
func (m *Middleware) RequirePasswordChanged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := identitysdk.RequestIdentityFromContext(r.Context())
		if !ok || !identity.Principal.Known {
			m.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		if identity.Principal.MustChangePassword {
			m.writeError(w, r, http.StatusForbidden, "auth.password_change_required")
			return
		}
		if next == nil {
			m.writeError(w, r, http.StatusInternalServerError, "identity.middleware_handler_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthenticatedFunc adapts RequireAuthenticated to the standard route-guard
// shape used by net/http HandlerFunc-based routers.
func (m *Middleware) AuthenticatedFunc(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(m.RequireAuthenticated(next).ServeHTTP)
}

// PermissionFunc returns a HandlerFunc route guard backed exclusively by the
// SDK AccessBundle attached to RequestIdentity.
func (m *Middleware) PermissionFunc(permission string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(m.RequirePermission(permission, next).ServeHTTP)
	}
}

func (m *Middleware) RequirePermission(permission string, next http.Handler) http.Handler {
	required := strings.TrimSpace(permission)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := identitysdk.RequestIdentityFromContext(r.Context())
		if !ok {
			m.writeError(w, r, http.StatusUnauthorized, "auth.token_required")
			return
		}
		if next == nil {
			m.writeError(w, r, http.StatusInternalServerError, "identity.middleware_handler_required")
			return
		}
		if required == "" {
			m.writeError(w, r, http.StatusForbidden, "auth.permission_required")
			return
		}
		if !identity.Principal.HasPermission(required) {
			m.writeError(w, r, http.StatusForbidden, "auth.permission_denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func BearerToken(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[1], true
}

func authenticationError(err error) (int, string) {
	var identityError *identitysdk.Error
	if errors.As(err, &identityError) {
		if identityError.StatusCode >= 500 {
			return http.StatusServiceUnavailable, "auth.service_unavailable"
		}
		if identityError.Code != "" {
			return http.StatusUnauthorized, identityError.Code
		}
	}
	return http.StatusUnauthorized, "auth.token_invalid"
}

func writeJSONError(w http.ResponseWriter, _ *http.Request, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":  code,
		"error": map[string]string{"code": code},
	})
}
