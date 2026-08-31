// Package browsergateway adapts a deployment-neutral Identity Binding to a
// same-origin browser session API. Refresh credentials are accepted and
// returned only as rotating HttpOnly cookies; JavaScript receives short-lived
// access credentials only.
package browsergateway

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

const DefaultRefreshCookieName = "domainry_identity_refresh"

type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
}

type Config struct {
	ApplicationKey     identity.ApplicationKey
	AllowedReturnURLs  []string
	DefaultWorkspaceID identity.WorkspaceID
	Cookie             CookieConfig
	MaxRequestBodySize int64
}

type Gateway struct {
	binding identity.Binding
	config  Config
}

func New(binding identity.Binding, config Config) (*Gateway, error) {
	if binding == nil || binding.Authentication() == nil || binding.Credentials() == nil {
		return nil, errors.New("Identity Binding authentication and credentials are required")
	}
	if !config.ApplicationKey.Valid() {
		return nil, errors.New("Identity browser application key is required")
	}
	if !config.DefaultWorkspaceID.Valid() {
		return nil, errors.New("Identity browser initialized workspace is required")
	}
	if strings.TrimSpace(config.Cookie.Name) == "" {
		config.Cookie.Name = DefaultRefreshCookieName
	}
	if strings.TrimSpace(config.Cookie.Path) == "" {
		config.Cookie.Path = "/auth"
	}
	if config.Cookie.SameSite <= http.SameSiteDefaultMode {
		config.Cookie.SameSite = http.SameSiteLaxMode
	}
	if config.Cookie.MaxAge <= 0 {
		config.Cookie.MaxAge = 30 * 24 * time.Hour
	}
	if config.MaxRequestBodySize <= 0 {
		config.MaxRequestBodySize = 1 << 20
	}
	return &Gateway{binding: binding, config: config}, nil
}

// RegisterRoutes mounts the complete browser session surface below prefix.
// For example, prefix "/browser" produces "/browser/auth/login".
func (gateway *Gateway) RegisterRoutes(mux *http.ServeMux, prefix string) error {
	if gateway == nil || mux == nil {
		return errors.New("Identity browser gateway and ServeMux are required")
	}
	prefix, err := normalizeRoutePrefix(prefix)
	if err != nil {
		return err
	}
	path := func(suffix string) string { return prefix + suffix }

	mux.HandleFunc("GET "+path("/auth/session"), gateway.Session)
	mux.HandleFunc("POST "+path("/auth/code/exchange"), gateway.ExchangeAuthorizationCode)
	mux.HandleFunc("POST "+path("/auth/login"), gateway.Login)
	mux.HandleFunc("POST "+path("/auth/refresh"), gateway.Refresh)
	mux.HandleFunc("POST "+path("/auth/logout"), gateway.Logout)
	mux.HandleFunc("POST "+path("/auth/change-password"), gateway.ChangePassword)
	mux.HandleFunc("POST "+path("/auth/reset-password"), gateway.ResetPassword)
	mux.HandleFunc("POST "+path("/auth/sessions/revoke-others"), gateway.RevokeSessions)
	mux.HandleFunc("GET "+path("/auth/providers"), gateway.Providers)
	mux.HandleFunc("GET "+path("/auth/providers/{provider}/start"), gateway.StartProvider)
	mux.HandleFunc("POST "+path("/auth/providers/{provider}/start"), gateway.StartProvider)
	mux.HandleFunc("GET "+path("/auth/providers/{provider}/callback"), gateway.ProviderCallback)
	mux.HandleFunc("POST "+path("/auth/providers/{provider}/callback"), gateway.ProviderCallback)
	mux.HandleFunc("POST "+path("/auth/providers/{provider}/verify"), gateway.VerifyProvider)
	return nil
}

// RoutePatterns returns the exact browser-session route contract owned by the
// SDK. Hosts can use it for listener inventories and OpenAPI/surface checks
// without duplicating authentication routes.
func RoutePatterns(prefix string) ([]string, error) {
	prefix, err := normalizeRoutePrefix(prefix)
	if err != nil {
		return nil, err
	}
	path := func(suffix string) string { return prefix + suffix }
	return []string{
		"GET " + path("/auth/session"),
		"POST " + path("/auth/code/exchange"),
		"POST " + path("/auth/login"),
		"POST " + path("/auth/refresh"),
		"POST " + path("/auth/logout"),
		"POST " + path("/auth/change-password"),
		"POST " + path("/auth/reset-password"),
		"POST " + path("/auth/sessions/revoke-others"),
		"GET " + path("/auth/providers"),
		"GET " + path("/auth/providers/{provider}/start"),
		"POST " + path("/auth/providers/{provider}/start"),
		"GET " + path("/auth/providers/{provider}/callback"),
		"POST " + path("/auth/providers/{provider}/callback"),
		"POST " + path("/auth/providers/{provider}/verify"),
	}, nil
}

func normalizeRoutePrefix(prefix string) (string, error) {
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "/")
	if prefix != "" && (!strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "?# \t\r\n")) {
		return "", fmt.Errorf("invalid Identity browser route prefix %q", prefix)
	}
	return prefix, nil
}
