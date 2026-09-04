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

// RegisterRoutes mounts the complete browser session adapter below prefix.
// For example, prefix "/browser" produces "/browser/auth/login".
func (gateway *Gateway) RegisterRoutes(mux *http.ServeMux, prefix string) error {
	if gateway == nil || mux == nil {
		return errors.New("Identity browser gateway and ServeMux are required")
	}
	definitions, err := ActionDefinitions(prefix)
	if err != nil {
		return err
	}
	specs := browserGatewayRouteSpecs()
	if len(definitions) != len(specs) {
		return errors.New("Identity browser gateway Action manifest is incomplete")
	}
	for index, definition := range definitions {
		handler := gateway.routeHandler(specs[index].handlerKey)
		if handler == nil || definition.HTTP == nil {
			return fmt.Errorf("Identity browser gateway action %q has no handler", definition.Key)
		}
		mux.HandleFunc(definition.HTTP.Method+" "+definition.HTTP.RouteTemplate, handler)
	}
	return nil
}

// RoutePatterns returns the exact browser-session route contract owned by the
// SDK. Hosts can use it for listener inventories and OpenAPI/adapter checks
// without duplicating authentication routes.
func RoutePatterns(prefix string) ([]string, error) {
	definitions, err := ActionDefinitions(prefix)
	if err != nil {
		return nil, err
	}
	patterns := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		patterns = append(patterns, definition.HTTP.Method+" "+definition.HTTP.RouteTemplate)
	}
	return patterns, nil
}

func normalizeRoutePrefix(prefix string) (string, error) {
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "/")
	if prefix != "" && (!strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "?# \t\r\n")) {
		return "", fmt.Errorf("invalid Identity browser route prefix %q", prefix)
	}
	return prefix, nil
}
