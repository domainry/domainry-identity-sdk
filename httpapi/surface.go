// Package httpapi defines optional HTTP surfaces owned by an in-process
// Identity implementation. Deployment-neutral Runtime code may mount these
// surfaces without importing the Identity implementation or duplicating its
// authentication and administration handlers.
package httpapi

import "net/http"

const ContractVersion = "domainry-identity-http-surface-v1"

type Exposure string

const (
	ExposurePublic      Exposure = "public"
	ExposureTenantAdmin Exposure = "tenant_admin"
)

type Route struct {
	Pattern   string
	Exposures []Exposure
}

// Surface is an immutable, explicitly routed HTTP boundary. Hosts register
// only the declared routes and must never install Handler as a catch-all.
type Surface interface {
	ContractVersion() string
	Name() string
	Routes() []Route
	Handler() http.Handler
}

// Provider is implemented by in-process bindings only. A SaaS binding owns
// its HTTP endpoints remotely and therefore does not implement Provider.
type Provider interface {
	HTTPSurfaces() []Surface
}
