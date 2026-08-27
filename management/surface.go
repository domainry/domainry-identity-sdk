// Package management defines the optional HTTP administration surface exposed
// by an embedded Identity module. It is deliberately separate from the
// deployment-neutral identity.Binding contract: remote/SaaS factories do not
// implement Provider and keep owning their administration endpoint.
package management

import "net/http"

const ContractVersion = "domainry-identity-management-surface-v1"

// Route is one exact route owned by Identity. Pattern uses the Go 1.22
// ServeMux form (for example "GET /identity/users/{userID}").
type Route struct {
	Pattern string
}

// Surface is a closed, immutable administration route set. Runtime registers
// only Routes; Handler must not be installed as an unrestricted fallback.
type Surface interface {
	ContractVersion() string
	Routes() []Route
	Handler() http.Handler
}

// Provider is implemented only by bindings which carry an in-process
// administration surface. Callers discover it explicitly after Factory.Open.
type Provider interface {
	ManagementSurface() Surface
}
