// Package httpapi defines optional HTTP surfaces owned by an in-process
// Identity implementation. Deployment-neutral Runtime code may mount these
// surfaces without importing the Identity implementation or duplicating its
// authentication and administration handlers.
package httpapi

import "github.com/domainry/domainry-foundation/modulehttp"

// These aliases preserve the Identity SDK import surface while moving the
// actual host contract to the shared module HTTP owner. New modules import
// modulehttp directly; this package can be retired after downstream migration.
const ContractVersion = modulehttp.ContractVersion

type Exposure = modulehttp.Exposure
type Authentication = modulehttp.Authentication
type Route = modulehttp.Route
type Surface = modulehttp.Surface
type Provider = modulehttp.Provider

const (
	ExposurePublic      = modulehttp.ExposurePublic
	ExposureTenantAdmin = modulehttp.ExposureTenantAdmin
	ExposureOps         = modulehttp.ExposureOps

	AuthenticationAnonymous     = modulehttp.AuthenticationAnonymous
	AuthenticationAuthenticated = modulehttp.AuthenticationAuthenticated
	AuthenticationService       = modulehttp.AuthenticationService
)
