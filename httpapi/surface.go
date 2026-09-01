// Package httpapi defines optional HTTP surfaces owned by an in-process
// Identity implementation. Deployment-neutral Runtime code may mount these
// surfaces without importing the Identity implementation or duplicating its
// authentication and administration handlers.
package httpapi

import "github.com/domainry/domainry-foundation/modulehttp"

const ContractVersion = modulehttp.ContractVersion

type Exposure = modulehttp.Exposure
type Route = modulehttp.Route
type Surface = modulehttp.Surface
type Provider = modulehttp.Provider

const (
	ExposurePublic      = modulehttp.ExposurePublic
	ExposureTenantAdmin = modulehttp.ExposureTenantAdmin
	ExposureOps         = modulehttp.ExposureOps
)
