// Package httpapi defines optional HTTP adapters owned by an in-process
// Identity implementation. Deployment-neutral Runtime code may mount these
// adapters without importing the Identity implementation or duplicating its
// authentication and administration handlers.
package httpapi

import "github.com/domainry/domainry-foundation/modulehttp"

const ContractVersion = modulehttp.ContractVersion

type Exposure = modulehttp.Exposure
type Route = modulehttp.Route
type Adapter = modulehttp.Adapter
type Provider = modulehttp.Provider

const (
	ExposurePublic     = modulehttp.ExposurePublic
	ExposureManagement = modulehttp.ExposureManagement
	ExposureOps        = modulehttp.ExposureOps
)
