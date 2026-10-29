package browsergateway

import (
	"net/http"

	"github.com/domainry/domainry-foundation/modulehttp"
	identity "github.com/domainry/domainry-identity-sdk"
)

// Adapter exposes the SDK-owned browser session gateway through the same
// source-owned HTTP adapter contract used by Runtime modules. It is created by
// project composition for SaaS deployments; a remote Binding never pretends
// to own in-process HTTP routes itself.
type Adapter struct {
	routes  []modulehttp.Route
	handler http.Handler
}

func NewAdapter(binding identity.Binding, config Config) (*Adapter, error) {
	gateway, err := New(binding, config)
	if err != nil {
		return nil, err
	}
	definitions, err := ActionDefinitions("")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	if err := gateway.RegisterRoutes(mux, ""); err != nil {
		return nil, err
	}
	routes := make([]modulehttp.Route, 0, len(definitions))
	for _, definition := range definitions {
		routes = append(routes, modulehttp.Route{Action: definition})
	}
	return &Adapter{routes: routes, handler: mux}, nil
}

func (*Adapter) ContractVersion() string { return modulehttp.ContractVersion }
func (*Adapter) Owner() string           { return "identity" }
func (*Adapter) Name() string            { return "saas_browser_gateway" }
func (adapter *Adapter) Routes() []modulehttp.Route {
	return append([]modulehttp.Route(nil), adapter.routes...)
}
func (adapter *Adapter) Handler() http.Handler { return adapter.handler }

var _ modulehttp.Adapter = (*Adapter)(nil)
