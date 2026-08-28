package application

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type applicationServices struct{ binding *binding }

func (value applicationServices) delegate() (identity.ApplicationServiceAuthentication, error) {
	capability, ok := value.binding.delegate.(identity.ApplicationServiceBinding)
	if !ok || capability.ApplicationServices() == nil {
		return nil, scopeError(http.StatusNotImplemented, "identity.application_service_authentication_unavailable")
	}
	return capability.ApplicationServices(), nil
}

func (value applicationServices) Exchange(ctx context.Context, request identity.ExchangeApplicationServiceTokenRequest) (identity.ApplicationServiceToken, error) {
	request.Application = value.binding.application
	capability, err := value.delegate()
	if err != nil {
		return identity.ApplicationServiceToken{}, err
	}
	return capability.Exchange(ctx, request)
}

func (value applicationServices) Verify(ctx context.Context, request identity.VerifyApplicationServiceTokenRequest) (identity.ApplicationServicePrincipal, error) {
	if request.Audience == "" {
		request.Audience = value.binding.application.ApplicationKey
	} else if request.Audience != value.binding.application.ApplicationKey {
		return identity.ApplicationServicePrincipal{}, scopeError(http.StatusForbidden, "identity.application_mismatch")
	}
	capability, err := value.delegate()
	if err != nil {
		return identity.ApplicationServicePrincipal{}, err
	}
	return capability.Verify(ctx, request)
}
