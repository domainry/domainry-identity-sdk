package application

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type applicationServices struct{ binding *binding }

type applicationServiceVerifier struct{ binding *binding }

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
	return verifyApplicationServiceToken(ctx, value.binding, request)
}

func (value applicationServiceVerifier) Verify(ctx context.Context, request identity.VerifyApplicationServiceTokenRequest) (identity.ApplicationServicePrincipal, error) {
	return verifyApplicationServiceToken(ctx, value.binding, request)
}

func verifyApplicationServiceToken(ctx context.Context, binding *binding, request identity.VerifyApplicationServiceTokenRequest) (identity.ApplicationServicePrincipal, error) {
	if request.Audience == "" {
		request.Audience = binding.application.ApplicationKey
	} else if request.Audience != binding.application.ApplicationKey {
		return identity.ApplicationServicePrincipal{}, scopeError(http.StatusForbidden, "identity.application_mismatch")
	}
	if capability, ok := binding.delegate.(identity.ApplicationServiceVerificationBinding); ok && capability.ApplicationServiceVerifier() != nil {
		return capability.ApplicationServiceVerifier().Verify(ctx, request)
	}
	if capability, ok := binding.delegate.(identity.ApplicationServiceBinding); ok && capability.ApplicationServices() != nil {
		return capability.ApplicationServices().Verify(ctx, request)
	}
	return identity.ApplicationServicePrincipal{}, scopeError(http.StatusNotImplemented, "identity.application_service_verification_unavailable")
}

var _ identity.ApplicationServiceAuthentication = applicationServices{}
var _ identity.ApplicationServiceTokenVerifier = applicationServiceVerifier{}
