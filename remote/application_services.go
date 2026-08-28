package remote

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type applicationServices struct{ client *client }

func (adapter applicationServices) Exchange(ctx context.Context, request identity.ExchangeApplicationServiceTokenRequest) (identity.ApplicationServiceToken, error) {
	if strings.TrimSpace(request.Credential) == "" && adapter.client != nil {
		request.Credential = adapter.client.serviceAccessToken
	}
	if err := request.Validate(); err != nil {
		return identity.ApplicationServiceToken{}, err
	}
	payload := request
	payload.Credential = ""
	var token identity.ApplicationServiceToken
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/application-service/token", request.Credential, payload, &token); err != nil {
		return identity.ApplicationServiceToken{}, err
	}
	return token, nil
}

func (adapter applicationServices) Verify(ctx context.Context, request identity.VerifyApplicationServiceTokenRequest) (identity.ApplicationServicePrincipal, error) {
	if strings.TrimSpace(request.AccessToken) == "" || !request.Audience.Valid() || !request.Grant.Valid() {
		return identity.ApplicationServicePrincipal{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.application_service_verify_invalid"}
	}
	var principal identity.ApplicationServicePrincipal
	headers := http.Header{}
	headers.Set("X-Domainry-Tenant-ID", adapter.client.tenantID)
	headers.Set("X-Domainry-Workspace-ID", adapter.client.workspaceID)
	if err := adapter.client.doJSONWithHeaders(ctx, http.MethodPost, "/identity/application-service/verify", adapter.client.serviceAccessToken, request, &principal, headers); err != nil {
		return identity.ApplicationServicePrincipal{}, err
	}
	return principal, nil
}
