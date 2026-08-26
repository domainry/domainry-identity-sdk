package remote

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func (c *Client) Providers(ctx context.Context) ([]identitysdk.Provider, error) {
	var providers []identitysdk.Provider
	if err := c.doJSON(ctx, http.MethodGet, "/auth/providers", "", nil, &providers); err != nil {
		return nil, err
	}
	return providers, nil
}

func (c *Client) StartProvider(ctx context.Context, provider string, request identitysdk.ProviderStartRequest) (identitysdk.ProviderChallenge, error) {
	provider = strings.TrimSpace(provider)
	request.WorkspaceID = c.resolveWorkspace(request.WorkspaceID)
	if provider == "" || request.WorkspaceID == "" {
		return identitysdk.ProviderChallenge{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "auth.provider_request_invalid"}
	}
	var challenge identitysdk.ProviderChallenge
	endpoint := "/auth/providers/" + url.PathEscape(provider) + "/start"
	if err := c.doJSON(ctx, http.MethodPost, endpoint, "", request, &challenge); err != nil {
		return identitysdk.ProviderChallenge{}, err
	}
	return challenge, nil
}

func (c *Client) VerifyProvider(ctx context.Context, provider string, request identitysdk.ProviderVerifyRequest) (identitysdk.AuthSession, error) {
	provider = strings.TrimSpace(provider)
	request.WorkspaceID = c.resolveWorkspace(request.WorkspaceID)
	request.State, request.Code = strings.TrimSpace(request.State), strings.TrimSpace(request.Code)
	if provider == "" || request.WorkspaceID == "" || request.State == "" || request.Code == "" {
		return identitysdk.AuthSession{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "auth.provider_verify_request_invalid"}
	}
	var session identitysdk.AuthSession
	endpoint := "/auth/providers/" + url.PathEscape(provider) + "/verify"
	if err := c.doJSON(ctx, http.MethodPost, endpoint, "", request, &session); err != nil {
		return identitysdk.AuthSession{}, err
	}
	return session, nil
}

func (c *Client) CompleteProviderCallback(ctx context.Context, provider string, callback identitysdk.ProviderCallback) (identitysdk.AuthSession, error) {
	provider = strings.TrimSpace(provider)
	if provider == "" || len(callback.Values) == 0 {
		return identitysdk.AuthSession{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "auth.provider_callback_request_invalid"}
	}
	values := url.Values{}
	for key, value := range callback.Values {
		if key = strings.TrimSpace(key); key != "" {
			values.Set(key, value)
		}
	}
	var session identitysdk.AuthSession
	endpoint := "/auth/providers/" + url.PathEscape(provider) + "/callback"
	if err := c.doForm(ctx, http.MethodPost, endpoint, values, &session); err != nil {
		return identitysdk.AuthSession{}, err
	}
	return session, nil
}
