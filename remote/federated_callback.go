package remote

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

func (c *client) completeFederatedLogin(ctx context.Context, provider string, values url.Values) (identity.FederatedLoginCompletion, error) {
	if ctx == nil {
		return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.context_required"}
	}
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	if c.breaker != nil && !c.breaker.Allow() {
		return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.circuit_open"}
	}
	requestURL := *c.baseURL
	requestURL.Path = strings.TrimRight(c.baseURL.Path, "/") + "/auth/providers/" + url.PathEscape(provider) + "/callback"
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, requestURL.String(), strings.NewReader(values.Encode()))
	if err != nil {
		return identity.FederatedLoginCompletion{}, err
	}
	copyIdentityHeaders(request.Header, c.contextHeadersFor(requestContext))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", c.userAgent)
	if c.workspaceID != "" {
		request.Header.Set("X-Workspace-ID", c.workspaceID)
	}
	httpClient := *c.httpClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(request)
	if err != nil {
		if c.breaker != nil {
			c.breaker.Observe(true)
		}
		return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.remote_unavailable", Cause: err}
	}
	defer response.Body.Close()
	if c.breaker != nil {
		c.breaker.Observe(response.StatusCode >= http.StatusInternalServerError)
	}
	if response.StatusCode == http.StatusFound || response.StatusCode == http.StatusSeeOther || response.StatusCode == http.StatusTemporaryRedirect || response.StatusCode == http.StatusPermanentRedirect {
		location, parseErr := url.Parse(strings.TrimSpace(response.Header.Get("Location")))
		if parseErr != nil || location == nil {
			return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.provider_redirect_invalid", Cause: parseErr}
		}
		code, state := strings.TrimSpace(location.Query().Get("code")), strings.TrimSpace(location.Query().Get("state"))
		if code == "" {
			return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.provider_authorization_code_missing"}
		}
		query := location.Query()
		query.Del("code")
		query.Del("state")
		location.RawQuery = query.Encode()
		return identity.FederatedLoginCompletion{AuthorizationCode: code, ReturnURL: location.String(), State: state}, nil
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_read_failed", Cause: readErr}
	}
	if len(raw) > maxResponseBytes {
		return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_too_large"}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return identity.FederatedLoginCompletion{}, decodeError(response, raw)
	}
	var completion identity.FederatedLoginCompletion
	if err := json.Unmarshal(raw, &completion); err != nil {
		return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_invalid", Cause: err}
	}
	if strings.TrimSpace(completion.AuthorizationCode) == "" || strings.TrimSpace(completion.ReturnURL) == "" {
		return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.provider_completion_invalid"}
	}
	return completion, nil
}
