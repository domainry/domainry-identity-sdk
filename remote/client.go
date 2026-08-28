package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

const (
	maxRequestBytes  = 4 << 20
	maxResponseBytes = 4 << 20
)

type client struct {
	baseURL            *url.URL
	tenantID           string
	workspaceID        string
	applicationKey     string
	httpClient         *http.Client
	userAgent          string
	serviceAccessToken string
	requestTimeout     time.Duration
	retry              RetryPolicy
	contextHeaders     ContextHeaderProvider
	breaker            *availabilityCircuitBreaker
}

func newClient(config Config) (*client, error) {
	config = normalizedConfig(config)
	baseURLValue := strings.TrimSpace(config.Endpoint)
	baseURL, err := url.Parse(baseURLValue)
	if err != nil {
		return nil, fmt.Errorf("parse Identity base URL: %w", err)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, errors.New("Identity base URL must use http or https")
	}
	if strings.TrimSpace(baseURL.Host) == "" || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("Identity base URL must contain a host and no query or fragment")
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: config.RequestTimeout}
	}
	userAgent := strings.TrimSpace(config.UserAgent)
	if userAgent == "" {
		userAgent = "domainry-identity-sdk-go"
	}
	return &client{
		baseURL: baseURL, tenantID: strings.TrimSpace(config.TenantID), workspaceID: strings.TrimSpace(config.WorkspaceID), applicationKey: strings.TrimSpace(config.Audience),
		httpClient: httpClient, userAgent: userAgent, serviceAccessToken: strings.TrimSpace(config.ServiceAccessToken),
		requestTimeout: config.RequestTimeout, retry: config.Retry, contextHeaders: config.ContextHeaders,
		breaker: newAvailabilityCircuitBreaker(config.CircuitBreaker, config.Clock),
	}, nil
}

func (c *client) resolveApplication(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" && c != nil {
		value = c.applicationKey
	}
	if value == "" || c != nil && c.applicationKey != "" && value != c.applicationKey {
		return "", &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "identity.application_mismatch"}
	}
	return value, nil
}

func (c *client) resolveWorkspace(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	if c == nil {
		return ""
	}
	return c.workspaceID
}

func (c *client) now() time.Time {
	if c != nil && c.breaker != nil && c.breaker.clock != nil {
		return c.breaker.clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *client) doJSON(ctx context.Context, method, endpoint, accessToken string, input, output any) error {
	return c.doJSONWithHeaders(ctx, method, endpoint, accessToken, input, output, nil)
}

func (c *client) doJSONWithHeaders(ctx context.Context, method, endpoint, accessToken string, input, output any, headers http.Header) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode Identity request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	return c.doWithHeaders(ctx, method, endpoint, accessToken, "application/json", body, output, headers)
}

func (c *client) doForm(ctx context.Context, method, endpoint string, values url.Values, output any) error {
	return c.do(ctx, method, endpoint, "", "application/x-www-form-urlencoded", strings.NewReader(values.Encode()), output)
}

func (c *client) do(ctx context.Context, method, endpoint, accessToken, contentType string, body io.Reader, output any) error {
	return c.doWithHeaders(ctx, method, endpoint, accessToken, contentType, body, output, nil)
}

func (c *client) doWithHeaders(ctx context.Context, method, endpoint, accessToken, contentType string, body io.Reader, output any, headers http.Header) error {
	if c == nil || c.baseURL == nil || c.httpClient == nil {
		return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.client_unavailable"}
	}
	if ctx == nil {
		return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.context_required"}
	}
	requestBody, err := boundedRequestBody(body)
	if err != nil {
		return err
	}
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	attempts := 1
	if retryableIdentityRequest(method, endpoint, headers) {
		attempts = c.retry.MaxAttempts
	}
	var lastError error
	for attempt := 1; attempt <= attempts; attempt++ {
		if c.breaker != nil && !c.breaker.Allow() {
			return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.circuit_open"}
		}
		response, raw, requestErr := c.execute(requestContext, method, endpoint, accessToken, contentType, requestBody, headers)
		availabilityFailure := requestErr != nil || response != nil && response.StatusCode >= http.StatusInternalServerError
		if c.breaker != nil {
			c.breaker.Observe(availabilityFailure)
		}
		if requestErr != nil {
			lastError = identityExecutionError(requestErr)
			if attempt < attempts && retryableTransportError(requestContext, requestErr) {
				if waitErr := waitForRetry(requestContext, c.retryDelay(attempt, nil)); waitErr != nil {
					return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.remote_unavailable", Cause: waitErr}
				}
				continue
			}
			return lastError
		}
		if attempt < attempts && retryableStatus(response.StatusCode) {
			if waitErr := waitForRetry(requestContext, c.retryDelay(attempt, response)); waitErr != nil {
				return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.remote_unavailable", Cause: waitErr}
			}
			continue
		}
		return decodeIdentityResponse(response, raw, output)
	}
	return lastError
}

func identityExecutionError(err error) error {
	var readError *identityResponseReadError
	if errors.As(err, &readError) {
		return &identitysdk.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_read_failed", Cause: err}
	}
	var tooLarge *identityResponseTooLargeError
	if errors.As(err, &tooLarge) {
		return &identitysdk.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_too_large", Cause: err}
	}
	return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.remote_unavailable", Cause: err}
}

func (c *client) execute(ctx context.Context, method, endpoint, accessToken, contentType string, body []byte, headers http.Header) (*http.Response, []byte, error) {
	requestURL := *c.baseURL
	requestURL.Path = strings.TrimRight(c.baseURL.Path, "/") + "/" + strings.TrimLeft(endpoint, "/")
	var requestBody io.Reader
	if body != nil {
		requestBody = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), requestBody)
	if err != nil {
		return nil, nil, fmt.Errorf("build Identity request: %w", err)
	}
	copyIdentityHeaders(request.Header, c.contextHeadersFor(ctx))
	copyIdentityHeaders(request.Header, headers)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", c.userAgent)
	if requestBody != nil && contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if c.workspaceID != "" {
		request.Header.Set("X-Workspace-ID", c.workspaceID)
	}
	if accessToken = strings.TrimSpace(accessToken); accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return response, nil, &identityResponseReadError{cause: err}
	}
	if len(raw) > maxResponseBytes {
		return response, nil, &identityResponseTooLargeError{}
	}
	return response, raw, nil
}

func (c *client) contextHeadersFor(ctx context.Context) http.Header {
	if c.contextHeaders == nil {
		return nil
	}
	return c.contextHeaders(ctx)
}

func boundedRequestBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxRequestBytes+1))
	if err != nil {
		return nil, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.request_read_failed", Cause: err}
	}
	if len(raw) > maxRequestBytes {
		return nil, &identitysdk.Error{StatusCode: http.StatusRequestEntityTooLarge, Code: "identity.request_too_large"}
	}
	return raw, nil
}

func decodeIdentityResponse(response *http.Response, raw []byte, output any) error {
	if response == nil {
		return &identitysdk.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_missing"}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return decodeError(response, raw)
	}
	if output == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, output); err != nil {
		return &identitysdk.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_invalid", Cause: err}
	}
	return nil
}

type identityResponseReadError struct{ cause error }

func (err *identityResponseReadError) Error() string {
	return "read Identity response: " + err.cause.Error()
}
func (err *identityResponseReadError) Unwrap() error { return err.cause }

type identityResponseTooLargeError struct{}

func (*identityResponseTooLargeError) Error() string { return "Identity response exceeds size limit" }

func decodeError(response *http.Response, raw []byte) error {
	payload := struct {
		Code      string            `json:"code"`
		Message   string            `json:"message"`
		Detail    string            `json:"detail"`
		RequestID string            `json:"request_id"`
		Params    map[string]string `json:"params"`
		Error     json.RawMessage   `json:"error"`
	}{}
	_ = json.Unmarshal(raw, &payload)
	if len(payload.Error) > 0 && payload.Code == "" {
		var nested struct {
			Code    string            `json:"code"`
			Message string            `json:"message"`
			Params  map[string]string `json:"params"`
		}
		if json.Unmarshal(payload.Error, &nested) == nil {
			payload.Code, payload.Message = nested.Code, nested.Message
			if len(payload.Params) == 0 {
				payload.Params = nested.Params
			}
		}
	}
	if payload.Code == "" {
		payload.Code = "identity.request_failed"
	}
	if payload.Message == "" {
		payload.Message = payload.Detail
	}
	if payload.RequestID == "" {
		payload.RequestID = strings.TrimSpace(response.Header.Get("X-Request-ID"))
	}
	return &identitysdk.Error{
		StatusCode: response.StatusCode, Code: payload.Code, Message: payload.Message,
		RequestID: payload.RequestID, Params: payload.Params,
	}
}
