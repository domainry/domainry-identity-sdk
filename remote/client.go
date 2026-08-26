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

const maxResponseBytes = 4 << 20

type Config struct {
	BaseURL     string
	WorkspaceID string
	HTTPClient  *http.Client
	UserAgent   string
}

type Client struct {
	baseURL     *url.URL
	workspaceID string
	httpClient  *http.Client
	userAgent   string
}

var _ identitysdk.Client = (*Client)(nil)

func New(config Config) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(config.BaseURL))
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
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	userAgent := strings.TrimSpace(config.UserAgent)
	if userAgent == "" {
		userAgent = "domainry-identity-sdk-go"
	}
	return &Client{
		baseURL: baseURL, workspaceID: strings.TrimSpace(config.WorkspaceID),
		httpClient: httpClient, userAgent: userAgent,
	}, nil
}

func (c *Client) WorkspaceID() string {
	if c == nil {
		return ""
	}
	return c.workspaceID
}

func (c *Client) doJSON(ctx context.Context, method, endpoint, accessToken string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode Identity request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	return c.do(ctx, method, endpoint, accessToken, "application/json", body, output)
}

func (c *Client) doForm(ctx context.Context, method, endpoint string, values url.Values, output any) error {
	return c.do(ctx, method, endpoint, "", "application/x-www-form-urlencoded", strings.NewReader(values.Encode()), output)
}

func (c *Client) do(ctx context.Context, method, endpoint, accessToken, contentType string, body io.Reader, output any) error {
	if c == nil || c.baseURL == nil || c.httpClient == nil {
		return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.client_unavailable"}
	}
	requestURL := *c.baseURL
	requestURL.Path = strings.TrimRight(c.baseURL.Path, "/") + "/" + strings.TrimLeft(endpoint, "/")
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return fmt.Errorf("build Identity request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", c.userAgent)
	if body != nil && contentType != "" {
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
		return &identitysdk.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.remote_unavailable", Cause: err}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return &identitysdk.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_read_failed", Cause: err}
	}
	if len(raw) > maxResponseBytes {
		return &identitysdk.Error{StatusCode: http.StatusBadGateway, Code: "identity.response_too_large"}
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
