package module

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/remote"
)

type Config struct {
	Handler     http.Handler
	WorkspaceID string
	UserAgent   string
}

type Client struct {
	*remote.Client
}

var _ identitysdk.Client = (*Client)(nil)

func New(config Config) (*Client, error) {
	if config.Handler == nil {
		return nil, errors.New("Identity module handler is required")
	}
	httpClient := &http.Client{Transport: handlerTransport{handler: config.Handler}}
	client, err := remote.New(remote.Config{
		BaseURL: "http://identity.module", WorkspaceID: config.WorkspaceID,
		HTTPClient: httpClient, UserAgent: config.UserAgent,
	})
	if err != nil {
		return nil, err
	}
	return &Client{Client: client}, nil
}

type handlerTransport struct {
	handler http.Handler
}

func (transport handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	response := &responseCapture{header: http.Header{}}
	transport.handler.ServeHTTP(response, request)
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	statusCode := response.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     response.header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(response.body.Bytes())),
		Request:    request,
	}, nil
}

type responseCapture struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func (response *responseCapture) Header() http.Header { return response.header }

func (response *responseCapture) WriteHeader(statusCode int) {
	if response.statusCode == 0 {
		response.statusCode = statusCode
	}
}

func (response *responseCapture) Write(value []byte) (int, error) {
	if response.statusCode == 0 {
		response.statusCode = http.StatusOK
	}
	return response.body.Write(value)
}
