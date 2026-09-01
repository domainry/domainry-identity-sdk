package remote

import (
	"context"
	"net/http"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

type ContextHeaderProvider = func(context.Context) http.Header

type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type CircuitBreakerPolicy struct {
	FailureThreshold int
	OpenDuration     time.Duration
}

type Config struct {
	Endpoint                 string
	TenantID                 string
	WorkspaceID              string
	Issuer                   string
	Audience                 string
	ServiceAccessToken       string
	CapabilityContractSHA256 string
	HTTPClient               *http.Client
	UserAgent                string
	RequestTimeout           time.Duration
	Retry                    RetryPolicy
	CircuitBreaker           CircuitBreakerPolicy
	ContextHeaders           ContextHeaderProvider
	Clock                    identity.Clock
}

func normalizedConfig(config Config) Config {
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.Retry.MaxAttempts <= 0 {
		config.Retry.MaxAttempts = 2
	}
	if config.Retry.InitialBackoff <= 0 {
		config.Retry.InitialBackoff = 50 * time.Millisecond
	}
	if config.Retry.MaxBackoff <= 0 {
		config.Retry.MaxBackoff = 500 * time.Millisecond
	}
	if config.Retry.MaxBackoff < config.Retry.InitialBackoff {
		config.Retry.MaxBackoff = config.Retry.InitialBackoff
	}
	if config.CircuitBreaker.FailureThreshold <= 0 {
		config.CircuitBreaker.FailureThreshold = 5
	}
	if config.CircuitBreaker.OpenDuration <= 0 {
		config.CircuitBreaker.OpenDuration = 5 * time.Second
	}
	if config.Clock == nil {
		config.Clock = remoteSystemClock{}
	}
	return config
}

type remoteSystemClock struct{}

func (remoteSystemClock) Now() time.Time { return time.Now().UTC() }
