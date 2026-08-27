package remote

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func retryableIdentityRequest(method, endpoint string, headers http.Header) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut:
		return true
	}
	if strings.TrimSpace(headers.Get("Idempotency-Key")) != "" {
		return true
	}
	switch "/" + strings.TrimLeft(endpoint, "/") {
	case "/identity/access-bundle", "/identity/reauthorize", "/identity/catalog/revision":
		return true
	default:
		return false
	}
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryableTransportError(ctx context.Context, err error) bool {
	var tooLarge *identityResponseTooLargeError
	if errors.As(err, &tooLarge) {
		return false
	}
	return ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

func (c *client) retryDelay(attempt int, response *http.Response) time.Duration {
	delay := c.retry.InitialBackoff
	for index := 1; index < attempt && delay < c.retry.MaxBackoff; index++ {
		delay *= 2
		if delay > c.retry.MaxBackoff {
			delay = c.retry.MaxBackoff
		}
	}
	if response != nil {
		if retryAfter := retryAfterDuration(response.Header.Get("Retry-After"), c.breaker.clock.Now()); retryAfter > delay {
			delay = retryAfter
		}
	}
	if delay > c.retry.MaxBackoff {
		return c.retry.MaxBackoff
	}
	return delay
}

func retryAfterDuration(raw string, now time.Time) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(raw); err == nil && when.After(now) {
		return when.Sub(now)
	}
	return 0
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
