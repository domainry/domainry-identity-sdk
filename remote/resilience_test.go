package remote

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestRemoteClientRetriesOnlyReplaySafeRequests(t *testing.T) {
	var reads atomic.Int32
	var logins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if reads.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.URL.Path == "/auth/login" {
			logins.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := newClient(Config{
		Endpoint: server.URL, WorkspaceID: "workspace-a", Audience: "runtime-app", HTTPClient: server.Client(),
		Retry: RetryPolicy{MaxAttempts: 2, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	var health map[string]string
	if err := client.doJSON(t.Context(), http.MethodGet, "/health", "", nil, &health); err != nil || health["status"] != "ok" || reads.Load() != 2 {
		t.Fatalf("health=%v reads=%d err=%v", health, reads.Load(), err)
	}
	before := reads.Load()
	_, err = (authentication{client: client}).LoginWithPassword(t.Context(), identity.PasswordLoginRequest{WorkspaceID: "workspace-a", Login: "admin@example.com", Password: "password"})
	if err == nil || reads.Load() != before || logins.Load() != 1 {
		t.Fatalf("login err=%v logins=%d unrelated reads=%d", err, logins.Load(), reads.Load())
	}
}

func TestRemoteClientCircuitBreakerUsesOneRecoveryProbe(t *testing.T) {
	clock := &resilienceClock{now: time.Date(2026, 8, 27, 1, 0, 0, 0, time.UTC)}
	var calls atomic.Int32
	var available atomic.Bool
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if !available.Load() {
			return nil, errors.New("identity unavailable")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
	})
	client, err := newClient(Config{
		Endpoint: "https://identity.example.com", WorkspaceID: "workspace-a", Audience: "runtime-app", HTTPClient: &http.Client{Transport: transport}, Clock: clock,
		Retry: RetryPolicy{MaxAttempts: 1}, CircuitBreaker: CircuitBreakerPolicy{FailureThreshold: 2, OpenDuration: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := client.doJSON(t.Context(), http.MethodGet, "/health", "", nil, nil); err == nil {
			t.Fatal("unavailable request succeeded")
		}
	}
	err = client.doJSON(t.Context(), http.MethodGet, "/health", "", nil, nil)
	var sdkError *identity.Error
	if !errors.As(err, &sdkError) || sdkError.Code != "identity.circuit_open" || calls.Load() != 2 {
		t.Fatalf("open circuit err=%#v calls=%d", err, calls.Load())
	}
	clock.Advance(time.Minute + time.Second)
	available.Store(true)
	if err := client.doJSON(t.Context(), http.MethodGet, "/health", "", nil, nil); err != nil || calls.Load() != 3 {
		t.Fatalf("recovery probe err=%v calls=%d", err, calls.Load())
	}
}

func TestRemoteClientPropagatesSafeContextHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Request-ID") != "request-1" || r.Header.Get("traceparent") != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
			t.Fatalf("trace headers=%v", r.Header)
		}
		if r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("X-Workspace-ID") != "workspace-a" || r.Header.Get("Cookie") != "" {
			t.Fatalf("protected headers=%v", r.Header)
		}
		_, _ = w.Write([]byte(`{"session_id":"session-1","tenant_id":"tenant-a","workspace_id":"workspace-a","subject_id":"user-1","authorization_revision":"revision-1","user":{"id":"user-1"}}`))
	}))
	t.Cleanup(server.Close)
	client, err := newClient(Config{
		Endpoint: server.URL, WorkspaceID: "workspace-a", Audience: "runtime-app", HTTPClient: server.Client(),
		ContextHeaders: func(context.Context) http.Header {
			return http.Header{
				"X-Request-ID":   []string{"request-1"},
				"traceparent":    []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
				"Authorization":  []string{"Bearer attacker"},
				"X-Workspace-ID": []string{"other-workspace"},
				"Cookie":         []string{"secret=attacker"},
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := (authentication{client: client}).CurrentSession(t.Context(), identity.CurrentSessionRequest{AccessToken: "access-token"})
	if err != nil || session.SubjectID != "user-1" {
		t.Fatalf("session=%+v err=%v", session, err)
	}
}

func TestRemoteClientEnforcesTotalRequestTimeout(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	client, err := newClient(Config{
		Endpoint: "https://identity.example.com", HTTPClient: &http.Client{Transport: transport}, RequestTimeout: 5 * time.Millisecond,
		Retry: RetryPolicy{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = client.doJSON(t.Context(), http.MethodGet, "/health", "", nil, nil)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("timeout err=%v elapsed=%s", err, time.Since(started))
	}
}

type resilienceClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *resilienceClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *resilienceClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}
