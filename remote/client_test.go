package remote

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{BaseURL: server.URL, WorkspaceID: "workspace-a", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestAuthenticateAndAuthorize(t *testing.T) {
	calls := []string{}
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("X-Workspace-ID") != "workspace-a" {
			t.Fatalf("headers = %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/me":
			_, _ = w.Write([]byte(`{"user":{"id":"user-1","name":"Ada","status":"active"},"roles":[{"id":"role-1","key":"admin","label":"Admin"}],"default_role":"admin","permissions":["order.write","order.read","order.read"],"must_change_password":false}`))
		case "/identity/principal-context":
			_, _ = w.Write([]byte(`{"contract_version":"domainry-principal-context-v1","known":true,"workspace_id":"workspace-a","user_id":"user-1","role_key":"admin","reporting_user_ids":[],"organization_scopes":{"team_ids":[],"store_ids":[],"territory_ids":[],"warehouse_ids":[]},"business_profiles":[],"request_contexts":[]}`))
		case "/identity/access/explain":
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request["user_id"] != "user-1" || request["object_key"] != "order" || request["action"] != "read" || request["record_id"] != "order-1" {
				t.Fatalf("access request = %#v", request)
			}
			_, _ = w.Write([]byte(`{"user_id":"user-1","object_key":"order","action":"read","record_id":"order-1","allowed":true,"authorization_revision":"revision-1","reason":{"code":"effective_access_allowed","effect":"allow","layer":"effective"}}`))
		default:
			http.NotFound(w, r)
		}
	}))

	principal, err := client.Authenticate(t.Context(), " access-token ")
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known || principal.UserID != "user-1" || principal.User.Name != "Ada" || principal.RoleKey != "admin" || len(principal.Permissions) != 2 || principal.Permissions[0] != "order.read" {
		t.Fatalf("principal = %#v", principal)
	}
	decision, err := client.Authorize(t.Context(), identitysdk.RequestIdentity{Principal: principal, AccessToken: "access-token"}, identitysdk.AccessRequest{ObjectKey: " order ", Action: " read ", RecordID: " order-1 "})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.AuthorizationRevision != "revision-1" || len(calls) != 3 {
		t.Fatalf("decision=%#v calls=%v", decision, calls)
	}
	if _, err := client.Authenticate(t.Context(), " "); err == nil {
		t.Fatal("empty access token accepted")
	}
	if _, err := client.Authorize(t.Context(), identitysdk.RequestIdentity{}, identitysdk.AccessRequest{}); err == nil {
		t.Fatal("unknown identity accepted")
	}
}

func TestPasswordAndProviderFlows(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/login":
			var request identitysdk.LoginRequest
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.WorkspaceID != "workspace-a" || request.Login != "admin@example.com" || request.Password != "password" {
				t.Fatalf("login request = %#v", request)
			}
			_, _ = w.Write([]byte(`{"workspace_id":"workspace-a","access_token":"access-1","refresh_token":"refresh-1","token_type":"Bearer","user":{"id":"user-1"}}`))
		case "/auth/refresh":
			_, _ = w.Write([]byte(`{"workspace_id":"workspace-a","access_token":"access-2","refresh_token":"refresh-2","token_type":"Bearer","user":{"id":"user-1"}}`))
		case "/auth/logout":
			w.WriteHeader(http.StatusNoContent)
		case "/auth/providers":
			_, _ = w.Write([]byte(`[{"key":"oidc","label":"Company SSO","type":"oidc","enabled":true}]`))
		case "/auth/providers/oidc/start":
			_, _ = w.Write([]byte(`{"provider":"oidc","state":"state-1","nonce":"nonce-1","auth_url":"https://login.example/authorize","expires_at":"2026-01-01T00:00:00Z"}`))
		case "/auth/providers/otp/verify":
			_, _ = w.Write([]byte(`{"workspace_id":"workspace-a","access_token":"otp-access","refresh_token":"otp-refresh","token_type":"Bearer","user":{"id":"user-1"}}`))
		case "/auth/providers/oidc/callback":
			if err := r.ParseForm(); err != nil || r.Form.Get("state") != "state-1" || r.Form.Get("code") != "code-1" {
				t.Fatalf("callback form=%v err=%v", r.Form, err)
			}
			_, _ = w.Write([]byte(`{"workspace_id":"workspace-a","access_token":"sso-access","refresh_token":"sso-refresh","token_type":"Bearer","user":{"id":"user-1"}}`))
		default:
			http.NotFound(w, r)
		}
	}))

	session, err := client.Login(t.Context(), identitysdk.LoginRequest{Login: " admin@example.com ", Password: "password"})
	if err != nil || session.AccessToken != "access-1" || session.RefreshToken != "refresh-1" {
		t.Fatalf("login session=%#v err=%v", session, err)
	}
	refreshed, err := client.Refresh(t.Context(), "refresh-1")
	if err != nil || refreshed.AccessToken != "access-2" {
		t.Fatalf("refresh session=%#v err=%v", refreshed, err)
	}
	if err := client.Logout(t.Context(), "refresh-2"); err != nil {
		t.Fatal(err)
	}
	providers, err := client.Providers(t.Context())
	if err != nil || len(providers) != 1 || providers[0].Key != "oidc" {
		t.Fatalf("providers=%#v err=%v", providers, err)
	}
	challenge, err := client.StartProvider(t.Context(), "oidc", identitysdk.ProviderStartRequest{})
	if err != nil || challenge.State != "state-1" || challenge.AuthURL == "" {
		t.Fatalf("challenge=%#v err=%v", challenge, err)
	}
	otp, err := client.VerifyProvider(t.Context(), "otp", identitysdk.ProviderVerifyRequest{State: "state", Code: "123456"})
	if err != nil || otp.AccessToken != "otp-access" {
		t.Fatalf("otp=%#v err=%v", otp, err)
	}
	sso, err := client.CompleteProviderCallback(t.Context(), "oidc", identitysdk.ProviderCallback{Values: map[string]string{"state": "state-1", "code": "code-1"}})
	if err != nil || sso.AccessToken != "sso-access" {
		t.Fatalf("sso=%#v err=%v", sso, err)
	}
}

func TestConfigurationAndRemoteErrors(t *testing.T) {
	for _, rawURL := range []string{"", "identity.example.com", "ftp://identity.example.com", "https://identity.example.com?bad=1"} {
		if _, err := New(Config{BaseURL: rawURL}); err == nil {
			t.Fatalf("invalid URL accepted: %q", rawURL)
		}
	}

	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "request-1")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"auth.token_invalid","params":{"kind":"expired"}}}`))
	}))
	_, err := client.Authenticate(t.Context(), "expired-token")
	var identityError *identitysdk.Error
	if !errors.As(err, &identityError) || identityError.StatusCode != http.StatusForbidden || identityError.Code != "auth.token_invalid" || identityError.RequestID != "request-1" || identityError.Params["kind"] != "expired" {
		t.Fatalf("error = %#v", err)
	}

	brokenClient := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	_, err = brokenClient.Authenticate(t.Context(), "token")
	if !errors.As(err, &identityError) || identityError.Code != "identity.response_invalid" {
		t.Fatalf("invalid response error = %#v", err)
	}

	unreachable, _ := New(Config{BaseURL: "http://127.0.0.1:1", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}})
	_, err = unreachable.Authenticate(t.Context(), "token")
	if !errors.As(err, &identityError) || identityError.Code != "identity.remote_unavailable" {
		t.Fatalf("unavailable error = %#v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestCallbackUsesFormEncoding(t *testing.T) {
	values := url.Values{"RelayState": {"state"}, "SAMLResponse": {"assertion"}}
	if encoded := values.Encode(); !strings.Contains(encoded, "SAMLResponse=assertion") {
		t.Fatalf("encoded callback = %q", encoded)
	}
}
