package remote

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestRemoteFactoryConfigurationComesFromCompositionEnvironment(t *testing.T) {
	t.Setenv("IDENTITY_ENDPOINT", " https://identity.example.test ")
	t.Setenv("IDENTITY_TENANT_ID", " tenant-a ")
	t.Setenv("IDENTITY_WORKSPACE_ID", " workspace-a ")
	t.Setenv("IDENTITY_ISSUER", " https://issuer.example.test ")
	t.Setenv("IDENTITY_AUDIENCE", " runtime-app ")
	t.Setenv("IDENTITY_SERVICE_ACCESS_TOKEN", " service-token ")
	t.Setenv("IDENTITY_USER_AGENT", " domainry-runtime/test ")
	config := ConfigFromEnvironment()
	if config.Endpoint != "https://identity.example.test" || config.TenantID != "tenant-a" || config.WorkspaceID != "workspace-a" || config.Issuer != "https://issuer.example.test" ||
		config.Audience != "runtime-app" || config.ServiceAccessToken != "service-token" || config.UserAgent != "domainry-runtime/test" {
		t.Fatalf("environment configuration = %#v", config)
	}
}

func newTestClient(t *testing.T, handler http.Handler) *client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := newClient(Config{Endpoint: server.URL, WorkspaceID: "workspace-a", Audience: "runtime-app", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestAuthenticationAndOnlineAuthorization(t *testing.T) {
	calls := []string{}
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer access-token" || r.Header.Get("X-Workspace-ID") != "workspace-a" {
			t.Fatalf("headers = %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/session":
			_, _ = w.Write([]byte(`{"session_id":"session-1","tenant_id":"tenant-a","workspace_id":"workspace-a","subject_id":"user-1","authorization_revision":"revision-1","user":{"id":"user-1","name":"Ada","status":"active"},"roles":[{"id":"role-1","key":"admin","label":"Admin"}],"default_role":"admin","permissions":["order.write","order.read"],"must_change_password":false}`))
		case "/identity/reauthorize":
			var request struct {
				Access identity.AccessRequest `json:"access"`
				Facts  identity.ResourceFacts `json:"facts"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Access.ObjectKey != "order" || request.Access.Action != "read" || request.Access.RecordID != "order-1" || request.Facts["owner_id"] != "user-1" {
				t.Fatalf("access request = %#v", request)
			}
			_, _ = w.Write([]byte(`{"user_id":"user-1","object_key":"order","action":"read","record_id":"order-1","allowed":true,"authorization_revision":"revision-1","reason":{"code":"effective_access_allowed","effect":"allow","layer":"effective"}}`))
		default:
			http.NotFound(w, r)
		}
	}))

	authentication := authentication{client: client}
	session, err := authentication.CurrentSession(t.Context(), identity.CurrentSessionRequest{AccessToken: "access-token"})
	if err != nil || session.SubjectID != "user-1" || session.WorkspaceID != "workspace-a" || session.DefaultRole != "admin" {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	// Reauthorization authenticates the bearer token on the Identity server;
	// the remote transport must not trust or require a caller-supplied user ID.
	principal := identity.Principal{Known: true, WorkspaceID: "workspace-a"}
	decision, err := (authorization{client: client}).Reauthorize(t.Context(), identity.DecisionRequest{
		Identity: identity.RequestIdentity{Principal: principal, AccessToken: "access-token"},
		Access:   identity.AccessRequest{ObjectKey: " order ", Action: " read ", RecordID: " order-1 "},
		Facts:    identity.ResourceFacts{"owner_id": "user-1"},
	})
	if err != nil || !decision.Allowed || len(calls) != 2 {
		t.Fatalf("decision=%#v calls=%v err=%v", decision, calls, err)
	}
	if _, err := authentication.CurrentSession(t.Context(), identity.CurrentSessionRequest{}); err == nil {
		t.Fatal("empty access token accepted")
	}
	if _, err := (authorization{client: client}).Reauthorize(t.Context(), identity.DecisionRequest{}); err == nil {
		t.Fatal("unknown identity accepted")
	}
}

func TestPasswordAndProviderFlows(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/login":
			var request identity.PasswordLoginRequest
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.WorkspaceID != "workspace-a" || request.ApplicationKey != "runtime-app" || request.Login != "admin@example.com" || request.Password != "password" {
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
			var request identity.BeginFederatedLoginRequest
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request.ApplicationKey != "runtime-app" {
				t.Fatalf("provider application key=%q", request.ApplicationKey)
			}
			_, _ = w.Write([]byte(`{"provider":"oidc","state":"state-1","nonce":"nonce-1","auth_url":"https://login.example/authorize","expires_at":"2026-01-01T00:00:00Z"}`))
		case "/auth/providers/otp/verify":
			_, _ = w.Write([]byte(`{"workspace_id":"workspace-a","access_token":"otp-access","refresh_token":"otp-refresh","token_type":"Bearer","user":{"id":"user-1"}}`))
		case "/auth/providers/oidc/callback":
			if err := r.ParseForm(); err != nil || r.Form.Get("state") != "state-1" || r.Form.Get("code") != "code-1" {
				t.Fatalf("callback form=%v err=%v", r.Form, err)
			}
			http.Redirect(w, r, "http://localhost:3100/auth/callback?code=domainry-code&state=state-1", http.StatusSeeOther)
		default:
			http.NotFound(w, r)
		}
	}))
	authentication := authentication{client: client}

	session, err := authentication.LoginWithPassword(t.Context(), identity.PasswordLoginRequest{Login: " admin@example.com ", Password: "password", WorkspaceID: "workspace-a"})
	if err != nil || session.AccessToken != "access-1" || session.RefreshToken != "refresh-1" {
		t.Fatalf("login session=%#v err=%v", session, err)
	}
	refreshed, err := authentication.RefreshSession(t.Context(), identity.RefreshRequest{WorkspaceID: "workspace-a", RefreshToken: "refresh-1"})
	if err != nil || refreshed.AccessToken != "access-2" {
		t.Fatalf("refresh session=%#v err=%v", refreshed, err)
	}
	if err := authentication.LogoutSession(t.Context(), identity.LogoutRequest{WorkspaceID: "workspace-a", RefreshToken: "refresh-2"}); err != nil {
		t.Fatal(err)
	}
	providers, err := authentication.Providers(t.Context(), identity.ProviderQuery{WorkspaceID: "workspace-a"})
	if err != nil || len(providers) != 1 || providers[0].Key != "oidc" {
		t.Fatalf("providers=%#v err=%v", providers, err)
	}
	challenge, err := authentication.BeginFederatedLogin(t.Context(), identity.BeginFederatedLoginRequest{WorkspaceID: "workspace-a", Provider: "oidc"})
	if err != nil || challenge.State != "state-1" || challenge.AuthURL == "" {
		t.Fatalf("challenge=%#v err=%v", challenge, err)
	}
	otp, err := authentication.VerifyOTP(t.Context(), identity.VerifyOTPRequest{WorkspaceID: "workspace-a", Provider: "otp", State: "state", Code: "123456"})
	if err != nil || otp.AccessToken != "otp-access" {
		t.Fatalf("otp=%#v err=%v", otp, err)
	}
	completion, err := authentication.CompleteFederatedLogin(t.Context(), identity.CompleteFederatedLoginRequest{Provider: "oidc", Values: map[string]string{"state": "state-1", "code": "code-1"}})
	if err != nil || completion.AuthorizationCode != "domainry-code" || completion.ReturnURL != "http://localhost:3100/auth/callback" {
		t.Fatalf("completion=%#v err=%v", completion, err)
	}
}

func TestCredentialMutationsPropagateIdempotencyKeys(t *testing.T) {
	wantKeys := map[string]string{
		"/auth/change-password":        "change-1",
		"/auth/reset-password":         "reset-1",
		"/auth/sessions/revoke-others": "revoke-1",
	}
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Idempotency-Key"), wantKeys[r.URL.Path]; got != want {
			t.Fatalf("%s idempotency key=%q want=%q", r.URL.Path, got, want)
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("%s authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/auth/change-password" {
			_, _ = w.Write([]byte(`{"workspace_id":"workspace-a","access_token":"rotated","refresh_token":"refresh","token_type":"Bearer","user":{"id":"user-1"}}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	credentials := credentialClient{client: client}
	if session, err := credentials.ChangePassword(t.Context(), identity.ChangePasswordRequest{AccessToken: "access-token", CurrentPassword: "old", NewPassword: "new", IdempotencyKey: "change-1"}); err != nil || session.AccessToken != "rotated" {
		t.Fatalf("change session=%#v err=%v", session, err)
	}
	if err := credentials.ResetPassword(t.Context(), identity.ResetPasswordRequest{AccessToken: "access-token", SubjectID: "user-2", NewPassword: "temporary", IdempotencyKey: "reset-1"}); err != nil {
		t.Fatal(err)
	}
	if err := credentials.RevokeSessions(t.Context(), identity.RevokeSessionsRequest{AccessToken: "access-token", SubjectID: "user-1", IdempotencyKey: "revoke-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationAndRemoteErrors(t *testing.T) {
	for _, rawURL := range []string{"", "identity.example.com", "ftp://identity.example.com", "https://identity.example.com?bad=1"} {
		if _, err := newClient(Config{Endpoint: rawURL}); err == nil {
			t.Fatalf("invalid URL accepted: %q", rawURL)
		}
	}

	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "request-1")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"auth.token_invalid","params":{"kind":"expired"}}}`))
	}))
	_, err := (authentication{client: client}).CurrentSession(t.Context(), identity.CurrentSessionRequest{AccessToken: "expired-token"})
	var identityError *identity.Error
	if !errors.As(err, &identityError) || identityError.StatusCode != http.StatusForbidden || identityError.Code != "auth.token_invalid" || identityError.RequestID != "request-1" || identityError.Params["kind"] != "expired" {
		t.Fatalf("error = %#v", err)
	}

	unreachable, _ := newClient(Config{Endpoint: "http://127.0.0.1:1", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}})
	_, err = (authentication{client: unreachable}).CurrentSession(t.Context(), identity.CurrentSessionRequest{AccessToken: "token"})
	if !errors.As(err, &identityError) || identityError.Code != "identity.remote_unavailable" {
		t.Fatalf("unavailable error = %#v", err)
	}
}

func TestDiscoveryRequiresCompatibleSaaSIssuerAndCapabilities(t *testing.T) {
	valid := identity.Descriptor{
		ProtocolVersion: identity.CurrentProtocolVersion,
		BundleVersion:   identity.CurrentPolicyBundleVersion,
		CatalogVersion:  identity.CatalogVersionV1,
		Mode:            identity.DeploymentModeSaaS,
		Issuer:          "https://identity.example.com",
		Capabilities:    []string{"authentication", "token_verification", "authorization", "principal_resolution", "directory_projection", "catalog"},
	}
	if err := validateDiscovery(valid, valid.Issuer); err != nil {
		t.Fatal(err)
	}

	tests := map[string]identity.Descriptor{
		"protocol": func() identity.Descriptor { value := valid; value.ProtocolVersion = "future"; return value }(),
		"mode":     func() identity.Descriptor { value := valid; value.Mode = identity.DeploymentModeModule; return value }(),
		"issuer":   func() identity.Descriptor { value := valid; value.Issuer = "https://other.example.com"; return value }(),
		"capabilities": func() identity.Descriptor {
			value := valid
			value.Capabilities = []string{"authentication"}
			return value
		}(),
	}
	for name, descriptor := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateDiscovery(descriptor, valid.Issuer); err == nil {
				t.Fatalf("invalid discovery accepted: %+v", descriptor)
			}
		})
	}
}

func TestRemoteApplicationUsesExplicitScopeAndRejectsSplitConfiguration(t *testing.T) {
	scope := identity.ApplicationRef{WorkspaceID: "workspace-a", ApplicationKey: "orders-runtime"}
	resolved, application, err := remoteApplication(Config{}, scope)
	if err != nil || resolved.WorkspaceID != "workspace-a" || resolved.Audience != "orders-runtime" || application.WorkspaceID != scope.WorkspaceID || application.ApplicationKey != scope.ApplicationKey {
		t.Fatalf("resolved=%+v application=%+v err=%v", resolved, application, err)
	}
	for name, config := range map[string]Config{
		"workspace":   {WorkspaceID: "workspace-b", Audience: "orders-runtime"},
		"application": {WorkspaceID: "workspace-a", Audience: "billing-runtime"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := remoteApplication(config, scope); err == nil {
				t.Fatalf("split Identity configuration accepted: %+v", config)
			}
		})
	}
	if _, _, err := remoteApplication(Config{}, identity.ApplicationRef{}); err == nil {
		t.Fatal("invalid application scope accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
