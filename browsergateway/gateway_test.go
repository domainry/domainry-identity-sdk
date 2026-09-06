package browsergateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulecapability"
	identity "github.com/domainry/domainry-identity-sdk"
)

func TestBrowserGatewayRoutesProjectOneFrozenActionManifest(t *testing.T) {
	definitions, err := ActionDefinitions("/browser")
	if err != nil {
		t.Fatal(err)
	}
	patterns, err := RoutePatterns("/browser")
	if err != nil {
		t.Fatal(err)
	}
	registry := actioncontract.NewRegistry()
	if err := registry.Register(definitions...); err != nil {
		t.Fatal(err)
	}
	if err := registry.Freeze(); err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 14 || len(patterns) != len(definitions) {
		t.Fatalf("definitions=%d patterns=%d", len(definitions), len(patterns))
	}
	for index, definition := range definitions {
		if definition.Permission != nil || definition.HTTP == nil || patterns[index] != definition.HTTP.Method+" "+definition.HTTP.RouteTemplate {
			t.Fatalf("definition[%d]=%#v pattern=%q", index, definition, patterns[index])
		}
		if _, found := registry.ResolveHTTP(definition.HTTP.Method, definition.HTTP.RouteTemplate); !found {
			t.Fatalf("action %q did not resolve", definition.Key)
		}
	}
}

type testBinding struct {
	modulecapability.Binding
	auth        *testAuthentication
	credentials testCredentials
}

func (binding testBinding) Descriptor() identity.Descriptor         { return identity.Descriptor{} }
func (binding testBinding) Authentication() identity.Authentication { return binding.auth }
func (testBinding) Tokens() identity.TokenVerifier                  { return nil }
func (testBinding) Authorization() identity.Authorization           { return nil }
func (testBinding) Principals() identity.PrincipalResolver          { return nil }
func (testBinding) Projection() identity.Projection                 { return nil }
func (testBinding) Applications() identity.ApplicationRegistry      { return nil }
func (testBinding) Permissions() identity.PermissionRegistry        { return nil }
func (binding testBinding) Credentials() identity.CredentialManager { return binding.credentials }
func (testBinding) Close(context.Context) error                     { return nil }

type testAuthentication struct {
	providerQuery   identity.ProviderQuery
	loginRequest    identity.PasswordLoginRequest
	loginSession    identity.AuthSession
	beginRequest    identity.BeginFederatedLoginRequest
	exchangeRequest identity.ExchangeAuthorizationCodeRequest
	verifyRequest   identity.VerifyOTPRequest
	refreshRequest  identity.RefreshRequest
	refreshError    error
	logoutRequest   identity.LogoutRequest
	logoutError     error
	currentRequest  identity.CurrentSessionRequest
	currentSession  identity.SessionView
}

func (authentication *testAuthentication) Providers(_ context.Context, request identity.ProviderQuery) ([]identity.Provider, error) {
	authentication.providerQuery = request
	return []identity.Provider{{Key: "local", Type: "password", Enabled: true}}, nil
}
func (authentication *testAuthentication) LoginWithPassword(_ context.Context, request identity.PasswordLoginRequest) (identity.AuthSession, error) {
	authentication.loginRequest = request
	if authentication.loginSession.AccessToken != "" {
		return authentication.loginSession, nil
	}
	return fakeAuthSession("login-refresh"), nil
}
func (authentication *testAuthentication) BeginFederatedLogin(_ context.Context, request identity.BeginFederatedLoginRequest) (identity.ProviderChallenge, error) {
	authentication.beginRequest = request
	return identity.ProviderChallenge{}, nil
}
func (*testAuthentication) CompleteFederatedLogin(context.Context, identity.CompleteFederatedLoginRequest) (identity.FederatedLoginCompletion, error) {
	return identity.FederatedLoginCompletion{}, nil
}
func (authentication *testAuthentication) ExchangeAuthorizationCode(_ context.Context, request identity.ExchangeAuthorizationCodeRequest) (identity.AuthSession, error) {
	authentication.exchangeRequest = request
	return fakeAuthSession("code-refresh"), nil
}
func (authentication *testAuthentication) VerifyOTP(_ context.Context, request identity.VerifyOTPRequest) (identity.AuthSession, error) {
	authentication.verifyRequest = request
	return fakeAuthSession("otp-refresh"), nil
}
func (authentication *testAuthentication) RefreshSession(_ context.Context, request identity.RefreshRequest) (identity.AuthSession, error) {
	authentication.refreshRequest = request
	if authentication.refreshError != nil {
		return identity.AuthSession{}, authentication.refreshError
	}
	return fakeAuthSession("rotated-refresh"), nil
}
func (authentication *testAuthentication) LogoutSession(_ context.Context, request identity.LogoutRequest) error {
	authentication.logoutRequest = request
	return authentication.logoutError
}
func (authentication *testAuthentication) CurrentSession(_ context.Context, request identity.CurrentSessionRequest) (identity.SessionView, error) {
	authentication.currentRequest = request
	if authentication.currentSession.WorkspaceID.Valid() {
		return authentication.currentSession, nil
	}
	return identity.SessionView{TenantID: "legacy-tenant", WorkspaceID: "workspace-primary", SubjectID: "user-1"}, nil
}

type testCredentials struct{}

func (testCredentials) ChangePassword(context.Context, identity.ChangePasswordRequest) (identity.AuthSession, error) {
	return fakeAuthSession("password-refresh"), nil
}
func (testCredentials) ResetPassword(context.Context, identity.ResetPasswordRequest) error {
	return nil
}
func (testCredentials) RevokeSessions(context.Context, identity.RevokeSessionsRequest) error {
	return nil
}

func fakeAuthSession(refreshToken string) identity.AuthSession {
	return identity.AuthSession{TenantID: "legacy-tenant", WorkspaceID: "workspace-primary", AccessToken: "access", RefreshToken: refreshToken, TokenType: "Bearer"}
}

func newTestGateway(t *testing.T, authentication *testAuthentication) *http.ServeMux {
	t.Helper()
	gateway, err := New(testBinding{auth: authentication}, Config{
		ApplicationKey:     "identity-admin",
		DefaultWorkspaceID: "workspace-primary",
		Cookie:             CookieConfig{Path: "/browser/auth", Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := gateway.RegisterRoutes(mux, "/browser"); err != nil {
		t.Fatal(err)
	}
	return mux
}

func TestGatewayRequiresAnInitializedWorkspace(t *testing.T) {
	for _, workspaceID := range []identity.WorkspaceID{"", "default"} {
		if _, err := New(testBinding{auth: &testAuthentication{}}, Config{ApplicationKey: "identity-admin", DefaultWorkspaceID: workspaceID}); err == nil {
			t.Fatalf("workspace %q was accepted", workspaceID)
		}
	}
}

func TestGatewayKeepsRefreshCredentialInHTTPOnlyCookie(t *testing.T) {
	authentication := &testAuthentication{}
	mux := newTestGateway(t, authentication)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/browser/auth/login", strings.NewReader(`{"workspace_id":"workspace-primary","login":"admin","password":"secret"}`))
	request.Header.Set("X-Workspace-ID", "workspace-primary")
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	assertBrowserBodyOmitsLegacyCredentials(t, response.Body.Bytes())
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control=%q", response.Header().Get("Cache-Control"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != DefaultRefreshCookieName || cookies[0].Value != "login-refresh" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].Path != "/browser/auth" || cookies[0].SameSite != http.SameSiteLaxMode {
		if len(cookies) == 1 {
			t.Fatalf("cookie=%s name=%q value=%q httpOnly=%v path=%q sameSite=%v", cookies[0].String(), cookies[0].Name, cookies[0].Value, cookies[0].HttpOnly, cookies[0].Path, cookies[0].SameSite)
		}
		t.Fatalf("cookies=%#v", cookies)
	}
	if authentication.loginRequest.ApplicationKey != "identity-admin" || authentication.loginRequest.WorkspaceID != "workspace-primary" || authentication.loginRequest.TenantID != "" {
		t.Fatalf("login request=%#v", authentication.loginRequest)
	}
}

func TestGatewayRejectsSessionWithoutRotatingRefreshCredential(t *testing.T) {
	authentication := &testAuthentication{loginSession: identity.AuthSession{
		WorkspaceID: "workspace-primary", AccessToken: "new-access", TokenType: "Bearer",
	}}
	mux := newTestGateway(t, authentication)
	request := httptest.NewRequest(http.MethodPost, "/browser/auth/login", strings.NewReader(`{"workspace_id":"workspace-primary","login":"admin","password":"secret"}`))
	request.AddCookie(&http.Cookie{Name: DefaultRefreshCookieName, Value: "stale-refresh"})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "new-access") || !strings.Contains(response.Body.String(), "identity.refresh_credential_missing") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatalf("stale refresh cookie was not cleared: %#v", cookies)
	}
}

func TestGatewayRefreshAcceptsOnlyCookieCredential(t *testing.T) {
	authentication := &testAuthentication{}
	mux := newTestGateway(t, authentication)

	unsafe := httptest.NewRecorder()
	mux.ServeHTTP(unsafe, httptest.NewRequest(http.MethodPost, "/browser/auth/refresh", strings.NewReader(`{"refresh_token":"javascript-secret"}`)))
	if unsafe.Code != http.StatusBadRequest || authentication.refreshRequest.RefreshToken != "" {
		t.Fatalf("unsafe status=%d request=%#v", unsafe.Code, authentication.refreshRequest)
	}

	request := httptest.NewRequest(http.MethodPost, "/browser/auth/refresh", strings.NewReader(`{}`))
	request.AddCookie(&http.Cookie{Name: DefaultRefreshCookieName, Value: "cookie-refresh"})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || authentication.refreshRequest.RefreshToken != "cookie-refresh" || authentication.refreshRequest.TenantID != "" {
		t.Fatalf("status=%d request=%#v body=%s", response.Code, authentication.refreshRequest, response.Body.String())
	}
	assertBrowserBodyOmitsLegacyCredentials(t, response.Body.Bytes())
}

func TestGatewayClearsInvalidRefreshButKeepsTransientCredential(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		err        error
		wantCookie bool
	}{
		{name: "invalid", err: &identity.Error{StatusCode: http.StatusUnauthorized, Code: "auth.session_expired"}, wantCookie: true},
		{name: "transient", err: &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.remote_unavailable"}, wantCookie: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			authentication := &testAuthentication{refreshError: testCase.err}
			mux := newTestGateway(t, authentication)
			request := httptest.NewRequest(http.MethodPost, "/browser/auth/refresh", strings.NewReader(`{}`))
			request.AddCookie(&http.Cookie{Name: DefaultRefreshCookieName, Value: "cookie-refresh"})
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			cookies := response.Result().Cookies()
			if got := len(cookies) == 1 && cookies[0].MaxAge < 0; got != testCase.wantCookie {
				t.Fatalf("cookies=%#v want cleared=%v", cookies, testCase.wantCookie)
			}
		})
	}
}

func TestGatewayAlwaysClearsBrowserCookieOnLogout(t *testing.T) {
	authentication := &testAuthentication{logoutError: &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.remote_unavailable", Cause: errors.New("offline")}}
	mux := newTestGateway(t, authentication)
	request := httptest.NewRequest(http.MethodPost, "/browser/auth/logout", strings.NewReader(`{}`))
	request.AddCookie(&http.Cookie{Name: DefaultRefreshCookieName, Value: "cookie-refresh"})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	cookies := response.Result().Cookies()
	if response.Code != http.StatusServiceUnavailable || len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatalf("status=%d cookies=%#v body=%s", response.Code, cookies, response.Body.String())
	}
	if authentication.logoutRequest.RefreshToken != "cookie-refresh" || authentication.logoutRequest.TenantID != "" || authentication.logoutRequest.WorkspaceID != "workspace-primary" {
		t.Fatalf("logout request=%#v", authentication.logoutRequest)
	}
}

func TestGatewayRejectsLegacyTenantJSONAtEveryBrowserSessionEntry(t *testing.T) {
	testCases := []struct {
		name string
		path string
		body string
	}{
		{name: "password login", path: "/browser/auth/login", body: `{"login":"admin","password":"secret","tenant_id":"legacy"}`},
		{name: "refresh", path: "/browser/auth/refresh", body: `{"tenant_id":"legacy"}`},
		{name: "logout", path: "/browser/auth/logout", body: `{"tenant_id":"legacy"}`},
		{name: "provider start", path: "/browser/auth/providers/sms/start", body: `{"phone":"+8613800000000","tenant_id":"legacy"}`},
		{name: "provider verify", path: "/browser/auth/providers/sms/verify", body: `{"state":"state-1","code":"123456","tenant_id":"legacy"}`},
		{name: "code exchange", path: "/browser/auth/code/exchange", body: `{"code":"code-1","return_url":"https://app.example.test/callback","tenant_id":"legacy"}`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authentication := &testAuthentication{}
			request := httptest.NewRequest(http.MethodPost, testCase.path, strings.NewReader(testCase.body))
			request.AddCookie(&http.Cookie{Name: DefaultRefreshCookieName, Value: "browser-refresh"})
			response := httptest.NewRecorder()
			newTestGateway(t, authentication).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "backend.invalid_json") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if authentication.loginRequest.Login != "" || authentication.refreshRequest.RefreshToken != "" || authentication.logoutRequest.RefreshToken != "" || authentication.beginRequest.Phone != "" || authentication.verifyRequest.Code != "" || authentication.exchangeRequest.Code != "" {
				t.Fatalf("legacy tenant reached authentication binding: %#v", authentication)
			}
		})
	}
}

func TestGatewayRejectsJavaScriptRefreshCredentialAtEveryBrowserSessionMutation(t *testing.T) {
	testCases := []struct {
		name string
		path string
		body string
	}{
		{name: "password login", path: "/browser/auth/login", body: `{"login":"admin","password":"secret","refresh_token":"javascript-secret"}`},
		{name: "refresh", path: "/browser/auth/refresh", body: `{"refresh_token":"javascript-secret"}`},
		{name: "logout", path: "/browser/auth/logout", body: `{"refresh_token":"javascript-secret"}`},
		{name: "provider start", path: "/browser/auth/providers/sms/start", body: `{"phone":"+8613800000000","refresh_token":"javascript-secret"}`},
		{name: "provider verify", path: "/browser/auth/providers/sms/verify", body: `{"state":"state-1","code":"123456","refresh_token":"javascript-secret"}`},
		{name: "code exchange", path: "/browser/auth/code/exchange", body: `{"code":"code-1","return_url":"https://app.example.test/callback","refresh_token":"javascript-secret"}`},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authentication := &testAuthentication{}
			request := httptest.NewRequest(http.MethodPost, testCase.path, strings.NewReader(testCase.body))
			request.AddCookie(&http.Cookie{Name: DefaultRefreshCookieName, Value: "cookie-refresh"})
			response := httptest.NewRecorder()
			newTestGateway(t, authentication).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "backend.invalid_json") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestGatewayRejectsLegacyTenantSelectorsOutsideJSON(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		path   string
		header bool
	}{
		{name: "query", path: "/browser/auth/session?tenant_id=legacy"},
		{name: "header", path: "/browser/auth/session", header: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			authentication := &testAuthentication{}
			request := httptest.NewRequest(http.MethodGet, testCase.path, nil)
			request.Header.Set("Authorization", "Bearer access")
			if testCase.header {
				request.Header.Set("X-Tenant-ID", "legacy")
			}
			response := httptest.NewRecorder()
			newTestGateway(t, authentication).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "identity.workspace_scope_only") || authentication.currentRequest.AccessToken != "" {
				t.Fatalf("status=%d request=%#v body=%s", response.Code, authentication.currentRequest, response.Body.String())
			}
		})
	}
}

func TestGatewaySessionResponseIsWorkspaceOnly(t *testing.T) {
	authentication := &testAuthentication{currentSession: identity.SessionView{
		SessionID: "session-1", TenantID: "legacy-tenant", WorkspaceID: "workspace-primary", SubjectID: "user-1",
	}}
	request := httptest.NewRequest(http.MethodGet, "/browser/auth/session", nil)
	request.Header.Set("Authorization", "Bearer access")
	response := httptest.NewRecorder()
	newTestGateway(t, authentication).ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || authentication.currentRequest.AccessToken != "access" {
		t.Fatalf("status=%d request=%#v body=%s", response.Code, authentication.currentRequest, response.Body.String())
	}
	assertBrowserBodyOmitsLegacyCredentials(t, response.Body.Bytes())
}

func TestGatewayFederatedRequestsDoNotPropagateLegacyTenantScope(t *testing.T) {
	authentication := &testAuthentication{}
	mux := newTestGateway(t, authentication)

	providers := httptest.NewRecorder()
	mux.ServeHTTP(providers, httptest.NewRequest(http.MethodGet, "/browser/auth/providers", nil))
	if providers.Code != http.StatusOK || authentication.providerQuery.WorkspaceID != "workspace-primary" || authentication.providerQuery.TenantID != "" {
		t.Fatalf("providers status=%d query=%#v body=%s", providers.Code, authentication.providerQuery, providers.Body.String())
	}

	start := httptest.NewRecorder()
	mux.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/browser/auth/providers/sms/start", strings.NewReader(`{"application_key":"untrusted","phone":"+8613800000000"}`)))
	if start.Code != http.StatusOK || authentication.beginRequest.WorkspaceID != "workspace-primary" || authentication.beginRequest.ApplicationKey != "identity-admin" || authentication.beginRequest.TenantID != "" {
		t.Fatalf("start status=%d request=%#v body=%s", start.Code, authentication.beginRequest, start.Body.String())
	}

	verify := httptest.NewRecorder()
	mux.ServeHTTP(verify, httptest.NewRequest(http.MethodPost, "/browser/auth/providers/sms/verify", strings.NewReader(`{"state":"state-1","code":"123456"}`)))
	if verify.Code != http.StatusOK || authentication.verifyRequest.WorkspaceID != "workspace-primary" || authentication.verifyRequest.TenantID != "" {
		t.Fatalf("verify status=%d request=%#v body=%s", verify.Code, authentication.verifyRequest, verify.Body.String())
	}
	assertBrowserBodyOmitsLegacyCredentials(t, verify.Body.Bytes())

	exchange := httptest.NewRecorder()
	mux.ServeHTTP(exchange, httptest.NewRequest(http.MethodPost, "/browser/auth/code/exchange", strings.NewReader(`{"application_key":"untrusted","code":"code-1","return_url":"https://app.example.test/callback"}`)))
	if exchange.Code != http.StatusOK || authentication.exchangeRequest.WorkspaceID != "workspace-primary" || authentication.exchangeRequest.ApplicationKey != "identity-admin" {
		t.Fatalf("exchange status=%d request=%#v body=%s", exchange.Code, authentication.exchangeRequest, exchange.Body.String())
	}
	assertBrowserBodyOmitsLegacyCredentials(t, exchange.Body.Bytes())
}

func TestGatewaySessionRejectsWorkspaceMismatch(t *testing.T) {
	authentication := &testAuthentication{currentSession: identity.SessionView{WorkspaceID: "workspace-secondary", SubjectID: "user-1"}}
	request := httptest.NewRequest(http.MethodGet, "/browser/auth/session", nil)
	request.Header.Set("Authorization", "Bearer access")
	request.Header.Set("X-Workspace-ID", "workspace-primary")
	response := httptest.NewRecorder()
	newTestGateway(t, authentication).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "identity.workspace_scope_mismatch") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGatewayProviderCallbackRejectsLegacyTenantSelector(t *testing.T) {
	authentication := &testAuthentication{}
	response := httptest.NewRecorder()
	newTestGateway(t, authentication).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/browser/auth/providers/oidc/callback?tenant_id=legacy&code=provider-code", nil))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "identity.workspace_scope_only") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func assertBrowserBodyOmitsLegacyCredentials(t *testing.T, body []byte) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode browser response: %v body=%s", err, body)
	}
	if _, found := payload["tenant_id"]; found {
		t.Fatalf("browser response exposed tenant_id: %s", body)
	}
	if _, found := payload["refresh_token"]; found {
		t.Fatalf("browser response exposed refresh_token: %s", body)
	}
}

func TestGatewayRejectsWorkspaceConfusion(t *testing.T) {
	authentication := &testAuthentication{}
	mux := newTestGateway(t, authentication)
	request := httptest.NewRequest(http.MethodPost, "/browser/auth/login", strings.NewReader(`{"workspace_id":"workspace-b","login":"admin","password":"secret"}`))
	request.Header.Set("X-Workspace-ID", "workspace-a")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || authentication.loginRequest.Login != "" {
		t.Fatalf("status=%d request=%#v body=%s", response.Code, authentication.loginRequest, response.Body.String())
	}
}

var _ identity.Binding = testBinding{}
