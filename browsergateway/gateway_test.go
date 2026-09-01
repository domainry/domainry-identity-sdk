package browsergateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/modulecapability"
	identity "github.com/domainry/domainry-identity-sdk"
)

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
func (testBinding) Directory() identity.Directory                   { return nil }
func (testBinding) Catalog() identity.CatalogClient                 { return nil }
func (binding testBinding) Credentials() identity.CredentialManager { return binding.credentials }
func (testBinding) Close(context.Context) error                     { return nil }

type testAuthentication struct {
	loginRequest   identity.PasswordLoginRequest
	loginSession   identity.AuthSession
	refreshRequest identity.RefreshRequest
	refreshError   error
	logoutError    error
}

func (*testAuthentication) Providers(context.Context, identity.ProviderQuery) ([]identity.Provider, error) {
	return []identity.Provider{{Key: "local", Type: "password", Enabled: true}}, nil
}
func (authentication *testAuthentication) LoginWithPassword(_ context.Context, request identity.PasswordLoginRequest) (identity.AuthSession, error) {
	authentication.loginRequest = request
	if authentication.loginSession.AccessToken != "" {
		return authentication.loginSession, nil
	}
	return browserSession("login-refresh"), nil
}
func (*testAuthentication) BeginFederatedLogin(context.Context, identity.BeginFederatedLoginRequest) (identity.ProviderChallenge, error) {
	return identity.ProviderChallenge{}, nil
}
func (*testAuthentication) CompleteFederatedLogin(context.Context, identity.CompleteFederatedLoginRequest) (identity.FederatedLoginCompletion, error) {
	return identity.FederatedLoginCompletion{}, nil
}
func (*testAuthentication) ExchangeAuthorizationCode(context.Context, identity.ExchangeAuthorizationCodeRequest) (identity.AuthSession, error) {
	return browserSession("code-refresh"), nil
}
func (*testAuthentication) VerifyOTP(context.Context, identity.VerifyOTPRequest) (identity.AuthSession, error) {
	return browserSession("otp-refresh"), nil
}
func (authentication *testAuthentication) RefreshSession(_ context.Context, request identity.RefreshRequest) (identity.AuthSession, error) {
	authentication.refreshRequest = request
	if authentication.refreshError != nil {
		return identity.AuthSession{}, authentication.refreshError
	}
	return browserSession("rotated-refresh"), nil
}
func (authentication *testAuthentication) LogoutSession(context.Context, identity.LogoutRequest) error {
	return authentication.logoutError
}
func (*testAuthentication) CurrentSession(context.Context, identity.CurrentSessionRequest) (identity.SessionView, error) {
	return identity.SessionView{WorkspaceID: "workspace-primary", SubjectID: "user-1"}, nil
}

type testCredentials struct{}

func (testCredentials) ChangePassword(context.Context, identity.ChangePasswordRequest) (identity.AuthSession, error) {
	return browserSession("password-refresh"), nil
}
func (testCredentials) ResetPassword(context.Context, identity.ResetPasswordRequest) error {
	return nil
}
func (testCredentials) RevokeSessions(context.Context, identity.RevokeSessionsRequest) error {
	return nil
}

func browserSession(refreshToken string) identity.AuthSession {
	return identity.AuthSession{WorkspaceID: "workspace-primary", AccessToken: "access", RefreshToken: refreshToken, TokenType: "Bearer"}
}

func newTestGateway(t *testing.T, authentication *testAuthentication) *http.ServeMux {
	t.Helper()
	gateway, err := New(testBinding{auth: authentication}, Config{
		ApplicationKey: "identity-admin", AllowedReturnURLs: []string{"http://localhost:3100/auth/callback"},
		DefaultWorkspaceID: "workspace-primary",
		Cookie:             CookieConfig{Path: "/browser/auth", MaxAge: time.Hour},
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

	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "login-refresh") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control=%q", response.Header().Get("Cache-Control"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != DefaultRefreshCookieName || cookies[0].Value != "login-refresh" || !cookies[0].HttpOnly || cookies[0].Path != "/browser/auth" || cookies[0].SameSite != http.SameSiteLaxMode {
		if len(cookies) == 1 {
			t.Fatalf("cookie=%s name=%q value=%q httpOnly=%v path=%q sameSite=%v", cookies[0].String(), cookies[0].Name, cookies[0].Value, cookies[0].HttpOnly, cookies[0].Path, cookies[0].SameSite)
		}
		t.Fatalf("cookies=%#v", cookies)
	}
	if authentication.loginRequest.ApplicationKey != "identity-admin" || authentication.loginRequest.WorkspaceID != "workspace-primary" {
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
	if response.Code != http.StatusOK || authentication.refreshRequest.RefreshToken != "cookie-refresh" || strings.Contains(response.Body.String(), "rotated-refresh") {
		t.Fatalf("status=%d request=%#v body=%s", response.Code, authentication.refreshRequest, response.Body.String())
	}
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
