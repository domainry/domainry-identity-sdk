package httpmiddleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type authenticatorStub struct {
	principal identitysdk.Principal
	err       error
	token     string
	calls     int
}

func (stub *authenticatorStub) Authenticate(_ context.Context, token string) (identitysdk.Principal, error) {
	stub.calls++
	stub.token = token
	return stub.principal, stub.err
}

func TestAuthenticatePublishesIdentityAndRejectsCredentials(t *testing.T) {
	stub := &authenticatorStub{principal: identitysdk.Principal{Known: true, UserID: "user-1", Permissions: []string{"order.read"}}}
	middleware, err := New(stub)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := identitysdk.RequestIdentityFromContext(r.Context())
		if !ok || identity.Principal.UserID != "user-1" || identity.AccessToken != "token-1" {
			t.Fatalf("identity = %#v ok=%v", identity, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "bearer token-1")
	response := httptest.NewRecorder()
	middleware.Authenticate(next).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || stub.calls != 1 || stub.token != "token-1" {
		t.Fatalf("status=%d calls=%d token=%q", response.Code, stub.calls, stub.token)
	}

	for _, header := range []string{"", "Basic token", "Bearer", "Bearer one two"} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", header)
		response := httptest.NewRecorder()
		middleware.Authenticate(next).ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "auth.token_required") {
			t.Fatalf("header=%q status=%d body=%s", header, response.Code, response.Body.String())
		}
	}
}

func TestAuthenticateFailsClosedAndPreservesServiceOutage(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		stub   *authenticatorStub
		status int
		code   string
	}{
		{name: "invalid", stub: &authenticatorStub{err: errors.New("invalid")}, status: http.StatusUnauthorized, code: "auth.token_invalid"},
		{name: "unknown", stub: &authenticatorStub{principal: identitysdk.Principal{}}, status: http.StatusUnauthorized, code: "auth.token_invalid"},
		{name: "remote unavailable", stub: &authenticatorStub{err: &identitysdk.Error{StatusCode: 503, Code: "backend.unavailable"}}, status: http.StatusServiceUnavailable, code: "auth.service_unavailable"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			middleware, _ := New(fixture.stub)
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			middleware.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler called") })).ServeHTTP(response, request)
			if response.Code != fixture.status || !strings.Contains(response.Body.String(), fixture.code) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestPermissionGatesRequireAuthenticatedContext(t *testing.T) {
	middleware, _ := New(&authenticatorStub{})
	nextCalls := 0
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ })
	identity := identitysdk.RequestIdentity{Principal: identitysdk.Principal{Known: true, UserID: "user", Permissions: []string{"order.read", "order.export"}}}
	request := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(identitysdk.WithRequestIdentity(context.Background(), identity))

	for _, handler := range []http.Handler{
		middleware.RequirePermission("order.read", next),
		middleware.RequireAllPermissions([]string{"order.read", "order.export"}, next),
		middleware.RequireAnyPermission([]string{"missing", "order.export"}, next),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
	}
	if nextCalls != 3 {
		t.Fatalf("next calls = %d", nextCalls)
	}

	denied := httptest.NewRecorder()
	middleware.RequirePermission("order.write", next).ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "auth.permission_denied") {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}

	unauthenticated := httptest.NewRecorder()
	middleware.RequirePermission("order.read", next).ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", unauthenticated.Code)
	}
}

func TestNewAndCustomErrorWriter(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil authenticator accepted")
	}
	writtenCode := ""
	middleware, _ := New(&authenticatorStub{}, WithErrorWriter(func(w http.ResponseWriter, _ *http.Request, status int, code string) {
		writtenCode = code
		w.WriteHeader(status)
	}))
	response := httptest.NewRecorder()
	middleware.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusUnauthorized || writtenCode != "auth.token_required" {
		t.Fatalf("status=%d code=%q", response.Code, writtenCode)
	}
}
