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

type authorizationStub struct {
	decision identitysdk.AccessDecision
	err      error
	request  identitysdk.DecisionRequest
	calls    int
}

func (stub *authorizationStub) ResolveAccess(context.Context, identitysdk.AccessBundleRequest) (identitysdk.AccessBundle, error) {
	return identitysdk.AccessBundle{}, errors.New("not used")
}

func (stub *authorizationStub) Reauthorize(_ context.Context, request identitysdk.DecisionRequest) (identitysdk.AccessDecision, error) {
	stub.calls++
	stub.request = request
	return stub.decision, stub.err
}

func (stub *authenticatorStub) Authenticate(_ context.Context, token string) (identitysdk.Principal, error) {
	stub.calls++
	stub.token = token
	return stub.principal, stub.err
}

func permissionBundle(permissions ...string) *identitysdk.AccessBundle {
	bundle := &identitysdk.AccessBundle{}
	for _, permission := range permissions {
		resource, action, ok := strings.Cut(permission, ".")
		if !ok {
			continue
		}
		bundle.FunctionGrants = append(bundle.FunctionGrants, identitysdk.FunctionGrant{
			Resource: identitysdk.ResourceType(resource), Action: identitysdk.Action(action), Effect: identitysdk.EffectAllow,
		})
		bundle.DataPolicies = append(bundle.DataPolicies, identitysdk.DataPolicy{
			Key: permission, Resource: identitysdk.ResourceType(resource), Action: identitysdk.Action(action), Effect: identitysdk.EffectAllow,
			DataScopes: []identitysdk.DataScope{identitysdk.DataScopeAll},
		})
	}
	return bundle
}

func TestAuthenticatePublishesIdentityAndRejectsCredentials(t *testing.T) {
	stub := &authenticatorStub{principal: identitysdk.Principal{Known: true, UserID: "user-1", AccessBundle: permissionBundle("order.read")}}
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
	identity := identitysdk.RequestIdentity{Principal: identitysdk.Principal{Known: true, UserID: "user", AccessBundle: permissionBundle("order.read", "order.export")}}
	request := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(identitysdk.WithRequestIdentity(context.Background(), identity))

	for _, handler := range []http.Handler{
		middleware.RequirePermission("order.read", next),
		middleware.RequirePermission("order.export", next),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
	}
	if nextCalls != 2 {
		t.Fatalf("next calls = %d", nextCalls)
	}

	denied := httptest.NewRecorder()
	middleware.RequirePermission("order.write", next).ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "auth.permission_denied") {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}

	empty := httptest.NewRecorder()
	middleware.RequirePermission(" ", next).ServeHTTP(empty, request)
	if empty.Code != http.StatusForbidden || !strings.Contains(empty.Body.String(), "auth.permission_required") {
		t.Fatalf("empty status=%d body=%s", empty.Code, empty.Body.String())
	}

	unauthenticated := httptest.NewRecorder()
	middleware.RequirePermission("order.read", next).ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", unauthenticated.Code)
	}
}

func TestRequirePasswordChangedOwnsTemporaryPasswordBusinessGate(t *testing.T) {
	middleware, _ := New(&authenticatorStub{})
	nextCalls := 0
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ })

	for _, fixture := range []struct {
		name      string
		principal *identitysdk.Principal
		status    int
	}{
		{name: "missing identity", status: http.StatusUnauthorized},
		{name: "temporary password", principal: &identitysdk.Principal{Known: true, UserID: "user", MustChangePassword: true}, status: http.StatusForbidden},
		{name: "password changed", principal: &identitysdk.Principal{Known: true, UserID: "user"}, status: http.StatusOK},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/business", nil)
			if fixture.principal != nil {
				request = request.WithContext(identitysdk.WithRequestIdentity(request.Context(), identitysdk.RequestIdentity{Principal: *fixture.principal}))
			}
			response := httptest.NewRecorder()
			middleware.RequirePasswordChanged(next).ServeHTTP(response, request)
			if response.Code != fixture.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if nextCalls != 1 {
		t.Fatalf("next calls=%d", nextCalls)
	}
}

func TestRouteGuardHelpersUseOnlySDKRequestIdentity(t *testing.T) {
	middleware, err := New(&authenticatorStub{principal: identitysdk.Principal{
		Known: true, UserID: "user-a", WorkspaceID: "workspace-a", AccessBundle: permissionBundle("workspace.admin"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	protected := middleware.AuthenticatedFunc(middleware.PermissionFunc("workspace.admin")(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "/admin", nil)
	response := httptest.NewRecorder()
	protected(response, request)
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("route guard accepted a host-only request: status=%d called=%t", response.Code, called)
	}

	request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.Header.Set("Authorization", "Bearer token")
	response = httptest.NewRecorder()
	middleware.Authenticate(http.HandlerFunc(protected)).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("route guard rejected SDK identity: status=%d called=%t body=%s", response.Code, called, response.Body.String())
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

func TestRequireReauthorizationUsesOnlineDecisionAndFacts(t *testing.T) {
	authorization := &authorizationStub{decision: identitysdk.AccessDecision{Allowed: true}}
	middleware, err := New(&authenticatorStub{}, WithAuthorization(authorization))
	if err != nil {
		t.Fatal(err)
	}
	nextCalls := 0
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ })
	identity := identitysdk.RequestIdentity{Principal: identitysdk.Principal{Known: true, UserID: "user"}, AccessToken: "access-token"}
	request := httptest.NewRequest(http.MethodDelete, "/orders/1", nil).WithContext(identitysdk.WithRequestIdentity(context.Background(), identity))
	handler := middleware.RequireReauthorization(identitysdk.AccessRequest{ObjectKey: "order", Action: "delete", RecordID: "1"}, func(*http.Request) identitysdk.ResourceFacts {
		return identitysdk.ResourceFacts{"owner_id": "user"}
	}, next)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if nextCalls != 1 || authorization.calls != 1 || authorization.request.Identity.AccessToken != "access-token" || authorization.request.Facts["owner_id"] != "user" {
		t.Fatalf("next=%d calls=%d request=%#v", nextCalls, authorization.calls, authorization.request)
	}

	authorization.decision.Allowed = false
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || nextCalls != 1 {
		t.Fatalf("denied status=%d next=%d", response.Code, nextCalls)
	}

	authorization.err = errors.New("offline")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || nextCalls != 1 {
		t.Fatalf("failed status=%d next=%d", response.Code, nextCalls)
	}

	withoutAuthorization, _ := New(&authenticatorStub{})
	response = httptest.NewRecorder()
	withoutAuthorization.RequireReauthorization(identitysdk.AccessRequest{}, nil, next).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing authorization status=%d", response.Code)
	}
}
