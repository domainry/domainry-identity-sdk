package remote

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestApplicationServicesExchangeAndVerifyKeepStaticCredentialAtIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/identity/application-service/token":
			if request.Header.Get("Authorization") != "Bearer static-credential" {
				t.Fatalf("exchange authorization=%q", request.Header.Get("Authorization"))
			}
			var input identity.ExchangeApplicationServiceTokenRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.Credential != "" || input.Application.ApplicationKey != "orders-runtime" || input.Audience != "domainry-notification" {
				t.Fatalf("exchange input=%+v", input)
			}
			_ = json.NewEncoder(response).Encode(identity.ApplicationServiceToken{AccessToken: "short-token", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Minute)})
		case "/identity/application-service/verify":
			if request.Header.Get("Authorization") != "Bearer static-credential" {
				t.Fatalf("verify authorization=%q", request.Header.Get("Authorization"))
			}
			if request.Header.Get("X-Domainry-Tenant-ID") != "tenant-a" || request.Header.Get("X-Domainry-Workspace-ID") != "workspace-a" {
				t.Fatalf("verify scope headers=%v", request.Header)
			}
			var input identity.VerifyApplicationServiceTokenRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.AccessToken != "short-token" || input.Audience != "domainry-notification" || input.Grant.Resource != "notification_event" {
				t.Fatalf("verify input=%+v", input)
			}
			_ = json.NewEncoder(response).Encode(identity.ApplicationServicePrincipal{SubjectID: "service:orders-runtime", Audience: "domainry-notification"})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)
	client, err := newClient(Config{Endpoint: server.URL, TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "orders-runtime", ServiceAccessToken: "static-credential", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	capability := applicationServices{client: client}
	grant := identity.ApplicationServiceGrant{Resource: "notification_event", Action: "publish"}
	token, err := capability.Exchange(t.Context(), identity.ExchangeApplicationServiceTokenRequest{
		Application: identity.ApplicationRef{TenantID: "tenant-a", WorkspaceID: "workspace-a", ApplicationKey: "orders-runtime"},
		Audience:    "domainry-notification", Grants: []identity.ApplicationServiceGrant{grant},
	})
	if err != nil || token.AccessToken != "short-token" {
		t.Fatalf("token=%+v err=%v", token, err)
	}
	principal, err := capability.Verify(t.Context(), identity.VerifyApplicationServiceTokenRequest{AccessToken: token.AccessToken, Audience: "domainry-notification", Grant: grant})
	if err != nil || principal.SubjectID != "service:orders-runtime" {
		t.Fatalf("principal=%+v err=%v", principal, err)
	}
}
