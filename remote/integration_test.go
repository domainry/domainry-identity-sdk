package remote

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	identitysdk "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/httpmiddleware"
)

func TestIdentityIntegrationPasswordSession(t *testing.T) {
	baseURL := os.Getenv("IDENTITY_SDK_INTEGRATION_URL")
	login := os.Getenv("IDENTITY_SDK_INTEGRATION_LOGIN")
	password := os.Getenv("IDENTITY_SDK_INTEGRATION_PASSWORD")
	workspaceID := os.Getenv("IDENTITY_SDK_INTEGRATION_WORKSPACE_ID")
	if baseURL == "" || login == "" || password == "" || workspaceID == "" {
		t.Skip("Identity SDK integration environment is not configured")
	}
	client, err := New(Config{BaseURL: baseURL, WorkspaceID: workspaceID})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Login(t.Context(), identitysdk.LoginRequest{Login: login, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Fatal("Identity login returned incomplete credentials")
	}
	principal, err := client.Authenticate(t.Context(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known || principal.UserID == "" || principal.WorkspaceID != workspaceID {
		t.Fatalf("principal identity mismatch: known=%v user=%q workspace=%q", principal.Known, principal.UserID, principal.WorkspaceID)
	}
	security, err := httpmiddleware.New(client)
	if err != nil {
		t.Fatal(err)
	}
	protected := security.Authenticate(security.RequirePermission("workspace.admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolved, ok := identitysdk.PrincipalFromContext(r.Context())
		if !ok || resolved.UserID != principal.UserID {
			t.Fatalf("middleware principal mismatch: %#v ok=%v", resolved, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+session.AccessToken)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("protected middleware status=%d body=%s", response.Code, response.Body.String())
	}
	if err := client.Logout(t.Context(), session.RefreshToken); err != nil {
		t.Fatal(err)
	}
}
