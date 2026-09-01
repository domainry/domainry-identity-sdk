package remote

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestApplicationServiceCredentialProtectsRegistrationAndDirectoryRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer application-service-secret" {
			t.Fatalf("%s authorization=%q", r.URL.Path, got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/identity/applications/current":
			var request identity.ApplicationRegistration
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Application.WorkspaceID != "workspace-a" || request.Application.ApplicationKey != "runtime-app" {
				t.Fatalf("application registration=%+v", request)
			}
			_, _ = w.Write([]byte(`{"application":{"workspace_id":"workspace-a","application_key":"runtime-app"},"status":"active"}`))
		case "/identity/runtime/directory/users":
			var request identity.DirectoryQuery
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Application.TenantID != "workspace-a" || request.Application.WorkspaceID != "workspace-a" || request.Application.ApplicationKey != "runtime-app" {
				t.Fatalf("directory application=%+v", request.Application)
			}
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := newClient(Config{
		Endpoint: server.URL, WorkspaceID: "workspace-a", Audience: "runtime-app",
		ServiceAccessToken: "application-service-secret", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (applicationRegistry{client: client}).Register(t.Context(), identity.ApplicationRegistration{Application: identity.ApplicationRef{WorkspaceID: "workspace-a", ApplicationKey: "runtime-app"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := (directoryClient{client: client}).ListUsers(t.Context(), identity.DirectoryQuery{}); err != nil {
		t.Fatal(err)
	}
}
