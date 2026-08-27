package remote

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestApplicationServiceCredentialProtectsCatalogAndDirectoryRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer application-service-secret" {
			t.Fatalf("%s authorization=%q", r.URL.Path, got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/identity/catalog/revision":
			var application identity.ApplicationRef
			if err := json.NewDecoder(r.Body).Decode(&application); err != nil {
				t.Fatal(err)
			}
			if application.WorkspaceID != "workspace-a" || application.ApplicationKey != "runtime-app" {
				t.Fatalf("catalog application=%+v", application)
			}
			_, _ = w.Write([]byte(`{"revision":"revision-1","sha256":"hash","published_at":"2026-01-01T00:00:00Z"}`))
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
	if _, err := (catalogClient{client: client}).CurrentRevision(t.Context(), identity.ApplicationRef{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (directoryClient{client: client}).ListUsers(t.Context(), identity.DirectoryQuery{}); err != nil {
		t.Fatal(err)
	}
}
