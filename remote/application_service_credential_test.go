package remote

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestApplicationServiceCredentialProtectsRegistrationAndProjectionRequests(t *testing.T) {
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
		case "/identity/users/query":
			var request identity.ProjectionQuery
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Application.TenantID != "workspace-a" || request.Application.WorkspaceID != "workspace-a" || request.Application.ApplicationKey != "runtime-app" {
				t.Fatalf("projection application=%+v", request.Application)
			}
			_, _ = w.Write([]byte(`[]`))
		case "/identity/display-names/resolve":
			var request identity.DisplayNameQuery
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Application.TenantID != "workspace-a" || request.Application.WorkspaceID != "workspace-a" || request.Application.ApplicationKey != "runtime-app" {
				t.Fatalf("display-name application=%+v", request.Application)
			}
			if len(request.UserIDs) != 1 || request.UserIDs[0] != "user-1" || len(request.OrganizationUnitIDs) != 1 || request.OrganizationUnitIDs[0] != "org-1" {
				t.Fatalf("display-name query=%+v", request)
			}
			_, _ = w.Write([]byte(`{"users":[{"id":"user-1","name":"Ada"}],"organization_units":[{"id":"org-1","name":"Engineering"}]}`))
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
	if _, err := (projectionClient{client: client}).ListUsers(t.Context(), identity.ProjectionQuery{}); err != nil {
		t.Fatal(err)
	}
	result, err := (projectionClient{client: client}).ResolveDisplayNames(t.Context(), identity.DisplayNameQuery{UserIDs: []string{"user-1"}, OrganizationUnitIDs: []string{"org-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Users) != 1 || result.Users[0].Name != "Ada" || len(result.OrganizationUnits) != 1 || result.OrganizationUnits[0].Name != "Engineering" {
		t.Fatalf("display-name result=%+v", result)
	}
}
