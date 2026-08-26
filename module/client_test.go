package module

import (
	"net/http"
	"testing"
)

func TestClientAuthenticatesThroughInProcessHandler(t *testing.T) {
	calls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Host != "identity.module" || r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("request host=%q authorization=%q", r.Host, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/me":
			_, _ = w.Write([]byte(`{"user":{"id":"user-1"},"roles":[],"default_role":"member","permissions":["order.read"]}`))
		case "/identity/principal-context":
			_, _ = w.Write([]byte(`{"contract_version":"domainry-principal-context-v1","known":true,"workspace_id":"workspace-a","user_id":"user-1","reporting_user_ids":[],"organization_scopes":{"team_ids":[],"store_ids":[],"territory_ids":[],"warehouse_ids":[]},"business_profiles":[],"request_contexts":[]}`))
		default:
			http.NotFound(w, r)
		}
	})
	client, err := New(Config{Handler: handler, WorkspaceID: "workspace-a"})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := client.Authenticate(t.Context(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Known || principal.UserID != "user-1" || !principal.HasPermission("order.read") || calls != 2 {
		t.Fatalf("principal=%#v calls=%d", principal, calls)
	}
}

func TestClientRequiresHandler(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("nil handler accepted")
	}
}
