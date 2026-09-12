package remote

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestWorkflowWorkloadClientUsesApplicationCredentialAndExactReleaseScope(t *testing.T) {
	bindings := []identity.WorkflowWorkloadBindingSpec{{
		WorkflowKey: "settlement", DefinitionVersionID: "version-2", DefinitionVersion: 2,
		RoleKey: "settlement_service", ActionKeys: []string{"payment.settle"},
	}}
	digest, err := identity.WorkflowWorkloadReleaseDigest(bindings)
	if err != nil {
		t.Fatal(err)
	}
	releaseID := identity.WorkflowWorkloadReleaseID(digest)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer application-service-secret" {
			t.Fatalf("%s authorization=%q", r.URL.Path, got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "PUT /identity/workflow-workloads":
			var request identity.ApplyWorkflowWorkloadBindingsRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Application != (identity.ApplicationScope{TenantID: "workspace-a", WorkspaceID: "workspace-a", ApplicationKey: "runtime-app"}) || request.ReleaseID != releaseID || request.ReleaseDigest != digest || !reflect.DeepEqual(request.Bindings, bindings) {
				t.Fatalf("apply request=%+v", request)
			}
			_ = json.NewEncoder(w).Encode(identity.ApplyWorkflowWorkloadBindingsResult{Bindings: []identity.WorkflowWorkloadBinding{{
				Application: request.Application, SubjectID: "workflow:settlement", WorkflowKey: "settlement",
				DefinitionVersionID: "version-2", DefinitionVersion: 2, RoleKey: "settlement_service",
				ActionKeys: []string{"payment.settle"}, ReleaseID: releaseID, ReleaseDigest: digest,
				SourceKind: "deployment_control_plane", SourceID: "runtime-app", Status: identity.WorkflowWorkloadBindingActive,
			}}})
		case "POST /identity/workflow-workloads/resolve":
			var request identity.GetWorkflowWorkloadBindingRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Application != (identity.ApplicationScope{TenantID: "workspace-a", WorkspaceID: "workspace-a", ApplicationKey: "runtime-app"}) || request.WorkflowKey != "settlement" || request.DefinitionVersionID != "version-2" || request.ReleaseDigest != digest {
				t.Fatalf("resolve request=%+v", request)
			}
			_ = json.NewEncoder(w).Encode(identity.WorkflowWorkloadBinding{
				Application: request.Application, SubjectID: "workflow:settlement", WorkflowKey: request.WorkflowKey,
				DefinitionVersionID: request.DefinitionVersionID, DefinitionVersion: 2, RoleKey: "settlement_service",
				ActionKeys: []string{"payment.settle"}, ReleaseID: releaseID, ReleaseDigest: request.ReleaseDigest,
				SourceKind: "deployment_control_plane", SourceID: "runtime-app", Status: identity.WorkflowWorkloadBindingActive,
			})
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
	workloads := workflowWorkloads{client: client}
	result, err := workloads.ApplyWorkflowWorkloadBindings(t.Context(), identity.ApplyWorkflowWorkloadBindingsRequest{
		ReleaseID: releaseID, ReleaseDigest: digest, Bindings: bindings,
	})
	if err != nil || len(result.Bindings) != 1 || result.Bindings[0].SubjectID != "workflow:settlement" || result.Bindings[0].SourceKind != "deployment_control_plane" {
		t.Fatalf("apply result=%+v err=%v", result, err)
	}
	resolved, err := workloads.GetWorkflowWorkloadBinding(t.Context(), identity.GetWorkflowWorkloadBindingRequest{
		WorkflowKey: "settlement", DefinitionVersionID: "version-2", ReleaseDigest: digest,
	})
	if err != nil || resolved.RoleKey != "settlement_service" || resolved.ReleaseID != releaseID {
		t.Fatalf("resolve result=%+v err=%v", resolved, err)
	}
	if _, err := workloads.GetWorkflowWorkloadBinding(t.Context(), identity.GetWorkflowWorkloadBindingRequest{
		Application: identity.ApplicationScope{WorkspaceID: "workspace-b", ApplicationKey: "runtime-app"},
		WorkflowKey: "settlement", DefinitionVersionID: "version-2", ReleaseDigest: digest,
	}); err == nil {
		t.Fatal("cross-workspace workload lookup was accepted")
	}
	if requests != 2 {
		t.Fatalf("remote requests=%d want=2", requests)
	}
}
