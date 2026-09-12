package identity

import (
	"errors"
	"testing"
)

func TestWorkflowWorkloadReleaseValidationPinsCanonicalDigest(t *testing.T) {
	bindings := []WorkflowWorkloadBindingSpec{
		{WorkflowKey: " beta ", DefinitionVersionID: "version-2", DefinitionVersion: 2, RoleKey: " role-b ", ActionKeys: []string{"b.execute", "a.execute"}},
		{WorkflowKey: "alpha", DefinitionVersionID: "version-1", DefinitionVersion: 1, RoleKey: "role-a", ActionKeys: []string{"alpha.execute"}},
	}
	digest, err := WorkflowWorkloadReleaseDigest(bindings)
	if err != nil {
		t.Fatal(err)
	}
	request := ApplyWorkflowWorkloadBindingsRequest{
		Application: ApplicationScope{TenantID: "tenant", WorkspaceID: "workspace", ApplicationKey: "runtime"},
		ReleaseID:   WorkflowWorkloadReleaseID(digest), ReleaseDigest: digest, Bindings: bindings,
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	request.ReleaseDigest = "tampered"
	var identityError *Error
	if err := request.Validate(); !errors.As(err, &identityError) || identityError.Code != "identity.workflow_workload_release_digest_mismatch" {
		t.Fatalf("tampered digest error = %v", err)
	}
}

func TestWorkflowWorkloadEmptyReleaseHasStableDigest(t *testing.T) {
	digest, err := WorkflowWorkloadReleaseDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := ApplyWorkflowWorkloadBindingsRequest{
		Application: ApplicationScope{TenantID: "tenant", WorkspaceID: "workspace", ApplicationKey: "runtime"},
		ReleaseID:   WorkflowWorkloadReleaseID(digest), ReleaseDigest: digest,
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
}
