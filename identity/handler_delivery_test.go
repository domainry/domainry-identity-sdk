package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHandlerContractsDoNotSerializeBearerOrDerivedAuthority(t *testing.T) {
	request := HandlerDeliveryRequest{
		ContractVersion: CurrentHandlerDeliveryContractVersion, AccessToken: "secret-bearer", IdempotencyKey: "delivery-1",
		User: HandlerUserMutation{Operation: HandlerUserCreate, LoginMode: HandlerLoginPassword, User: User{UserID: "user-1"}}, RoleKeys: []string{"member"},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "secret-bearer") || strings.Contains(string(payload), "workspace") || strings.Contains(string(payload), "actor") {
		t.Fatalf("serialized handler authority: %s", payload)
	}
	if !HandlerUserCreate.Valid() || !HandlerUserUpdate.Valid() || !HandlerUserDisable.Valid() || HandlerUserOperation("other").Valid() {
		t.Fatal("handler operation validation contract changed")
	}
	resultPayload, err := json.Marshal(HandlerDeliveryResult{InitialCredential: &HandlerInitialCredential{
		InitialPassword: "one-time-secret", MustChangePassword: true, NoStore: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(resultPayload), "one-time-secret") {
		t.Fatalf("serialized initial credential: %s", resultPayload)
	}
}

func TestHandlerBoundIdentityCarriesOnlyRequestedBindingCAS(t *testing.T) {
	request := HandlerBoundIdentityRequest{
		ContractVersion: CurrentHandlerDeliveryContractVersion,
		AccessToken:     "secret-bearer",
		UserID:          "user-1",
		ProfileBinding:  &HandlerProfileBindingSelector{BindingKey: "employee", ObjectKey: "employee_profile", ProfileID: "profile-1"},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "secret-bearer") || !strings.Contains(string(payload), `"profile_id":"profile-1"`) {
		t.Fatalf("serialized bound-identity request=%s", payload)
	}
	resultPayload, err := json.Marshal(HandlerBoundIdentity{
		UserID: "user-1",
		ProfileBinding: &HandlerProfileBinding{
			BindingKey: "employee", ObjectKey: "employee_profile", ProfileID: "profile-1", IdentityUserID: "user-1", Status: "active", Version: 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"binding_key":"employee"`, `"object_key":"employee_profile"`, `"version":7`} {
		if !strings.Contains(string(resultPayload), expected) {
			t.Fatalf("bound-identity result omitted %s: %s", expected, resultPayload)
		}
	}
}

func TestHandlerContractsDoNotSerializeWorkloadAuthority(t *testing.T) {
	authority := &HandlerWorkloadAuthority{
		WorkspaceID: "workspace-1", SubjectID: "workflow:directory-sync", RoleKey: "directory_sync_service",
		WorkflowKey: "directory-sync", DefinitionVersionID: "definition-1", DefinitionVersion: 3,
		ReleaseID: "release-1", ReleaseDigest: "release-digest", TaskID: "task-1", SourceEventID: "event-1",
	}
	for _, request := range []any{
		HandlerDeliveryRequest{ContractVersion: CurrentHandlerDeliveryContractVersion, WorkloadAuthority: authority},
		HandlerBoundIdentityRequest{ContractVersion: CurrentHandlerDeliveryContractVersion, WorkloadAuthority: authority},
	} {
		payload, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"workspace-1", "workflow:directory-sync", "release-digest", "task-1"} {
			if strings.Contains(string(payload), forbidden) {
				t.Fatalf("serialized workload authority %q: %s", forbidden, payload)
			}
		}
	}
}
