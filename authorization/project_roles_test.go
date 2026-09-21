package authorization

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProjectRolePermissionCarriesItsOwnClosedDataScope(t *testing.T) {
	want := []DataScope{DataScopeAll, DataScopeOwner, DataScopeOrg, DataScopeOrgChild, DataScopeTargetOrg}
	if got := DataScopeValues(); !reflect.DeepEqual(got, want) {
		t.Fatalf("data scope values = %v, want %v", got, want)
	}
	for _, scope := range want {
		if !scope.Valid() {
			t.Fatalf("canonical scope %q is invalid", scope)
		}
	}
	for _, scope := range []DataScope{"", "none", "custom", "all_records", "owned_records", "organization", "organization_and_children", "self_and_subordinates"} {
		if scope.Valid() {
			t.Fatalf("legacy scope %q is valid", scope)
		}
	}

	raw, err := json.Marshal(ProjectRoleDefinition{Key: "operator", Name: "Operator", Permissions: []ProjectRolePermission{{PermissionKey: "customer.read", DataScope: DataScopeOrgChild}, {PermissionKey: "customer.approve", DataScope: DataScopeTargetOrg}}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "record_scope") || strings.Contains(text, "data_permissions") || !strings.Contains(text, `"permission_key":"customer.read","data_scope":"org_child"`) || !strings.Contains(text, `"permission_key":"customer.approve","data_scope":"target_org"`) {
		t.Fatalf("project role wire contract = %s", text)
	}
}

func TestProjectRoleCatalogPreservesApplicationObjectCatalog(t *testing.T) {
	catalog := ProjectRoleCatalog{
		Application:                          ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"},
		Objects:                              json.RawMessage(`[{"key":"customer","fields":[{"key":"name"}]}]`),
		Roles:                                []ProjectRoleDefinition{},
		InitialWorkspaceAdministratorRoleKey: "crm_acceptance_admin",
	}
	payload, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip ProjectRoleCatalog
	if err := json.Unmarshal(payload, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.InitialWorkspaceAdministratorRoleKey != "" || strings.Contains(string(payload), "crm_acceptance_admin") {
		t.Fatalf("trusted bootstrap role leaked through JSON: %s", payload)
	}
	var objects []struct {
		Key    string `json:"key"`
		Fields []struct {
			Key string `json:"key"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(roundTrip.Objects, &objects); err != nil || len(objects) != 1 || objects[0].Key != "customer" || len(objects[0].Fields) != 1 || objects[0].Fields[0].Key != "name" {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
}

func TestProjectRolePermissionCompilesClosedRelationalDataPolicy(t *testing.T) {
	policy := ProjectDataPolicy{
		Operator: ProjectDataPolicyAnd,
		Children: []ProjectDataPolicy{
			{Operator: ProjectDataPolicyEq, FieldKey: "workspace_id", SubjectClaim: ProjectSubjectClaimWorkspaceID},
			{
				Operator: ProjectDataPolicyIn,
				Path:     []ProjectDataPolicyRelationSegment{{Direction: RelationForward, RelationFieldKey: "customer_id", TargetObjectKey: "customer"}},
				FieldKey: "organization_id", SubjectClaim: ProjectSubjectClaimOrgScopeIDs,
			},
		},
	}
	permission := ProjectRolePermission{PermissionKey: "order.read", DataPolicy: &policy}
	if err := permission.Validate(); err != nil {
		t.Fatalf("valid relational data policy: %v", err)
	}
	predicate, err := policy.Predicate()
	if err != nil {
		t.Fatal(err)
	}
	if len(predicate.All) != 2 || predicate.All[0].Fact != "workspace_id" || predicate.All[0].Operator != OperatorEqual || predicate.All[0].Value != "$subject.workspace_id" {
		t.Fatalf("compiled direct predicate = %#v", predicate)
	}
	if got := predicate.All[1]; got.Fact != "organization_id" || got.Operator != OperatorIn || got.Value != "$subject.org_scope_ids" || len(got.Path) != 1 || got.Path[0].Reference != "customer_id" || got.Path[0].TargetResource != "customer" {
		t.Fatalf("compiled relation predicate = %#v", got)
	}
}

func TestProjectRolePermissionRejectsAmbiguousOrOpenEndedPolicies(t *testing.T) {
	tests := []ProjectRolePermission{
		{PermissionKey: "order.read"},
		{PermissionKey: "order.read", DataScope: DataScopeAll, DataPolicy: &ProjectDataPolicy{Operator: ProjectDataPolicyEq, FieldKey: "owner_id", SubjectClaim: ProjectSubjectClaimID}},
		{PermissionKey: "order.read", DataPolicy: &ProjectDataPolicy{Operator: "sql", FieldKey: "owner_id", SubjectClaim: ProjectSubjectClaimID}},
		{PermissionKey: "order.read", DataPolicy: &ProjectDataPolicy{Operator: ProjectDataPolicyEq, FieldKey: "owner_id", SubjectClaim: ProjectSubjectClaimOrgScopeIDs}},
		{PermissionKey: "order.read", DataPolicy: &ProjectDataPolicy{Operator: ProjectDataPolicyIn, FieldKey: "owner_id", SubjectClaim: ProjectSubjectClaimID}},
		{PermissionKey: "order.read", DataPolicy: &ProjectDataPolicy{Operator: ProjectDataPolicyEq, FieldKey: "owner_id", SubjectClaim: "business_role"}},
	}
	for index, permission := range tests {
		if err := permission.Validate(); err == nil {
			t.Fatalf("invalid permission %d was accepted: %#v", index, permission)
		}
	}
}
