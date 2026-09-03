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
