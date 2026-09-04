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
		Application: ApplicationRef{WorkspaceID: "workspace-primary", ApplicationKey: "runtime"},
		Objects:     json.RawMessage(`[{"key":"customer","fields":[{"key":"name"}]}]`),
		Roles:       []ProjectRoleDefinition{},
	}
	payload, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip ProjectRoleCatalog
	if err := json.Unmarshal(payload, &roundTrip); err != nil {
		t.Fatal(err)
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
