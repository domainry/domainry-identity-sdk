package authorization

import "testing"

func TestWorkspaceBootstrapProjectRoleCatalogSHA256IsCanonicalAndAuthorizationComplete(t *testing.T) {
	roles := []ProjectRoleDefinition{
		{
			Key: "admin", Name: "Administrator", Audience: "any", AssignmentMode: "manual", ProvisionToWorkspaces: true, SchemaHash: "schema-admin",
			Permissions: []ProjectRolePermission{
				{PermissionKey: "customer.write", DataScope: DataScopeOrg},
				{PermissionKey: "customer.read", DataScope: DataScopeAll},
			},
			PermissionSetKeys: []string{"write", "read"},
		},
		{Key: "member", Name: "Member", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true, SchemaHash: "schema-member"},
		{Key: "service", Name: "Service", Audience: "service", AssignmentMode: "system_managed"},
	}
	digest := func(inputs []ProjectRoleDefinition, administrator string) string {
		t.Helper()
		value, err := WorkspaceBootstrapProjectRoleCatalogSHA256(ProjectRoleCatalog{
			Roles: inputs, InitialWorkspaceAdministratorRoleKey: administrator,
		})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	want := digest(roles, "admin")
	reordered := []ProjectRoleDefinition{roles[2], roles[1], roles[0]}
	reordered[2].Permissions = []ProjectRolePermission{roles[0].Permissions[1], roles[0].Permissions[0]}
	reordered[2].PermissionSetKeys = []string{"read", "write"}
	if got := digest(reordered, "admin"); got != want {
		t.Fatalf("semantic reordering changed role catalog digest: got=%s want=%s", got, want)
	}
	changedSchema := append([]ProjectRoleDefinition(nil), roles...)
	changedSchema[0].SchemaHash = "schema-admin-changed"
	if got := digest(changedSchema, "admin"); got == want {
		t.Fatal("schema hash drift was absent from role catalog digest")
	}
	changedPermission := append([]ProjectRoleDefinition(nil), roles...)
	changedPermission[0].Permissions = append([]ProjectRolePermission(nil), roles[0].Permissions...)
	changedPermission[0].Permissions[0].DataScope = DataScopeAll
	if got := digest(changedPermission, "admin"); got == want {
		t.Fatal("permission drift was absent from role catalog digest")
	}
	if got := digest(roles, "member"); got == want {
		t.Fatal("administrator role drift was absent from role catalog digest")
	}
}

func TestWorkspaceBootstrapProjectRoleCatalogSHA256ValidatesTrustedPolicy(t *testing.T) {
	validAdmin := ProjectRoleDefinition{Key: "admin", Name: "Admin", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true}
	for _, test := range []struct {
		name  string
		roles []ProjectRoleDefinition
		admin string
	}{
		{name: "missing administrator", roles: []ProjectRoleDefinition{validAdmin}},
		{name: "unknown administrator", roles: []ProjectRoleDefinition{validAdmin}, admin: "missing"},
		{name: "service provisioned", roles: []ProjectRoleDefinition{validAdmin, {Key: "service", Name: "Service", Audience: "service", AssignmentMode: "system_managed", ProvisionToWorkspaces: true}}, admin: "admin"},
		{name: "request-only administrator", roles: []ProjectRoleDefinition{{Key: "admin", Name: "Admin", Audience: "user", AssignmentMode: "request_only", ProvisionToWorkspaces: true}}, admin: "admin"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := WorkspaceBootstrapProjectRoleCatalogSHA256(ProjectRoleCatalog{Roles: test.roles, InitialWorkspaceAdministratorRoleKey: test.admin}); err == nil {
				t.Fatal("invalid trusted bootstrap role policy was accepted")
			}
		})
	}
}
