package authorization

import (
	"context"
	"encoding/json"
)

// ProjectRoleDefinition is the deployment-neutral projection of one
// application-owned role. Policy collections remain canonical JSON so the SDK
// does not take ownership of an application's metadata model.
type ProjectRoleDefinition struct {
	Key                   string                  `json:"key"`
	Name                  string                  `json:"name"`
	Permissions           []ProjectRolePermission `json:"permissions,omitempty"`
	FieldPermissions      json.RawMessage         `json:"field_permissions,omitempty"`
	ReferencePermissions  json.RawMessage         `json:"reference_permissions,omitempty"`
	ExportRules           json.RawMessage         `json:"export_rules,omitempty"`
	Audience              string                  `json:"audience,omitempty"`
	RequiredBindingKey    string                  `json:"required_binding_key,omitempty"`
	AssignmentMode        string                  `json:"assignment_mode,omitempty"`
	RiskLevel             string                  `json:"risk_level,omitempty"`
	ConflictRoleKeys      []string                `json:"conflict_role_keys,omitempty"`
	GrantableRoleKeys     []string                `json:"grantable_role_keys,omitempty"`
	PermissionSetKeys     []string                `json:"permission_set_keys,omitempty"`
	PermissionSetGroups   []string                `json:"permission_set_group_keys,omitempty"`
	GuardrailKeys         []string                `json:"guardrail_keys,omitempty"`
	Guardrails            json.RawMessage         `json:"guardrails,omitempty"`
	ProvisionToWorkspaces bool                    `json:"provision_to_workspaces,omitempty"`
	SchemaHash            string                  `json:"schema_hash"`
}

// DataScope is the complete authoring vocabulary for record visibility.
// Absence of a Permission grant is the fail-closed state; custom
// predicates belong only to the compiled AccessBundle contract.
type DataScope string

const (
	DataScopeAll       DataScope = "all"
	DataScopeOwner     DataScope = "owner"
	DataScopeOrg       DataScope = "org"
	DataScopeOrgChild  DataScope = "org_child"
	DataScopeTargetOrg DataScope = "target_org"
)

func (scope DataScope) Valid() bool {
	switch scope {
	case DataScopeAll, DataScopeOwner, DataScopeOrg, DataScopeOrgChild, DataScopeTargetOrg:
		return true
	default:
		return false
	}
}

func DataScopeValues() []DataScope {
	return []DataScope{DataScopeAll, DataScopeOwner, DataScopeOrg, DataScopeOrgChild, DataScopeTargetOrg}
}

// ProjectRolePermission is one exact Action Permission grant and its own data
// scope. Different actions on the same resource may deliberately use
// different scopes.
type ProjectRolePermission struct {
	PermissionKey string    `json:"permission_key"`
	DataScope     DataScope `json:"data_scope"`
	AuditDenial   bool      `json:"audit_denial,omitempty"`
}

type ProjectRoleCatalog struct {
	Application ApplicationRef `json:"application"`
	// Objects is the application-owned object/field catalog used to project
	// declared role field permissions into an effective AccessBundle. It stays
	// as canonical JSON so Identity SDK does not take ownership of an
	// application's metadata model.
	Objects json.RawMessage         `json:"objects,omitempty"`
	Roles   []ProjectRoleDefinition `json:"roles"`
}

type ProjectRoleCatalogReceipt struct {
	Published int    `json:"published"`
	SHA256    string `json:"sha256"`
}

type ProjectRoleCatalogPublisher interface {
	PublishProjectRoles(context.Context, ProjectRoleCatalog) (ProjectRoleCatalogReceipt, error)
}
