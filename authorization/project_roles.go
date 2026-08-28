package authorization

import (
	"context"
	"encoding/json"
)

// ProjectRoleDefinition is the deployment-neutral projection of one
// application-owned role. Policy collections remain canonical JSON so the SDK
// does not take ownership of an application's metadata model.
type ProjectRoleDefinition struct {
	Key                  string          `json:"key"`
	Name                 string          `json:"name"`
	Permissions          []string        `json:"permissions,omitempty"`
	RecordScope          string          `json:"record_scope,omitempty"`
	DataPermissions      json.RawMessage `json:"data_permissions,omitempty"`
	FieldPermissions     json.RawMessage `json:"field_permissions,omitempty"`
	ReferencePermissions json.RawMessage `json:"reference_permissions,omitempty"`
	ExportRules          json.RawMessage `json:"export_rules,omitempty"`
	Audience             string          `json:"audience,omitempty"`
	RequiredBindingKey   string          `json:"required_binding_key,omitempty"`
	AssignmentMode       string          `json:"assignment_mode,omitempty"`
	RiskLevel            string          `json:"risk_level,omitempty"`
	ConflictRoleKeys     []string        `json:"conflict_role_keys,omitempty"`
	GrantableRoleKeys    []string        `json:"grantable_role_keys,omitempty"`
	PermissionSetKeys    []string        `json:"permission_set_keys,omitempty"`
	PermissionSetGroups  []string        `json:"permission_set_group_keys,omitempty"`
	GuardrailKeys        []string        `json:"guardrail_keys,omitempty"`
	Guardrails           json.RawMessage `json:"guardrails,omitempty"`
	SchemaHash           string          `json:"schema_hash"`
}

type ProjectRoleCatalog struct {
	Application ApplicationRef          `json:"application"`
	Roles       []ProjectRoleDefinition `json:"roles"`
}

type ProjectRoleCatalogReceipt struct {
	Published int    `json:"published"`
	SHA256    string `json:"sha256"`
}

type ProjectRoleCatalogPublisher interface {
	PublishProjectRoles(context.Context, ProjectRoleCatalog) (ProjectRoleCatalogReceipt, error)
}
