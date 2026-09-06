package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type workspaceBootstrapRoleCatalogCanonical struct {
	Roles                                []ProjectRoleDefinition `json:"roles"`
	InitialWorkspaceAdministratorRoleKey string                  `json:"initial_workspace_administrator_role_key"`
}

// WorkspaceBootstrapProjectRoleCatalogSHA256 returns the canonical digest
// bound into Workspace bootstrap receipts and request fingerprints. It
// covers every selected role's complete authorization definition and the
// explicit initial-administrator role.
func WorkspaceBootstrapProjectRoleCatalogSHA256(catalog ProjectRoleCatalog) (string, error) {
	administratorRoleKey := strings.TrimSpace(catalog.InitialWorkspaceAdministratorRoleKey)
	if administratorRoleKey == "" {
		return "", fmt.Errorf("Workspace bootstrap initial administrator role is required")
	}
	seen := make(map[string]bool, len(catalog.Roles))
	selected := make([]ProjectRoleDefinition, 0, len(catalog.Roles))
	administratorFound := false
	for _, input := range catalog.Roles {
		key := strings.TrimSpace(input.Key)
		if key == "" || strings.TrimSpace(input.Name) == "" {
			return "", fmt.Errorf("Workspace bootstrap role key and name are required")
		}
		if seen[key] {
			return "", fmt.Errorf("Workspace bootstrap role %q is duplicated", key)
		}
		seen[key] = true
		normalized, err := normalizeWorkspaceBootstrapRoleDefinition(input)
		if err != nil {
			return "", err
		}
		if !normalized.ProvisionToWorkspaces {
			continue
		}
		if !workspaceBootstrapProvisionableHumanRole(normalized) {
			return "", fmt.Errorf("Workspace bootstrap role %q is not a provisionable human role", key)
		}
		selected = append(selected, normalized)
		if key == administratorRoleKey {
			administratorFound = true
			if !workspaceBootstrapInitialAdministratorRole(normalized) {
				return "", fmt.Errorf("Workspace bootstrap initial administrator role %q is not manually assignable to a user", key)
			}
		}
	}
	if len(selected) == 0 {
		return "", fmt.Errorf("Workspace bootstrap role catalog is empty")
	}
	if !administratorFound {
		return "", fmt.Errorf("Workspace bootstrap initial administrator role %q is not provisioned", administratorRoleKey)
	}
	sort.Slice(selected, func(left, right int) bool { return selected[left].Key < selected[right].Key })
	canonical, err := json.Marshal(workspaceBootstrapRoleCatalogCanonical{
		Roles: selected, InitialWorkspaceAdministratorRoleKey: administratorRoleKey,
	})
	if err != nil {
		return "", fmt.Errorf("encode Workspace bootstrap role catalog: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func workspaceBootstrapProvisionableHumanRole(role ProjectRoleDefinition) bool {
	audience := strings.TrimSpace(role.Audience)
	if audience == "" {
		audience = "any"
	}
	mode := strings.TrimSpace(role.AssignmentMode)
	if mode == "" {
		mode = "manual"
	}
	return (audience == "any" || audience == "user" || audience == "business_profile") &&
		(mode == "manual" || mode == "request_only")
}

func workspaceBootstrapInitialAdministratorRole(role ProjectRoleDefinition) bool {
	audience := strings.TrimSpace(role.Audience)
	if audience == "" {
		audience = "any"
	}
	mode := strings.TrimSpace(role.AssignmentMode)
	if mode == "" {
		mode = "manual"
	}
	return (audience == "any" || audience == "user") && mode == "manual" && strings.TrimSpace(role.RequiredBindingKey) == ""
}

func normalizeWorkspaceBootstrapRoleDefinition(input ProjectRoleDefinition) (ProjectRoleDefinition, error) {
	input.Permissions = append([]ProjectRolePermission(nil), input.Permissions...)
	input.ConflictRoleKeys = append([]string(nil), input.ConflictRoleKeys...)
	input.GrantableRoleKeys = append([]string(nil), input.GrantableRoleKeys...)
	input.PermissionSetKeys = append([]string(nil), input.PermissionSetKeys...)
	input.PermissionSetGroups = append([]string(nil), input.PermissionSetGroups...)
	input.GuardrailKeys = append([]string(nil), input.GuardrailKeys...)
	input.Key = strings.TrimSpace(input.Key)
	input.Name = strings.TrimSpace(input.Name)
	input.Audience = strings.TrimSpace(input.Audience)
	if input.Audience == "" {
		input.Audience = "any"
	}
	input.RequiredBindingKey = strings.TrimSpace(input.RequiredBindingKey)
	input.AssignmentMode = strings.TrimSpace(input.AssignmentMode)
	if input.AssignmentMode == "" {
		input.AssignmentMode = "manual"
	}
	input.RiskLevel = strings.TrimSpace(input.RiskLevel)
	if input.RiskLevel == "" {
		input.RiskLevel = "normal"
	}
	input.SchemaHash = strings.TrimSpace(input.SchemaHash)
	for _, values := range [][]string{
		input.ConflictRoleKeys, input.GrantableRoleKeys, input.PermissionSetKeys,
		input.PermissionSetGroups, input.GuardrailKeys,
	} {
		for index := range values {
			values[index] = strings.TrimSpace(values[index])
		}
		sort.Strings(values)
	}
	for index := range input.Permissions {
		input.Permissions[index].PermissionKey = strings.TrimSpace(input.Permissions[index].PermissionKey)
		if input.Permissions[index].PermissionKey == "" || !input.Permissions[index].DataScope.Valid() {
			return ProjectRoleDefinition{}, fmt.Errorf("Workspace bootstrap role %q has an invalid permission", input.Key)
		}
	}
	sort.Slice(input.Permissions, func(left, right int) bool {
		if input.Permissions[left].PermissionKey != input.Permissions[right].PermissionKey {
			return input.Permissions[left].PermissionKey < input.Permissions[right].PermissionKey
		}
		if input.Permissions[left].DataScope != input.Permissions[right].DataScope {
			return input.Permissions[left].DataScope < input.Permissions[right].DataScope
		}
		return !input.Permissions[left].AuditDenial && input.Permissions[right].AuditDenial
	})
	for index := 1; index < len(input.Permissions); index++ {
		if input.Permissions[index-1].PermissionKey == input.Permissions[index].PermissionKey {
			return ProjectRoleDefinition{}, fmt.Errorf("Workspace bootstrap role %q has duplicate permission %q", input.Key, input.Permissions[index].PermissionKey)
		}
	}
	var err error
	if input.FieldPermissions, err = canonicalWorkspaceBootstrapJSON(input.FieldPermissions); err != nil {
		return ProjectRoleDefinition{}, fmt.Errorf("canonicalize Workspace bootstrap role %q field permissions: %w", input.Key, err)
	}
	if input.ReferencePermissions, err = canonicalWorkspaceBootstrapJSON(input.ReferencePermissions); err != nil {
		return ProjectRoleDefinition{}, fmt.Errorf("canonicalize Workspace bootstrap role %q reference permissions: %w", input.Key, err)
	}
	if input.ExportRules, err = canonicalWorkspaceBootstrapJSON(input.ExportRules); err != nil {
		return ProjectRoleDefinition{}, fmt.Errorf("canonicalize Workspace bootstrap role %q export rules: %w", input.Key, err)
	}
	if input.Guardrails, err = canonicalWorkspaceBootstrapJSON(input.Guardrails); err != nil {
		return ProjectRoleDefinition{}, fmt.Errorf("canonicalize Workspace bootstrap role %q guardrails: %w", input.Key, err)
	}
	return input, nil
}

func canonicalWorkspaceBootstrapJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}
