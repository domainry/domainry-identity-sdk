package authorization

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
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
	PermissionKey string             `json:"permission_key"`
	DataScope     DataScope          `json:"data_scope,omitempty"`
	DataPolicy    *ProjectDataPolicy `json:"data_policy,omitempty"`
	AuditDenial   bool               `json:"audit_denial,omitempty"`
}

const (
	ProjectDataPolicyAnd = "and"
	ProjectDataPolicyOr  = "or"
	ProjectDataPolicyNot = "not"
	ProjectDataPolicyEq  = "eq"
	ProjectDataPolicyIn  = "in"

	ProjectSubjectClaimID                    = "id"
	ProjectSubjectClaimWorkspaceID           = "workspace_id"
	ProjectSubjectClaimOrgID                 = "org_id"
	ProjectSubjectClaimOrgScopeIDs           = "org_scope_ids"
	ProjectSubjectClaimSupportOrgID          = "support_org_id"
	ProjectSubjectClaimSupportOrgScopeIDs    = "support_org_scope_ids"
	ProjectSubjectClaimReportingScopeUserIDs = "reporting_scope_user_ids"
	maximumProjectDataPolicyDepth            = 8
	maximumProjectDataPolicyNodes            = 64
)

// ProjectDataPolicy is the only application-authored relational row-policy
// AST. Leaves compare a schema-bound field to one allowlisted Identity subject
// claim; literals, SQL fragments, context claims, and arbitrary callbacks are
// deliberately absent from the protocol.
type ProjectDataPolicy struct {
	Operator     string                             `json:"operator"`
	Path         []ProjectDataPolicyRelationSegment `json:"path,omitempty"`
	FieldKey     string                             `json:"field_key,omitempty"`
	SubjectClaim string                             `json:"subject_claim,omitempty"`
	Children     []ProjectDataPolicy                `json:"children,omitempty"`
}

type ProjectDataPolicyRelationSegment struct {
	Direction        RelationDirection `json:"direction"`
	RelationFieldKey string            `json:"relation_field_key"`
	TargetObjectKey  string            `json:"target_object_key"`
}

func (permission ProjectRolePermission) Validate() error {
	if strings.TrimSpace(permission.PermissionKey) == "" {
		return &Error{Code: "identity.project_role_permission_invalid"}
	}
	if permission.DataPolicy == nil {
		if !permission.DataScope.Valid() {
			return &Error{Code: "identity.project_role_permission_invalid"}
		}
		return nil
	}
	if permission.DataScope != "" {
		return &Error{Code: "identity.project_role_permission_ambiguous"}
	}
	if err := permission.DataPolicy.Validate(); err != nil {
		return err
	}
	return nil
}

func (policy ProjectDataPolicy) Validate() error {
	nodes := 0
	return validateProjectDataPolicy(policy, 0, &nodes)
}

// NormalizeProjectDataPolicy validates and returns a detached canonical copy.
// Callers can safely persist or hash the result without retaining aliases to
// the authoring request.
func NormalizeProjectDataPolicy(policy ProjectDataPolicy) (ProjectDataPolicy, error) {
	if err := policy.Validate(); err != nil {
		return ProjectDataPolicy{}, err
	}
	return canonicalProjectDataPolicy(policy), nil
}

func validateProjectDataPolicy(policy ProjectDataPolicy, depth int, nodes *int) error {
	*nodes = *nodes + 1
	if depth > maximumProjectDataPolicyDepth || *nodes > maximumProjectDataPolicyNodes {
		return &Error{Code: "identity.project_data_policy_limit_exceeded"}
	}
	operator := strings.ToLower(strings.TrimSpace(policy.Operator))
	switch operator {
	case ProjectDataPolicyAnd, ProjectDataPolicyOr:
		if len(policy.Children) < 2 || len(policy.Path) != 0 || strings.TrimSpace(policy.FieldKey) != "" || strings.TrimSpace(policy.SubjectClaim) != "" {
			return &Error{Code: "identity.project_data_policy_invalid"}
		}
		for _, child := range policy.Children {
			if err := validateProjectDataPolicy(child, depth+1, nodes); err != nil {
				return err
			}
		}
		return nil
	case ProjectDataPolicyNot:
		if len(policy.Children) != 1 || len(policy.Path) != 0 || strings.TrimSpace(policy.FieldKey) != "" || strings.TrimSpace(policy.SubjectClaim) != "" {
			return &Error{Code: "identity.project_data_policy_invalid"}
		}
		return validateProjectDataPolicy(policy.Children[0], depth+1, nodes)
	case ProjectDataPolicyEq, ProjectDataPolicyIn:
		if len(policy.Children) != 0 || strings.TrimSpace(policy.FieldKey) == "" || len(policy.Path) > 3 {
			return &Error{Code: "identity.project_data_policy_invalid"}
		}
	default:
		return &Error{Code: "identity.project_data_policy_operator_invalid"}
	}
	for _, segment := range policy.Path {
		if segment.Direction != RelationForward && segment.Direction != RelationReverse || strings.TrimSpace(segment.RelationFieldKey) == "" || strings.TrimSpace(segment.TargetObjectKey) == "" {
			return &Error{Code: "identity.project_data_policy_relation_invalid"}
		}
	}
	claim := strings.TrimSpace(policy.SubjectClaim)
	if operator == ProjectDataPolicyEq && !projectScalarSubjectClaim(claim) || operator == ProjectDataPolicyIn && !projectCollectionSubjectClaim(claim) {
		return &Error{Code: "identity.project_data_policy_claim_invalid"}
	}
	return nil
}

func projectScalarSubjectClaim(value string) bool {
	switch value {
	case ProjectSubjectClaimID, ProjectSubjectClaimWorkspaceID, ProjectSubjectClaimOrgID, ProjectSubjectClaimSupportOrgID:
		return true
	default:
		return false
	}
}

func projectCollectionSubjectClaim(value string) bool {
	switch value {
	case ProjectSubjectClaimOrgScopeIDs, ProjectSubjectClaimSupportOrgScopeIDs, ProjectSubjectClaimReportingScopeUserIDs:
		return true
	default:
		return false
	}
}

// Predicate compiles the authoring AST into the immutable AccessBundle
// predicate consumed by evaluators and Runtime query compilation.
func (policy ProjectDataPolicy) Predicate() (Predicate, error) {
	if err := policy.Validate(); err != nil {
		return Predicate{}, err
	}
	return compileProjectDataPolicy(policy), nil
}

func compileProjectDataPolicy(policy ProjectDataPolicy) Predicate {
	switch strings.ToLower(strings.TrimSpace(policy.Operator)) {
	case ProjectDataPolicyAnd:
		result := Predicate{All: make([]Predicate, len(policy.Children))}
		for index, child := range policy.Children {
			result.All[index] = compileProjectDataPolicy(child)
		}
		return result
	case ProjectDataPolicyOr:
		result := Predicate{Any: make([]Predicate, len(policy.Children))}
		for index, child := range policy.Children {
			result.Any[index] = compileProjectDataPolicy(child)
		}
		return result
	case ProjectDataPolicyNot:
		child := compileProjectDataPolicy(policy.Children[0])
		return Predicate{Not: &child}
	default:
		path := make([]RelationSegment, len(policy.Path))
		for index, segment := range policy.Path {
			path[index] = RelationSegment{Direction: segment.Direction, Reference: strings.TrimSpace(segment.RelationFieldKey), TargetResource: ResourceType(strings.TrimSpace(segment.TargetObjectKey))}
		}
		operator := OperatorEqual
		if strings.EqualFold(policy.Operator, ProjectDataPolicyIn) {
			operator = OperatorIn
		}
		return Predicate{Fact: strings.TrimSpace(policy.FieldKey), Path: path, Operator: operator, Value: "$subject." + strings.TrimSpace(policy.SubjectClaim)}
	}
}

func canonicalProjectDataPolicy(policy ProjectDataPolicy) ProjectDataPolicy {
	policy.Operator = strings.ToLower(strings.TrimSpace(policy.Operator))
	policy.FieldKey = strings.TrimSpace(policy.FieldKey)
	policy.SubjectClaim = strings.TrimSpace(policy.SubjectClaim)
	policy.Path = append([]ProjectDataPolicyRelationSegment(nil), policy.Path...)
	for index := range policy.Path {
		policy.Path[index].RelationFieldKey = strings.TrimSpace(policy.Path[index].RelationFieldKey)
		policy.Path[index].TargetObjectKey = strings.TrimSpace(policy.Path[index].TargetObjectKey)
	}
	policy.Children = append([]ProjectDataPolicy(nil), policy.Children...)
	for index := range policy.Children {
		policy.Children[index] = canonicalProjectDataPolicy(policy.Children[index])
	}
	if policy.Operator == ProjectDataPolicyAnd || policy.Operator == ProjectDataPolicyOr {
		sort.Slice(policy.Children, func(i, j int) bool {
			left, _ := json.Marshal(policy.Children[i])
			right, _ := json.Marshal(policy.Children[j])
			return string(left) < string(right)
		})
	}
	return policy
}

type ProjectRoleCatalog struct {
	Application ApplicationRef `json:"application"`
	// Objects is the application-owned object/field catalog used to project
	// declared role field permissions into an effective AccessBundle. It stays
	// as canonical JSON so Identity SDK does not take ownership of an
	// application's metadata model.
	Objects json.RawMessage         `json:"objects,omitempty"`
	Roles   []ProjectRoleDefinition `json:"roles"`
	// InitialWorkspaceAdministratorRoleKey is consumed only by the trusted,
	// in-process Workspace bootstrap catalog binder. It is deliberately not
	// serialized: public role-catalog publication and browser-facing DTOs
	// cannot select the first Workspace administrator's role.
	InitialWorkspaceAdministratorRoleKey string `json:"-"`
}

type ProjectRoleCatalogReceipt struct {
	Published int    `json:"published"`
	SHA256    string `json:"sha256"`
}

type ProjectRoleCatalogPublisher interface {
	PublishProjectRoles(context.Context, ProjectRoleCatalog) (ProjectRoleCatalogReceipt, error)
}
