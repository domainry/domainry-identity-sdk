package authorization

import (
	"context"
	"time"
)

type Authorization interface {
	ResolveAccess(context.Context, AccessBundleRequest) (AccessBundle, error)
	Reauthorize(context.Context, DecisionRequest) (AccessDecision, error)
}

type AccessBundleRequest struct {
	Identity     RequestIdentity `json:"-"`
	ResourceType ResourceType    `json:"resource_type,omitempty"`
	Action       Action          `json:"action,omitempty"`
}

type DecisionRequest struct {
	Identity RequestIdentity `json:"-"`
	Access   AccessRequest   `json:"access"`
	Facts    ResourceFacts   `json:"facts,omitempty"`
}

type AccessRequest struct {
	ObjectKey string `json:"object_key"`
	Action    string `json:"action"`
	FieldKey  string `json:"field_key,omitempty"`
	RecordID  string `json:"record_id,omitempty"`
}

type AccessDecision struct {
	UserID                string       `json:"user_id"`
	ObjectKey             string       `json:"object_key,omitempty"`
	Action                string       `json:"action,omitempty"`
	FieldKey              string       `json:"field_key,omitempty"`
	RecordID              string       `json:"record_id,omitempty"`
	Allowed               bool         `json:"allowed"`
	AuthorizationRevision string       `json:"authorization_revision,omitempty"`
	Reason                AccessReason `json:"reason"`
}

type AccessReason struct {
	Code     string            `json:"code"`
	Effect   string            `json:"effect"`
	Layer    string            `json:"layer"`
	Subject  string            `json:"subject,omitempty"`
	Details  map[string]string `json:"details,omitempty"`
	Sources  []GrantSource     `json:"sources,omitempty"`
	Children []AccessReason    `json:"children,omitempty"`
}

type GrantSource struct {
	Type               string `json:"type"`
	Key                string `json:"key"`
	RoleID             string `json:"role_id,omitempty"`
	RoleKey            string `json:"role_key,omitempty"`
	PermissionSetKey   string `json:"permission_set_key,omitempty"`
	PermissionSetGroup string `json:"permission_set_group_key,omitempty"`
	AssignmentSource   string `json:"assignment_source,omitempty"`
	BindingKey         string `json:"binding_key,omitempty"`
	ProfileID          string `json:"profile_id,omitempty"`
	WorkforceProfileID string `json:"workforce_profile_id,omitempty"`
	ValidFrom          string `json:"valid_from,omitempty"`
	ValidUntil         string `json:"valid_until,omitempty"`
	ExpiresAt          string `json:"expires_at,omitempty"`
}

type AccessBundle struct {
	ContractVersion       string                `json:"contract_version"`
	CatalogRevision       CatalogRevision       `json:"catalog_revision"`
	AuthorizationRevision AuthorizationRevision `json:"authorization_revision"`
	ExpiresAt             time.Time             `json:"expires_at"`
	Subject               Subject               `json:"subject"`
	FunctionGrants        []FunctionGrant       `json:"function_grants"`
	DataPolicies          []DataPolicy          `json:"data_policies"`
	FieldPolicies         []FieldPolicy         `json:"field_policies"`
	ReferencePolicies     []ReferencePolicy     `json:"reference_policies"`
	ExportPolicies        []ExportPolicy        `json:"export_policies"`
	Guardrails            []Guardrail           `json:"guardrails"`
}

type Subject struct {
	TenantID            TenantID            `json:"tenant_id,omitempty"`
	WorkspaceID         WorkspaceID         `json:"workspace_id"`
	SubjectID           SubjectID           `json:"subject_id"`
	WorkforceProfileID  string              `json:"workforce_profile_id,omitempty"`
	DepartmentID        string              `json:"department_id,omitempty"`
	DepartmentPath      string              `json:"department_path,omitempty"`
	ReportingPath       string              `json:"reporting_path,omitempty"`
	ReportingSubjectIDs []SubjectID         `json:"reporting_subject_ids,omitempty"`
	OrganizationScopes  map[string][]string `json:"organization_scopes,omitempty"`
}

type FunctionGrant struct {
	Resource ResourceType `json:"resource"`
	Action   Action       `json:"action"`
	Effect   Effect       `json:"effect"`
}

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type DataPolicy struct {
	Key       string       `json:"key"`
	Resource  ResourceType `json:"resource"`
	Action    Action       `json:"action"`
	Effect    Effect       `json:"effect"`
	Predicate Predicate    `json:"predicate"`
}

type FieldPolicy struct {
	Resource ResourceType `json:"resource"`
	Field    string       `json:"field"`
	Read     bool         `json:"read"`
	Write    bool         `json:"write"`
	Export   bool         `json:"export"`
	Masked   bool         `json:"masked"`
}

type ReferencePolicy struct {
	SourceResource ResourceType `json:"source_resource"`
	Reference      string       `json:"reference"`
	TargetResource ResourceType `json:"target_resource"`
	DisplayFields  []string     `json:"display_fields,omitempty"`
	Allowed        bool         `json:"allowed"`
}

type ExportMode string

const (
	ExportModeDeny      ExportMode = "deny"
	ExportModeAllowList ExportMode = "allow_list"
)

type ExportPolicy struct {
	Resource ResourceType `json:"resource"`
	Mode     ExportMode   `json:"mode"`
	Fields   []string     `json:"fields,omitempty"`
}

type Guardrail struct {
	Key       string       `json:"key"`
	Resource  ResourceType `json:"resource,omitempty"`
	Action    Action       `json:"action,omitempty"`
	Effect    Effect       `json:"effect"`
	Predicate *Predicate   `json:"predicate,omitempty"`
}

type Predicate struct {
	Fact     string      `json:"fact,omitempty"`
	Operator Operator    `json:"operator,omitempty"`
	Value    any         `json:"value,omitempty"`
	All      []Predicate `json:"all,omitempty"`
	Any      []Predicate `json:"any,omitempty"`
	Not      *Predicate  `json:"not,omitempty"`
}

type Operator string

const (
	OperatorEqual    Operator = "eq"
	OperatorNotEqual Operator = "neq"
	OperatorIn       Operator = "in"
	OperatorNotIn    Operator = "not_in"
	OperatorExists   Operator = "exists"
	OperatorPrefix   Operator = "prefix"
	OperatorContains Operator = "contains"
)

type ResourceFacts map[string]any
