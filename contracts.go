package identitysdk

import "context"

type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

type Authorizer interface {
	Authorize(context.Context, RequestIdentity, AccessRequest) (AccessDecision, error)
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
