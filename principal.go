package identitysdk

import "strings"

const PrincipalContextContractVersion = "domainry-principal-context-v1"

type User struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Locale  string `json:"locale"`
	Version int64  `json:"version"`
	Status  string `json:"status"`
}

type Role struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Label string `json:"label"`
}

type OrganizationScopes struct {
	TeamIDs      []string `json:"team_ids"`
	StoreIDs     []string `json:"store_ids"`
	TerritoryIDs []string `json:"territory_ids"`
	WarehouseIDs []string `json:"warehouse_ids"`
}

type BusinessProfile struct {
	BindingKey  string   `json:"binding_key"`
	ObjectKey   string   `json:"object_key"`
	RecordID    string   `json:"record_id"`
	SurfaceKeys []string `json:"surface_keys"`
	Active      bool     `json:"active"`
}

type RequestContext struct {
	Key                    string            `json:"key"`
	SubjectKind            string            `json:"subject_kind"`
	WorkforceProfileID     string            `json:"workforce_profile_id,omitempty"`
	SurfaceKey             string            `json:"surface_key,omitempty"`
	BusinessProfileKey     string            `json:"business_profile_key,omitempty"`
	BusinessProfileID      string            `json:"business_profile_id,omitempty"`
	CanonicalRequestHeader map[string]string `json:"canonical_request_headers"`
}

// Principal contains authenticated, non-secret identity facts. Access tokens
// are held by RequestIdentity and are never serialized with a Principal.
type Principal struct {
	ContractVersion       string             `json:"contract_version"`
	Known                 bool               `json:"known"`
	WorkspaceID           string             `json:"workspace_id"`
	UserID                string             `json:"user_id"`
	RoleKey               string             `json:"role_key,omitempty"`
	AuthorizationRevision string             `json:"authorization_revision,omitempty"`
	WorkforceProfileID    string             `json:"workforce_profile_id,omitempty"`
	DepartmentID          string             `json:"department_id,omitempty"`
	DepartmentPath        string             `json:"department_path,omitempty"`
	ReportingPath         string             `json:"reporting_path,omitempty"`
	ReportingUserIDs      []string           `json:"reporting_user_ids"`
	OrganizationScopes    OrganizationScopes `json:"organization_scopes"`
	SurfaceKey            string             `json:"surface_key,omitempty"`
	BusinessProfiles      []BusinessProfile  `json:"business_profiles"`
	RequestContexts       []RequestContext   `json:"request_contexts"`
	User                  User               `json:"user"`
	Roles                 []Role             `json:"roles"`
	Permissions           []string           `json:"permissions"`
	MustChangePassword    bool               `json:"must_change_password"`
}

func (p Principal) HasPermission(expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	for _, permission := range p.Permissions {
		if strings.EqualFold(strings.TrimSpace(permission), expected) {
			return true
		}
	}
	return false
}

// RequestIdentity is the authenticated request subject. AccessToken is kept
// out of JSON and must never be logged or copied into domain records.
type RequestIdentity struct {
	Principal   Principal `json:"principal"`
	AccessToken string    `json:"-"`
}
