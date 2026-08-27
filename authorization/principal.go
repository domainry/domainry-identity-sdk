package authorization

import (
	"context"
	"strings"

	identitymodel "github.com/domainry/domainry-identity-sdk/identity"
)

const PrincipalContextContractVersion = "domainry-principal-context-v1"

type OrganizationScopes struct {
	TeamIDs      []string `json:"team_ids"`
	StoreIDs     []string `json:"store_ids"`
	TerritoryIDs []string `json:"territory_ids"`
	WarehouseIDs []string `json:"warehouse_ids"`
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
	User                  User               `json:"user"`
	Roles                 []Role             `json:"roles"`
	Permissions           []string           `json:"permissions"`
	MustChangePassword    bool               `json:"must_change_password"`
	// AccessBundle is resolved policy state for in-process authorization. It is
	// never serialized into tokens, logs, or domain records.
	AccessBundle *AccessBundle `json:"-"`
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

// PrincipalAuthenticator resolves an access token into the bounded Runtime
// request principal. The concrete cache/resolution policy lives outside the
// root contract package.
type PrincipalAuthenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

// PrincipalResolver resolves a Runtime principal for trusted background work
// such as Agent execution. Remote implementations must protect this capability
// with an application service credential; it is never a browser API.
type PrincipalResolver interface {
	Resolve(context.Context, PrincipalResolutionRequest) (PrincipalResolution, error)
}

type PrincipalResolutionRequest struct {
	Application identitymodel.ApplicationScope `json:"application"`
	SubjectID   identitymodel.SubjectID        `json:"subject_id"`
	RoleKey     string                         `json:"role_key,omitempty"`
}

// PrincipalResolution keeps the policy bundle explicit on the wire. The
// Principal.AccessBundle field remains non-serializable so request principals
// cannot accidentally leak policy state into logs or business records.
type PrincipalResolution struct {
	Principal    Principal    `json:"principal"`
	AccessBundle AccessBundle `json:"access_bundle"`
}

type requestIdentityContextKey struct{}

func WithRequestIdentity(ctx context.Context, identity RequestIdentity) context.Context {
	return context.WithValue(ctx, requestIdentityContextKey{}, identity)
}

func RequestIdentityFromContext(ctx context.Context) (RequestIdentity, bool) {
	if ctx == nil {
		return RequestIdentity{}, false
	}
	identity, ok := ctx.Value(requestIdentityContextKey{}).(RequestIdentity)
	return identity, ok && identity.Principal.Known
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	identity, ok := RequestIdentityFromContext(ctx)
	return identity.Principal, ok
}
