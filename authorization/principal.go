package authorization

import (
	"context"
	"sort"
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
	// Permissions is a presentation-only projection for clients. Runtime
	// authorization is exclusively backed by AccessBundle and fails closed
	// when the bundle is absent.
	Permissions        []string `json:"permissions"`
	MustChangePassword bool     `json:"must_change_password"`
	// AccessBundle is resolved policy state for in-process authorization. It is
	// never serialized into tokens, logs, or domain records.
	AccessBundle *AccessBundle `json:"-"`
}

func (p Principal) HasPermission(expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" || p.AccessBundle == nil {
		return false
	}
	allowed := false
	for _, grant := range p.AccessBundle.FunctionGrants {
		permission := strings.TrimSpace(string(grant.Resource)) + "." + strings.TrimSpace(string(grant.Action))
		matches := permission == expected || grant.Resource == "*" && grant.Action == "*"
		if grant.Action == "*" {
			matches = matches || strings.HasPrefix(expected, strings.TrimSpace(string(grant.Resource))+".")
		}
		if !matches {
			continue
		}
		if grant.Effect == EffectDeny {
			return false
		}
		allowed = allowed || grant.Effect == EffectAllow
	}
	return allowed
}

// HasAllPermissions requires every stable permission key and fails closed for
// empty input or an unresolved AccessBundle.
func (p Principal) HasAllPermissions(expected []string) bool {
	if len(expected) == 0 {
		return false
	}
	for _, permission := range expected {
		if !p.HasPermission(permission) {
			return false
		}
	}
	return true
}

// PermissionKeys projects effective allow grants for presentation and audit
// boundaries. Authorization callers must continue to use HasPermission so a
// matching deny always wins.
func (p Principal) PermissionKeys() []string {
	if p.AccessBundle == nil {
		return nil
	}
	allowed, denied := map[string]bool{}, map[string]bool{}
	for _, grant := range p.AccessBundle.FunctionGrants {
		key := strings.TrimSpace(string(grant.Resource)) + "." + strings.TrimSpace(string(grant.Action))
		if key == "." {
			continue
		}
		if grant.Effect == EffectDeny {
			denied[key] = true
			delete(allowed, key)
			continue
		}
		if grant.Effect == EffectAllow && !denied[key] {
			allowed[key] = true
		}
	}
	keys := make([]string, 0, len(allowed))
	for key := range allowed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
