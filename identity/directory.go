// Package identity owns the stable, non-secret identity vocabulary shared by
// authentication, authorization, and application directory projections.
package identity

import "context"

const UserStatusActive = "active"

// ApplicationScope identifies the application allowed to consume an
// Identity projection. It deliberately excludes redirect and catalog data.
type ApplicationScope struct {
	TenantID       TenantID       `json:"tenant_id,omitempty"`
	WorkspaceID    WorkspaceID    `json:"workspace_id"`
	ApplicationKey ApplicationKey `json:"application_key"`
}

// Directory is a read-only application projection. Identity management commands
// and CRUD models do not belong to this contract.
type Directory interface {
	FindUser(context.Context, UserLookup) (User, bool, error)
	FindDepartment(context.Context, DepartmentLookup) (Department, bool, error)
	ListUsers(context.Context, DirectoryQuery) ([]User, error)
	ListRoles(context.Context, DirectoryQuery) ([]Role, error)
	ListUserRoleAssignments(context.Context, UserRoleAssignmentQuery) ([]UserRoleAssignment, error)
	ListWorkforce(context.Context, DirectoryQuery) ([]WorkforceEntry, error)
}

type DirectoryQuery struct {
	Application ApplicationScope `json:"application"`
}

type UserLookup struct {
	Application ApplicationScope `json:"application"`
	UserID      SubjectID        `json:"user_id"`
}

type DepartmentLookup struct {
	Application  ApplicationScope `json:"application"`
	DepartmentID string           `json:"department_id"`
}

type UserRoleAssignmentQuery struct {
	Application ApplicationScope `json:"application"`
	UserID      SubjectID        `json:"user_id,omitempty"`
}

// User contains only directory attributes safe for application projections. It
// never carries credentials, external-provider tokens, MFA, or session data.
type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	GivenName   string `json:"given_name,omitempty"`
	MiddleName  string `json:"middle_name,omitempty"`
	FamilyName  string `json:"family_name,omitempty"`
	NamePrefix  string `json:"name_prefix,omitempty"`
	NameSuffix  string `json:"name_suffix,omitempty"`
	NativeName  string `json:"native_name,omitempty"`
	NameLocale  string `json:"name_locale,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	AccountType string `json:"account_type,omitempty"`
	Locale      string `json:"locale,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
	Status      string `json:"status"`
	Version     int64  `json:"version"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type Department struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	ParentID                 *string  `json:"parent_id,omitempty"`
	LeaderWorkforceProfileID string   `json:"leader_workforce_profile_id,omitempty"`
	Path                     string   `json:"path,omitempty"`
	AncestorIDs              []string `json:"ancestor_ids,omitempty"`
	Depth                    int      `json:"depth,omitempty"`
	SortOrder                int      `json:"sort_order,omitempty"`
	Status                   string   `json:"status,omitempty"`
}

type Role struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
}

type UserRoleAssignment struct {
	UserID             string  `json:"user_id"`
	RoleID             string  `json:"role_id"`
	WorkforceProfileID string  `json:"workforce_profile_id,omitempty"`
	BindingKey         string  `json:"binding_key,omitempty"`
	ProfileID          string  `json:"profile_id,omitempty"`
	Source             string  `json:"source,omitempty"`
	Status             string  `json:"status,omitempty"`
	ValidFrom          string  `json:"valid_from,omitempty"`
	ValidUntil         string  `json:"valid_until,omitempty"`
	GrantedBy          string  `json:"granted_by,omitempty"`
	GrantReason        string  `json:"grant_reason,omitempty"`
	RevokedBy          string  `json:"revoked_by,omitempty"`
	RevokedAt          string  `json:"revoked_at,omitempty"`
	RevokeReason       string  `json:"revoke_reason,omitempty"`
	CreatedAt          string  `json:"created_at,omitempty"`
	UpdatedAt          string  `json:"updated_at,omitempty"`
	ExpiresAt          *string `json:"expires_at,omitempty"`
}

type WorkforceEntry struct {
	WorkforceProfileID    string `json:"workforce_profile_id"`
	IdentityUserID        string `json:"identity_user_id"`
	OrganizationUnitID    string `json:"organization_unit_id,omitempty"`
	OrganizationPath      string `json:"organization_path,omitempty"`
	ManagerIdentityUserID string `json:"manager_identity_user_id,omitempty"`
	ReportingPath         string `json:"reporting_path,omitempty"`
}
