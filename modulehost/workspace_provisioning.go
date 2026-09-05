// Package modulehost defines capabilities that exist only when Identity is
// embedded in the same process and database as its host application.
package modulehost

import "context"

// Transaction carries the host-owned native transaction across the module
// boundary. The host retains commit and rollback ownership; implementations
// must reject transaction types they cannot safely join.
type Transaction struct {
	Native any
	// WorkspaceProvisionFailures is an optional in-process acceptance seam.
	// The host selects it once at startup; public requests cannot set it.
	WorkspaceProvisionFailures WorkspaceProvisionFailureInjector
}

const (
	WorkspaceProvisionFailureAfterIdentityUser   = "after_identity_user"
	WorkspaceProvisionFailureAfterIdentityRole   = "after_identity_role"
	WorkspaceProvisionFailureAfterRoleAssignment = "after_role_assignment"
	WorkspaceProvisionFailureAfterCredential     = "after_credential"
)

// WorkspaceProvisionFailureInjector lets an embedded host verify that each
// Identity-owned write remains inside the host transaction. Implementations
// must return a stable, non-sensitive error.
type WorkspaceProvisionFailureInjector interface {
	InjectWorkspaceProvisionFailure(point string) error
}

type WorkspaceIdentityProvisionRequest struct {
	WorkspaceID  string `json:"workspace_id"`
	AdminLoginID string `json:"admin_login_id"`
	AdminName    string `json:"admin_name"`
	// InitialPassword is accepted only across the in-process bootstrap
	// boundary. It is deliberately excluded from serialized contracts so a
	// remote or public workspace-provisioning request cannot select a password.
	InitialPassword         string                            `json:"-"`
	AcceptanceOrganizations []WorkspaceAcceptanceOrganization `json:"-"`
	AcceptanceActors        []WorkspaceAcceptanceActor        `json:"-"`
}

// WorkspaceAcceptanceOrganization and WorkspaceAcceptanceActor are available
// only on the embedded bootstrap boundary used by a host-owned verification
// child process. Credentials can never enter a public or serialized request.
type WorkspaceAcceptanceOrganization struct {
	ID   string `json:"id"`
	Code string `json:"code"`
	Name string `json:"name"`
}

type WorkspaceAcceptanceActor struct {
	ID              string `json:"id"`
	LoginID         string `json:"login_id"`
	Name            string `json:"name"`
	RoleKey         string `json:"role_key"`
	OrganizationID  string `json:"organization_id,omitempty"`
	ManagerUserID   string `json:"manager_user_id,omitempty"`
	InitialPassword string `json:"-"`
}

type WorkspaceIdentityProvisionResult struct {
	AdminLoginID       string `json:"admin_login_id"`
	InitialPassword    string `json:"initial_password"`
	MustChangePassword bool   `json:"must_change_password"`
	ProvisionedRoles   int    `json:"provisioned_roles"`
}

type WorkspaceRoleReconcileRequest struct {
	WorkspaceID string `json:"workspace_id"`
}

type WorkspaceRoleReconcileResult struct {
	ProvisionedRoles int `json:"provisioned_roles"`
}

// WorkspaceProvisioner is an optional in-process capability. Remote Identity
// bindings intentionally do not implement it because they cannot participate
// in a host-owned local transaction.
type WorkspaceProvisioner interface {
	ProvisionWorkspaceIdentity(context.Context, WorkspaceIdentityProvisionRequest, Transaction) (WorkspaceIdentityProvisionResult, error)
	ReconcileWorkspaceRoles(context.Context, WorkspaceRoleReconcileRequest, Transaction) (WorkspaceRoleReconcileResult, error)
}
