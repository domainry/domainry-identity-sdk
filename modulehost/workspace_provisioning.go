// Package modulehost defines capabilities that exist only when Identity is
// embedded in the same process and database as its host application.
package modulehost

import "context"

// Transaction carries the host-owned native transaction across the module
// boundary. The host retains commit and rollback ownership; implementations
// must reject transaction types they cannot safely join.
type Transaction struct {
	Native any
}

type WorkspaceIdentityProvisionRequest struct {
	WorkspaceID  string `json:"workspace_id"`
	AdminLoginID string `json:"admin_login_id"`
	AdminName    string `json:"admin_name"`
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
