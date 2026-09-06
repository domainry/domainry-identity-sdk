// Package modulehost defines capabilities that exist only when Identity is
// embedded in the same process and database as its host application.
package modulehost

import (
	"context"

	"github.com/domainry/domainry-orm/sqlhost"
)

// TransactionExecutor is the smallest SQL surface shared by a host-owned
// transaction and Identity persistence. It deliberately omits begin, commit,
// rollback, close, and connection-pool access.
type TransactionExecutor = sqlhost.DBTX

// Transaction carries only the executor surface of a host-owned transaction
// across the module boundary. The host retains commit and rollback ownership;
// Identity binders accept *sql.Tx and domainry-orm driver.Transaction values,
// reject *sql.DB/plain connections, and never pass this value to handlers.
type Transaction struct {
	Executor TransactionExecutor
	// WorkspaceProvisionFailures is an optional in-process acceptance seam.
	// The host selects it once at startup; public requests cannot set it.
	WorkspaceProvisionFailures WorkspaceProvisionFailureInjector
}

const (
	WorkspaceProvisionFailureAfterIdentityUser     = "after_identity_user"
	WorkspaceProvisionFailureAfterIdentityRole     = "after_identity_role"
	WorkspaceProvisionFailureAfterRoleAssignment   = "after_role_assignment"
	WorkspaceProvisionFailureAfterCredential       = "after_credential"
	WorkspaceProvisionFailureAfterCompany          = "after_company"
	WorkspaceProvisionFailureAfterFirstStore       = "after_first_store"
	WorkspaceProvisionFailureAfterBootstrapReceipt = "after_bootstrap_receipt"
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

// WorkspaceProvisioner is the isolated V1 legacy capability. Protocol V3's
// BootstrapBinding does not expose it. New hosts must use
// WorkspaceIdentityBootstrapV2 so callers cannot choose roles or arbitrary
// organization relationships and credentials cannot escape before commit.
type WorkspaceProvisioner interface {
	ProvisionWorkspaceIdentity(context.Context, WorkspaceIdentityProvisionRequest, Transaction) (WorkspaceIdentityProvisionResult, error)
	ReconcileWorkspaceRoles(context.Context, WorkspaceRoleReconcileRequest, Transaction) (WorkspaceRoleReconcileResult, error)
}

// WorkspaceAcceptanceFixtureRequest is a startup-only verification seam. It
// can append managed fixtures after the fixed V2 graph inside the same host
// transaction, but cannot replace the initial administrator or its credential.
type WorkspaceAcceptanceFixtureRequest struct {
	WorkspaceID   string                            `json:"-"`
	Organizations []WorkspaceAcceptanceOrganization `json:"-"`
	Actors        []WorkspaceAcceptanceActor        `json:"-"`
}

type WorkspaceAcceptanceFixtureProvisioner interface {
	ProvisionWorkspaceAcceptanceFixtures(context.Context, WorkspaceAcceptanceFixtureRequest, Transaction) error
}

type WorkspaceAcceptanceFixtureProvisionerBinding interface {
	WorkspaceAcceptanceFixtureProvisioner() WorkspaceAcceptanceFixtureProvisioner
}

const (
	WorkspaceIdentityBootstrapContractVersionV2      = "domainry-workspace-identity-bootstrap-v2"
	WorkspaceIdentityBootstrapContractCanonicalV2    = "domainry-workspace-identity-bootstrap-v2|request:invocation_id,workspace_id,company_id,company_code,company_name,first_store_id,first_store_code,first_store_name,initial_admin_user_id,initial_admin_login_id,initial_admin_name|roles:tenant_admin,headquarters_admin,store_manager,staff|assignment:initial_admin=headquarters_admin@company|result:receipt_only|completion:committed,rolled_back|credential:post_commit_one_time_nonpersistent"
	WorkspaceIdentityBootstrapContractHashV2         = "5011287354029d67c64e1f9dedf3767234c9af8d7ec7e29886a9b4b419ccc9c8"
	CurrentWorkspaceIdentityBootstrapContractVersion = WorkspaceIdentityBootstrapContractVersionV2
	CurrentWorkspaceIdentityBootstrapContractHash    = WorkspaceIdentityBootstrapContractHashV2

	WorkspaceBootstrapRoleTenantAdmin       = "tenant_admin"
	WorkspaceBootstrapRoleHeadquartersAdmin = "headquarters_admin"
	WorkspaceBootstrapRoleStoreManager      = "store_manager"
	WorkspaceBootstrapRoleStaff             = "staff"
)

// WorkspaceIdentityBootstrapV2Request is a trusted, in-process-only graph
// command. Every field is excluded from JSON deliberately: a browser or
// generated public handler cannot select the Workspace, graph identifiers,
// organization relationship, role, or initial credential.
type WorkspaceIdentityBootstrapV2Request struct {
	ContractVersion     string `json:"-"`
	ContractHash        string `json:"-"`
	InvocationID        string `json:"-"`
	WorkspaceID         string `json:"-"`
	CompanyID           string `json:"-"`
	CompanyCode         string `json:"-"`
	CompanyName         string `json:"-"`
	FirstStoreID        string `json:"-"`
	FirstStoreCode      string `json:"-"`
	FirstStoreName      string `json:"-"`
	InitialAdminUserID  string `json:"-"`
	InitialAdminLoginID string `json:"-"`
	InitialAdminName    string `json:"-"`
}

// WorkspaceIdentityBootstrapV2Receipt is the only transaction-phase result.
// It is safe to persist and replay because it never contains a credential.
type WorkspaceIdentityBootstrapV2Receipt struct {
	ContractVersion     string `json:"contract_version"`
	ContractHash        string `json:"contract_hash"`
	ReceiptID           string `json:"receipt_id"`
	InvocationID        string `json:"invocation_id"`
	WorkspaceID         string `json:"workspace_id"`
	CompanyID           string `json:"company_id"`
	FirstStoreID        string `json:"first_store_id"`
	InitialAdminUserID  string `json:"initial_admin_user_id"`
	InitialAdminLoginID string `json:"initial_admin_login_id"`
	Replayed            bool   `json:"replayed"`
}

// WorkspaceIdentityBootstrapCredentialClaim is usable only after the host has
// committed the transaction that produced ReceiptID. It is not an HTTP DTO.
type WorkspaceIdentityBootstrapCredentialClaim struct {
	WorkspaceID string `json:"-"`
	ReceiptID   string `json:"-"`
}

type WorkspaceIdentityBootstrapTransactionOutcome string

const (
	WorkspaceIdentityBootstrapTransactionCommitted  WorkspaceIdentityBootstrapTransactionOutcome = "committed"
	WorkspaceIdentityBootstrapTransactionRolledBack WorkspaceIdentityBootstrapTransactionOutcome = "rolled_back"
)

// WorkspaceIdentityBootstrapCompletion is the host's mandatory transaction
// completion signal. A rollback destroys the volatile credential immediately;
// a commit is verified against the database before a later claim is allowed.
// The signal is excluded from HTTP serialization.
type WorkspaceIdentityBootstrapCompletion struct {
	WorkspaceID string                                       `json:"-"`
	ReceiptID   string                                       `json:"-"`
	Outcome     WorkspaceIdentityBootstrapTransactionOutcome `json:"-"`
}

// WorkspaceIdentityBootstrapOneTimeCredential is returned at most once and
// excluded from serialization. Identity persists only its password hash.
type WorkspaceIdentityBootstrapOneTimeCredential struct {
	LoginID            string `json:"-"`
	InitialPassword    string `json:"-"`
	MustChangePassword bool   `json:"-"`
}

// WorkspaceIdentityBootstrapV2 is the Protocol V3 initialization capability.
// BootstrapWorkspaceIdentityV2 joins the host transaction and returns only a
// non-secret receipt. The host must report commit or rollback through
// CompleteWorkspaceIdentityBootstrapV2. Only a verified commit permits the
// volatile credential to be claimed exactly once.
type WorkspaceIdentityBootstrapV2 interface {
	BootstrapWorkspaceIdentityV2(context.Context, WorkspaceIdentityBootstrapV2Request, Transaction) (WorkspaceIdentityBootstrapV2Receipt, error)
	CompleteWorkspaceIdentityBootstrapV2(context.Context, WorkspaceIdentityBootstrapCompletion) error
	ClaimWorkspaceIdentityBootstrapCredentialV2(context.Context, WorkspaceIdentityBootstrapCredentialClaim) (WorkspaceIdentityBootstrapOneTimeCredential, error)
}
