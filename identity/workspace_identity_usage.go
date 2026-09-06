package identity

import "context"

const (
	WorkspaceIdentityUsageContractVersionV1      = "domainry-identity-workspace-usage-v1"
	WorkspaceIdentityUsageContractVersionV2      = "domainry-identity-workspace-usage-v2"
	WorkspaceIdentityUsageContractVersionV3      = "domainry-identity-workspace-usage-v3"
	CurrentWorkspaceIdentityUsageContractVersion = WorkspaceIdentityUsageContractVersionV3
	// WorkspaceIdentityUsageContractHashV2 is the SHA-256 of the canonical v2
	// request/result/paging descriptor documented by Identity. It changes when
	// any field or paging-security semantic changes.
	WorkspaceIdentityUsageContractHashV2 = "1e58b9b154cd80fbd364dbbd2e1bad9ca1b9420ce25c321f1cca0878c17a3c14"
	// WorkspaceIdentityUsageContractHashV3 adds the infrastructure-only exact
	// Workspace resolve request used by transaction-bound billing handlers.
	WorkspaceIdentityUsageContractHashV3      = "5f6f8a71e4a9c569628a08a1d46e41bf212e0ec4b0ba64f5a3a815bb857d5f7e"
	CurrentWorkspaceIdentityUsageContractHash = WorkspaceIdentityUsageContractHashV3
)

const workspaceIdentityUsageCanonicalContractV2 = "domainry-identity-workspace-usage-v2\n" +
	"request:contract_version,contract_hash,page_size,cursor\n" +
	"accounts:active_human_accounts,active_human_accounts_with_active_role,disabled_human_accounts,service_accounts,automation_accounts\n" +
	"paging:aes-256-gcm;bind=version,contract_version,contract_hash,page_size,after_workspace_id,installation_id,application_key,subject_id,permission_key,authorization_revision,catalog_revision"

const workspaceIdentityUsageCanonicalContractV3 = "domainry-identity-workspace-usage-v3\n" +
	"list_request:contract_version,contract_hash,authorization(infrastructure-only),page_size,cursor\n" +
	"resolve_request:contract_version,contract_hash,authorization(infrastructure-only),workspace_code(infrastructure-only)\n" +
	"authorization:pre-transaction;host-audited;application,subject,permission,authorization-revision-bound\n" +
	"accounts:active_human_accounts,active_human_accounts_with_active_role,disabled_human_accounts,service_accounts,automation_accounts\n" +
	"resolve:single-authority-selected-active-workspace;no-cursor\n" +
	"paging:aes-256-gcm;bind=version,contract_version,contract_hash,page_size,after_workspace_id,installation_id,application_key,subject_id,permission_key,authorization_revision,catalog_revision"

const (
	WorkspaceIdentityUsageAggregatePermission = "identity.workspace_identity_usage.aggregate"
	WorkspaceIdentityUsageDefaultPageSize     = 50
	WorkspaceIdentityUsageMaxPageSize         = 100
)

// WorkspaceIdentityUsageRequest deliberately carries no Workspace IDs. The
// embedded host's trusted installation authority selects the authorized,
// active Workspace page after validating the non-HTTP purpose permission.
type WorkspaceIdentityUsageRequest struct {
	ContractVersion string                              `json:"contract_version"`
	ContractHash    string                              `json:"contract_hash"`
	Authorization   WorkspaceIdentityUsageAuthorization `json:"-"`
	// AccessToken is retained for trusted non-Runtime callers. Runtime obtains
	// Authorization before opening its Action write transaction so the host's
	// durable authorization audit cannot deadlock that transaction.
	AccessToken string `json:"-"`
	PageSize    int    `json:"page_size,omitempty"`
	Cursor      string `json:"cursor,omitempty"`
}

// WorkspaceIdentityUsageResolveRequest is infrastructure-only. Runtime
// supplies only the canonical Workspace code; the host authority selects the
// physical Workspace scope. The code is excluded from JSON because the public
// Handler request owns its typed copy.
type WorkspaceIdentityUsageResolveRequest struct {
	ContractVersion string                              `json:"contract_version"`
	ContractHash    string                              `json:"contract_hash"`
	Authorization   WorkspaceIdentityUsageAuthorization `json:"-"`
	AccessToken     string                              `json:"-"`
	WorkspaceCode   string                              `json:"-"`
}

type WorkspaceIdentityUsageAuthorizationRequest struct {
	AccessToken string `json:"-"`
}

// WorkspaceIdentityUsageAuthorization is an opaque infrastructure receipt.
// Runtime may only pass it back to the transaction-bound aggregate; no field
// is serialized or exposed to generated project code.
type WorkspaceIdentityUsageAuthorization struct {
	InstallationID        string `json:"-"`
	ApplicationKey        string `json:"-"`
	SubjectID             string `json:"-"`
	AuditWorkspaceID      string `json:"-"`
	PermissionKey         string `json:"-"`
	AuthorizationRevision string `json:"-"`
	AuthorizationAuditID  string `json:"-"`
}

// WorkspaceIdentityAccountCounts is a policy-neutral identity inventory.
// Callers apply their own explicitly versioned billing policy; Identity does
// not label any category as billable.
type WorkspaceIdentityAccountCounts struct {
	ActiveHumanAccounts               int64 `json:"active_human_accounts"`
	ActiveHumanAccountsWithActiveRole int64 `json:"active_human_accounts_with_active_role"`
	DisabledHumanAccounts             int64 `json:"disabled_human_accounts"`
	// ServiceAccounts and AutomationAccounts each include active and disabled
	// accounts of that type. Deleted accounts are excluded from every count.
	ServiceAccounts    int64 `json:"service_accounts"`
	AutomationAccounts int64 `json:"automation_accounts"`
}

type WorkspaceIdentityUsage struct {
	WorkspaceID string                         `json:"workspace_id"`
	Accounts    WorkspaceIdentityAccountCounts `json:"accounts"`
}

// WorkspaceIdentityUsagePage is ordered by WorkspaceID with an authenticated,
// encrypted keyset cursor. It contains aggregate counts only and never returns
// users or any person-identifying fields.
type WorkspaceIdentityUsagePage struct {
	Items      []WorkspaceIdentityUsage `json:"items"`
	NextCursor string                   `json:"next_cursor,omitempty"`
}

type WorkspaceIdentityUsageAggregate interface {
	ListWorkspaceIdentityUsage(context.Context, WorkspaceIdentityUsageRequest) (WorkspaceIdentityUsagePage, error)
	ResolveWorkspaceIdentityUsage(context.Context, WorkspaceIdentityUsageResolveRequest) (WorkspaceIdentityUsage, error)
}
