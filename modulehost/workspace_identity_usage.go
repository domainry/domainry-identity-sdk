package modulehost

import "context"

type WorkspaceIdentityUsageCatalogStatus string

const (
	WorkspaceIdentityUsageCatalogActive   WorkspaceIdentityUsageCatalogStatus = "active"
	WorkspaceIdentityUsageCatalogInactive WorkspaceIdentityUsageCatalogStatus = "inactive"
)

// WorkspaceIdentityUsageAuthorizationRequest is infrastructure-only. Identity
// supplies the exact source-owned purpose policy key; a public request cannot
// choose or weaken it.
type WorkspaceIdentityUsageAuthorizationRequest struct {
	AccessToken   string `json:"-"`
	PermissionKey string `json:"-"`
}

// WorkspaceIdentityUsageGrant is issued by the host's installation authority.
// AuditWorkspaceID is a trusted active Workspace used only to partition the
// installation-level audit event in the host database.
type WorkspaceIdentityUsageGrant struct {
	InstallationID        string `json:"-"`
	ApplicationKey        string `json:"-"`
	SubjectID             string `json:"-"`
	AuditWorkspaceID      string `json:"-"`
	PermissionKey         string `json:"-"`
	AuthorizationRevision string `json:"-"`
	// AuthorizationAuditID is the durable host audit receipt for the allow
	// decision. Identity rejects an allow grant without this evidence.
	AuthorizationAuditID string `json:"-"`
}

type WorkspaceIdentityUsageCatalogQuery struct {
	AfterWorkspaceID        string `json:"-"`
	Limit                   int    `json:"-"`
	ExpectedCatalogRevision string `json:"-"`
}

// WorkspaceIdentityUsageCatalogResolve is infrastructure-only. Runtime passes
// a canonical reference and the host selects the physical Workspace inside
// the same transaction; no physical ID crosses the request boundary.
type WorkspaceIdentityUsageCatalogResolve struct {
	WorkspaceCode string `json:"-"`
}

// WorkspaceIdentityUsageCatalogEntry is selected only by the trusted host
// catalog. Known and Authorized must both be explicit so Identity fails closed
// if a provider accidentally returns an inactive, unknown, or out-of-scope
// Workspace. Pages must use strictly increasing bytewise WorkspaceID order.
type WorkspaceIdentityUsageCatalogEntry struct {
	WorkspaceID string                              `json:"-"`
	Status      WorkspaceIdentityUsageCatalogStatus `json:"-"`
	Known       bool                                `json:"-"`
	Authorized  bool                                `json:"-"`
}

type WorkspaceIdentityUsageCatalogPage struct {
	CatalogRevision string                               `json:"-"`
	Workspaces      []WorkspaceIdentityUsageCatalogEntry `json:"-"`
}

// WorkspaceIdentityUsageInstallationAuthority is supplied only through an
// embedded DatabaseHandle. Runtime owns installation authorization and the
// active Workspace catalog; Identity neither reconstructs nor persists them.
// AuthorizeWorkspaceIdentityUsage is also the authoritative audit boundary
// for every authorization attempt reaching it: it must durably record allow
// and deny decisions, and fail closed when that audit cannot be recorded.
// Identity separately writes an aggregate-success audit in the host transaction
// only after a page is safe to release. Thus invalid cursors, catalog drift,
// and query failures retain the authority's access-attempt record but never
// produce a success event or any result.
type WorkspaceIdentityUsageInstallationAuthority interface {
	AuthorizeWorkspaceIdentityUsage(context.Context, WorkspaceIdentityUsageAuthorizationRequest) (WorkspaceIdentityUsageGrant, error)
	ListAuthorizedWorkspaceIdentityUsage(context.Context, WorkspaceIdentityUsageGrant, WorkspaceIdentityUsageCatalogQuery) (WorkspaceIdentityUsageCatalogPage, error)
	ResolveAuthorizedWorkspaceIdentityUsage(context.Context, WorkspaceIdentityUsageGrant, WorkspaceIdentityUsageCatalogResolve) (WorkspaceIdentityUsageCatalogEntry, error)
}
