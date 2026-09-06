package identity

import "context"

const StoreOrganizationDeliveryContractVersionV1 = "domainry-identity-store-organization-delivery-v1"

const (
	StoreOrganizationDefaultPageSize = 50
	StoreOrganizationMaxPageSize     = 100
)

const (
	StoreOrganizationDeliveryCreatePermission  = "identity.store_organization_delivery.create"
	StoreOrganizationDeliveryRenamePermission  = "identity.store_organization_delivery.rename"
	StoreOrganizationDeliveryDisablePermission = "identity.store_organization_delivery.disable"
	StoreOrganizationDeliveryResolvePermission = "identity.store_organization_delivery.resolve"
	StoreOrganizationDeliveryListPermission    = "identity.store_organization_delivery.list"
)

type StoreOrganizationOperation string

const (
	StoreOrganizationCreate  StoreOrganizationOperation = "create"
	StoreOrganizationRename  StoreOrganizationOperation = "rename"
	StoreOrganizationDisable StoreOrganizationOperation = "disable"
)

func (value StoreOrganizationOperation) Valid() bool {
	switch value {
	case StoreOrganizationCreate, StoreOrganizationRename, StoreOrganizationDisable:
		return true
	default:
		return false
	}
}

// StoreOrganizationMutation deliberately omits node_type and mutable hierarchy
// fields. Identity always creates a store node under the supplied, persisted
// company parent; rename and disable preserve that parent and the store code.
// OrganizationID is the Runtime-supplied stable opaque ID: Identity preserves
// it verbatim (after surrounding-space normalization) and never remaps it.
type StoreOrganizationMutation struct {
	Operation            StoreOrganizationOperation `json:"operation"`
	OrganizationID       string                     `json:"organization_id"`
	Code                 string                     `json:"code,omitempty"`
	Name                 string                     `json:"name,omitempty"`
	ParentOrganizationID string                     `json:"parent_organization_id,omitempty"`
	SortOrder            int                        `json:"sort_order,omitempty"`
	ExpectedVersion      int64                      `json:"expected_version"`
}

type StoreOrganizationDeliveryRequest struct {
	ContractVersion string                    `json:"contract_version"`
	AccessToken     string                    `json:"-"`
	IdempotencyKey  string                    `json:"idempotency_key"`
	Organization    StoreOrganizationMutation `json:"organization"`
}

type StoreOrganization struct {
	ID                   string   `json:"id"`
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	Status               string   `json:"status"`
	ParentOrganizationID string   `json:"parent_organization_id"`
	Path                 string   `json:"path"`
	AncestorIDs          []string `json:"ancestor_ids"`
	Depth                int      `json:"depth"`
	SortOrder            int      `json:"sort_order"`
	Version              int64    `json:"version"`
}

type StoreOrganizationDeliveryResult struct {
	DeliveryID   string            `json:"delivery_id"`
	Organization StoreOrganization `json:"organization"`
	Replayed     bool              `json:"replayed"`
}

type StoreOrganizationResolveRequest struct {
	ContractVersion string `json:"contract_version"`
	AccessToken     string `json:"-"`
	OrganizationID  string `json:"organization_id"`
}

type StoreOrganizationListRequest struct {
	ContractVersion string `json:"contract_version"`
	AccessToken     string `json:"-"`
	PageSize        int    `json:"page_size,omitempty"`
	Cursor          string `json:"cursor,omitempty"`
}

// StoreOrganizationPage is a bounded, stable ID-keyset page. NextCursor is
// opaque to callers and empty only when there is no subsequent page.
type StoreOrganizationPage struct {
	Items      []StoreOrganization `json:"items"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type StoreOrganizationDelivery interface {
	DeliverStoreOrganization(context.Context, StoreOrganizationDeliveryRequest) (StoreOrganizationDeliveryResult, error)
	ResolveStoreOrganization(context.Context, StoreOrganizationResolveRequest) (StoreOrganization, error)
	ListStoreOrganizations(context.Context, StoreOrganizationListRequest) (StoreOrganizationPage, error)
}
