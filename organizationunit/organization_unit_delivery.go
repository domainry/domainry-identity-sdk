// Package organizationunit defines the narrow, transaction-bound contract
// used by generated Runtime handlers to create, resolve, list, rename, and
// disable Identity-owned organization units. It is intentionally separate
// from generic management CRUD: callers cannot move nodes or rewrite
// Identity-owned hierarchy facts.
package organizationunit

import (
	"context"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

const DeliveryContractVersionV1 = "domainry-identity-organization-unit-delivery-v1"

const (
	DeliveryCreatePermission  = "identity.organization_unit_delivery.create"
	DeliveryRenamePermission  = "identity.organization_unit_delivery.rename"
	DeliveryDisablePermission = "identity.organization_unit_delivery.disable"
	DeliveryResolvePermission = "identity.organization_unit_delivery.resolve"
	DeliveryListPermission    = "identity.organization_unit_delivery.list"
)

const (
	DefaultPageSize = 50
	MaxPageSize     = 100
)

type NodeType string

const NodeTypeCompany NodeType = "company"

func (value NodeType) Valid() bool {
	raw := string(value)
	if raw == "" || len(raw) > 64 || raw != strings.TrimSpace(raw) || raw[0] < 'a' || raw[0] > 'z' {
		return false
	}
	for _, char := range raw[1:] {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' {
			return false
		}
	}
	return raw[len(raw)-1] != '_'
}

// ValidDeliveryChild reports whether V1 may create the type through the
// generic delivery capability. Company remains host-owned and root-only; all
// non-root node types use the same lifecycle contract.
func (value NodeType) ValidDeliveryChild() bool {
	return value.Valid() && value != NodeTypeCompany
}

// CreateCandidate deliberately accepts only create-time facts. Identity owns
// status, path, ancestors, and depth. A parent is mandatory, so company (the
// root node type) is not accepted by V1.
type CreateCandidate struct {
	OrganizationID       string   `json:"organization_id"`
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	NodeType             NodeType `json:"node_type"`
	ParentOrganizationID string   `json:"parent_organization_id"`
	SortOrder            int      `json:"sort_order,omitempty"`
	ExpectedVersion      int64    `json:"expected_version"`
}

type DeliveryRequest struct {
	ContractVersion string          `json:"contract_version"`
	AccessToken     string          `json:"-"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Organization    CreateCandidate `json:"organization"`
}

// DeliveredOrganizationUnit contains only canonical, non-secret Identity
// facts. Version is the delivery aggregate's optimistic-concurrency evidence;
// V1 creates start at version 1.
type DeliveredOrganizationUnit struct {
	ID                   int64    `json:"id"`
	OrganizationUnitID   string   `json:"organization_unit_id"`
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	NodeType             NodeType `json:"node_type"`
	Status               string   `json:"status"`
	ParentOrganizationID string   `json:"parent_organization_id"`
	Path                 string   `json:"path"`
	AncestorIDs          []string `json:"ancestor_ids"`
	Depth                int      `json:"depth"`
	SortOrder            int      `json:"sort_order"`
	Version              int64    `json:"version"`
}

type DeliveryResult struct {
	DeliveryID   string                    `json:"delivery_id"`
	Organization DeliveredOrganizationUnit `json:"organization"`
	Replayed     bool                      `json:"replayed"`
}

type MutationOperation string

const (
	MutationRename  MutationOperation = "rename"
	MutationDisable MutationOperation = "disable"
)

func (value MutationOperation) Valid() bool {
	return value == MutationRename || value == MutationDisable
}

// MutationCandidate identifies an existing node and the exact lifecycle
// transition requested by source-owned code. Identity preserves node type,
// code, parent and hierarchy; only rename changes Name.
type MutationCandidate struct {
	Operation       MutationOperation `json:"operation"`
	OrganizationID  string            `json:"organization_id"`
	NodeType        NodeType          `json:"node_type"`
	Name            string            `json:"name,omitempty"`
	ExpectedVersion int64             `json:"expected_version"`
}

type MutationRequest struct {
	ContractVersion string            `json:"contract_version"`
	AccessToken     string            `json:"-"`
	IdempotencyKey  string            `json:"idempotency_key"`
	Organization    MutationCandidate `json:"organization"`
}

// ResolveRequest requires the expected type. Identity resolves and authorizes
// against the node's persisted active parent; callers neither discover nor
// supply a potentially forged parent ID.
type ResolveRequest struct {
	ContractVersion string   `json:"contract_version"`
	AccessToken     string   `json:"-"`
	OrganizationID  string   `json:"organization_id"`
	NodeType        NodeType `json:"node_type"`
}

type ListRequest struct {
	ContractVersion string   `json:"contract_version"`
	AccessToken     string   `json:"-"`
	NodeType        NodeType `json:"node_type"`
	PageSize        int      `json:"page_size,omitempty"`
	Cursor          string   `json:"cursor,omitempty"`
}

type Page struct {
	Items      []DeliveredOrganizationUnit `json:"items"`
	NextCursor string                      `json:"next_cursor,omitempty"`
}

type Delivery interface {
	CreateOrganizationUnit(context.Context, DeliveryRequest) (DeliveryResult, error)
	MutateOrganizationUnit(context.Context, MutationRequest) (DeliveryResult, error)
	ResolveOrganizationUnit(context.Context, ResolveRequest) (DeliveredOrganizationUnit, error)
	ListOrganizationUnits(context.Context, ListRequest) (Page, error)
}

type UnitOfWorkBinder interface {
	BindOrganizationUnitDeliveryUnitOfWork(identitysdk.EmbeddedTransaction) (Delivery, error)
}

type Binding interface {
	OrganizationUnitDelivery() Delivery
}

type EmbeddedBinding interface {
	OrganizationUnitDeliveryUnitOfWorkBinder() UnitOfWorkBinder
}
