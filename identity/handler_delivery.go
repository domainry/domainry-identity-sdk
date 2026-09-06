package identity

import "context"

// HandlerDeliveryContractVersionV1 is the stable contract consumed by
// generated Runtime business handlers. Requests deliberately carry no
// workspace, actor user, or actor role: the provider derives all authority
// from AccessToken and its application-scoped Binding.
const HandlerDeliveryContractVersionV1 = "domainry-identity-handler-delivery-v1"

// These purpose-specific grants authorize only the composed HandlerDelivery
// use cases. They are not aliases for Identity's public user, role-assignment,
// or profile-binding CRUD permissions.
const (
	HandlerDeliveryCreatePermission  = "identity.handler_delivery.create"
	HandlerDeliveryUpdatePermission  = "identity.handler_delivery.update"
	HandlerDeliveryDisablePermission = "identity.handler_delivery.disable"
	HandlerDeliveryResolvePermission = "identity.handler_delivery.resolve"
)

type HandlerUserOperation string

type HandlerLoginMode string

const (
	HandlerUserCreate    HandlerUserOperation = "create"
	HandlerUserUpdate    HandlerUserOperation = "update"
	HandlerUserDisable   HandlerUserOperation = "disable"
	HandlerLoginNone     HandlerLoginMode     = "none"
	HandlerLoginPassword HandlerLoginMode     = "password"
)

func (value HandlerUserOperation) Valid() bool {
	switch value {
	case HandlerUserCreate, HandlerUserUpdate, HandlerUserDisable:
		return true
	default:
		return false
	}
}

// HandlerUserMutation is a complete desired Identity user projection. Update
// and disable require the current ExpectedVersion; create requires zero.
type HandlerUserMutation struct {
	Operation       HandlerUserOperation `json:"operation"`
	User            User                 `json:"user"`
	ExpectedVersion int64                `json:"expected_version"`
	// LoginMode is required for create and must be empty for update/disable.
	// The handler never supplies a password or password hash.
	LoginMode HandlerLoginMode `json:"login_mode,omitempty"`
}

// HandlerProfileBindingMutation requests one exact one-to-one business
// profile relation. Identity resolves the relation field and lifecycle policy
// from its trusted metadata; a handler cannot select a database column.
type HandlerProfileBindingMutation struct {
	BindingKey      string `json:"binding_key"`
	ObjectKey       string `json:"object_key"`
	ProfileID       string `json:"profile_id"`
	ExpectedVersion int64  `json:"expected_version"`
	Reason          string `json:"reason,omitempty"`
	ApprovalID      string `json:"approval_id,omitempty"`
	// EmbeddedProfileRecord is an in-memory pre-binding projection prepared by
	// Runtime after its own record validation. Only the embedded UoW adapter
	// recognizes it; remote/unbound SDK delivery ignores it.
	EmbeddedProfileRecord map[string]any `json:"-"`
}

// HandlerDeliveryRequest atomically delivers an Identity user, the exact set
// of manual roles, and an optional one-to-one profile binding. AccessToken is
// injected by the trusted Runtime invocation boundary and is never serialized.
type HandlerDeliveryRequest struct {
	ContractVersion string                         `json:"contract_version"`
	AccessToken     string                         `json:"-"`
	IdempotencyKey  string                         `json:"idempotency_key"`
	User            HandlerUserMutation            `json:"user"`
	RoleKeys        []string                       `json:"role_keys"`
	ProfileBinding  *HandlerProfileBindingMutation `json:"profile_binding,omitempty"`
}

type HandlerProfileBinding struct {
	BindingKey     string `json:"binding_key"`
	ObjectKey      string `json:"object_key"`
	ProfileID      string `json:"profile_id"`
	IdentityUserID string `json:"identity_user_id"`
	Status         string `json:"status"`
	Version        int64  `json:"version"`
}

// HandlerProfileBindingSelector identifies one statically published business
// profile binding. Runtime derives BindingKey and ObjectKey from the generated
// Action capability; project handlers may supply only the profile identifier
// through that generated wrapper.
type HandlerProfileBindingSelector struct {
	BindingKey string `json:"binding_key"`
	ObjectKey  string `json:"object_key"`
	ProfileID  string `json:"profile_id"`
}

type HandlerDeliveryResult struct {
	DeliveryID      string                 `json:"delivery_id"`
	User            User                   `json:"user"`
	RoleKeys        []string               `json:"role_keys"`
	ProfileBinding  *HandlerProfileBinding `json:"profile_binding,omitempty"`
	RevokedSessions int                    `json:"revoked_sessions"`
	Replayed        bool                   `json:"replayed"`
	// InitialCredential is in-memory only and exists solely on the first
	// successful password-login create. Runtime must mark its eventual Action
	// response no-store and must not log, persist, or cache this value.
	InitialCredential *HandlerInitialCredential `json:"-"`
}

type HandlerInitialCredential struct {
	InitialPassword    string `json:"-"`
	MustChangePassword bool   `json:"must_change_password"`
	NoStore            bool   `json:"no_store"`
}

// HandlerBoundIdentityRequest resolves a business profile's already-persisted
// identity_user_id. Business handlers supply that candidate identifier and,
// through a generated wrapper, may select one exact statically published
// profile. Identity derives workspace, actor, role, and hierarchy from the
// bearer and returns the profile binding only after exact-user verification.
type HandlerBoundIdentityRequest struct {
	ContractVersion string                         `json:"contract_version"`
	AccessToken     string                         `json:"-"`
	UserID          string                         `json:"user_id"`
	ProfileBinding  *HandlerProfileBindingSelector `json:"profile_binding,omitempty"`
}

// HandlerBoundIdentity is the minimal canonical projection business handlers
// may use for staff attribution and eligibility decisions. It deliberately
// excludes mutable business-profile duplicates and all credential/session data.
type HandlerBoundIdentity struct {
	UserID                string   `json:"user_id"`
	DisplayName           string   `json:"display_name"`
	Status                string   `json:"status"`
	Active                bool     `json:"active"`
	Version               int64    `json:"version"`
	OrganizationID        string   `json:"organization_id,omitempty"`
	OrganizationPath      string   `json:"organization_path,omitempty"`
	OrganizationScopeIDs  []string `json:"organization_scope_ids,omitempty"`
	SupportOrganizationID string   `json:"support_organization_id,omitempty"`
	SupportOrgScopeIDs    []string `json:"support_organization_scope_ids,omitempty"`
	ManagerUserID         string   `json:"manager_user_id,omitempty"`
	ReportingPath         string   `json:"reporting_path,omitempty"`
	ReportingScopeUserIDs []string `json:"reporting_scope_user_ids,omitempty"`
	RoleKeys              []string `json:"role_keys"`
	// ProfileBinding is present only when the trusted caller requested one
	// exact published binding and it is actively bound to UserID. Its Version
	// is the Identity-owned CAS value for a subsequent atomic update/disable.
	ProfileBinding *HandlerProfileBinding `json:"profile_binding,omitempty"`
}

// HandlerDelivery is the deployment-neutral command surface. The default
// method is owned by Identity's transaction boundary.
type HandlerDelivery interface {
	DeliverIdentity(context.Context, HandlerDeliveryRequest) (HandlerDeliveryResult, error)
	ResolveBoundIdentity(context.Context, HandlerBoundIdentityRequest) (HandlerBoundIdentity, error)
}
