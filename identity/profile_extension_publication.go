package identity

import "context"

// ProjectProfileExtension is the typed application-owned metadata needed by
// Identity's profile binding service. It deliberately publishes field names as
// metadata only; HandlerDelivery never accepts a relation column from a caller.
type ProjectProfileExtension struct {
	ObjectKey             string
	IdentityRelationField string
	Cardinality           string
	BusinessIdentity      ProjectBusinessIdentityBinding
	BindingLifecycle      ProjectProfileBindingLifecycle
	DefaultVisibility     string
	RequiredPermissions   []string
}

type ProjectBusinessIdentityBinding struct {
	Key                string
	StatusField        string
	ActiveStatusValues []string
	BlacklistField     string
	Claims             []ProjectProfileClaimBinding
}

type ProjectProfileClaimBinding struct {
	ClaimKey string
	FieldKey string
}

type ProjectProfileBindingLifecycle struct {
	AllowUnbound           bool
	InvitationChannels     []string
	ClaimProofs            []ProjectProfileClaimProof
	RebindRequiresApproval bool
	RebindRevokesSessions  bool
}

type ProjectProfileClaimProof struct {
	Type     string
	FieldKey string
}

type ProjectProfileExtensionPublisher interface {
	PublishProjectProfileExtensions(context.Context, []ProjectProfileExtension) error
}
