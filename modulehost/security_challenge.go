package modulehost

import "context"

// SecurityChallengeDelivery is a consuming-side host capability. Identity
// owns challenge policy and plaintext lifetime; the host owns connector
// selection, connection secrets, provider execution, and delivery evidence.
type SecurityChallengeDelivery interface {
	DeliverSecurityChallenge(context.Context, SecurityChallengeDeliveryRequest) (SecurityChallengeDeliveryReceipt, error)
}

type SecurityChallengeDeliveryRequest struct {
	ChallengeID       string `json:"challenge_id"`
	WorkspaceID       string `json:"workspace_id"`
	ConnectionKey     string `json:"connection_key"`
	Channel           string `json:"channel"`
	Destination       string `json:"destination"`
	MaskedDestination string `json:"masked_destination"`
	Message           string `json:"message"`
	ExpiresAt         string `json:"expires_at"`
}

type SecurityChallengeDeliveryReceipt struct {
	Status      string `json:"status"`
	ResponseRef string `json:"response_ref,omitempty"`
}
