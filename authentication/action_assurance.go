package authentication

import "context"

// BeginActionAssuranceRequest starts a user-bound step-up challenge. The
// access token is transport metadata and is never serialized into a JSON body.
type BeginActionAssuranceRequest struct {
	WorkspaceID WorkspaceID `json:"workspace_id"`
	AccessToken string      `json:"-"`
}

type VerifyActionAssuranceRequest struct {
	WorkspaceID WorkspaceID `json:"workspace_id"`
	AccessToken string      `json:"-"`
	Provider    string      `json:"provider"`
	State       string      `json:"state"`
	Code        string      `json:"code"`
}

// ActionAssuranceReceipt is an Identity-signed, short-lived proof. Runtime
// validates it through Identity before minting its one-time payload-bound
// Action assurance grant.
type ActionAssuranceReceipt struct {
	Token       string      `json:"token"`
	WorkspaceID WorkspaceID `json:"workspace_id"`
	SubjectID   SubjectID   `json:"subject_id"`
	Methods     []string    `json:"methods"`
	ExpiresAt   string      `json:"expires_at"`
}

type ValidateActionAssuranceReceiptRequest struct {
	Token       string      `json:"token"`
	WorkspaceID WorkspaceID `json:"workspace_id"`
	SubjectID   SubjectID   `json:"subject_id"`
	AccessToken string      `json:"-"`
}

type ActionAssurance interface {
	BeginActionAssurance(context.Context, BeginActionAssuranceRequest) (ProviderChallenge, error)
	VerifyActionAssurance(context.Context, VerifyActionAssuranceRequest) (ActionAssuranceReceipt, error)
	ValidateActionAssuranceReceipt(context.Context, ValidateActionAssuranceReceiptRequest) (ActionAssuranceReceipt, error)
}
