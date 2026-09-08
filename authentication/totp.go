package authentication

import "context"

// TOTPManager is an optional self-service extension of CredentialManager.
// Identity derives the subject and Workspace from the validated access token.
type TOTPManager interface {
	ManageTOTP(context.Context, TOTPRequest) (TOTPResult, error)
}

type TOTPRequest struct {
	AccessToken     string `json:"-"`
	Operation       string `json:"operation"`
	CurrentPassword string `json:"current_password,omitempty"`
	State           string `json:"state,omitempty"`
	Code            string `json:"code,omitempty"`
}

type TOTPResult struct {
	Enabled bool `json:"enabled"`

	State      string `json:"state,omitempty"`
	SetupKey   string `json:"setup_key,omitempty"`
	OTPAuthURL string `json:"otpauth_url,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}
