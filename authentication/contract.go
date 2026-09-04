package authentication

import "context"

type AuthSession struct {
	SessionID             SessionID `json:"session_id,omitempty"`
	TenantID              TenantID  `json:"tenant_id,omitempty"`
	WorkspaceID           string    `json:"workspace_id"`
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token,omitempty"`
	TokenType             string    `json:"token_type"`
	ExpiresAt             string    `json:"expires_at"`
	User                  User      `json:"user"`
	Roles                 []Role    `json:"roles"`
	DefaultRole           string    `json:"default_role"`
	Permissions           []string  `json:"permissions"`
	MustChangePassword    bool      `json:"must_change_password"`
	AuthenticationTime    int64     `json:"auth_time,omitempty"`
	AuthenticationMethods []string  `json:"amr,omitempty"`
	AssuranceLevel        string    `json:"acr,omitempty"`
}

type Provider struct {
	Key            string   `json:"key"`
	Label          string   `json:"label"`
	Type           string   `json:"type"`
	Enabled        bool     `json:"enabled"`
	Priority       string   `json:"priority,omitempty"`
	Market         string   `json:"market,omitempty"`
	Markets        []string `json:"markets,omitempty"`
	Channels       []string `json:"channels,omitempty"`
	SelectedMarket string   `json:"selected_market,omitempty"`
	MarketFit      string   `json:"market_fit,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	AuthURL        string   `json:"auth_url,omitempty"`
	RedirectURL    string   `json:"redirect_url,omitempty"`
	Scope          string   `json:"scope,omitempty"`
}

type ProviderChallenge struct {
	Provider          string          `json:"provider"`
	State             string          `json:"state"`
	Type              string          `json:"type,omitempty"`
	Purpose           string          `json:"purpose,omitempty"`
	Status            ChallengeStatus `json:"status,omitempty"`
	Nonce             string          `json:"nonce,omitempty"`
	Code              string          `json:"code,omitempty"`
	AuthURL           string          `json:"auth_url,omitempty"`
	MaskedDestination string          `json:"masked_destination,omitempty"`
	RetryAt           string          `json:"retry_at,omitempty"`
	ExpiresAt         string          `json:"expires_at"`
}

type ChallengeStatus string

const (
	ChallengeStatusPendingDelivery ChallengeStatus = "pending_delivery"
	ChallengeStatusActive          ChallengeStatus = "active"
	ChallengeStatusFailed          ChallengeStatus = "failed"
	ChallengeStatusConsumed        ChallengeStatus = "consumed"
	ChallengeStatusExpired         ChallengeStatus = "expired"
	ChallengeStatusSuperseded      ChallengeStatus = "superseded"
)

type AuthenticationStatus string

const (
	AuthenticationStatusAuthenticated     AuthenticationStatus = "authenticated"
	AuthenticationStatusChallengeRequired AuthenticationStatus = "challenge_required"
)

// AuthenticationOutcome prevents callers from treating a verified first
// factor as a completed login. Session is populated only after every required
// factor has completed.
type AuthenticationOutcome struct {
	Status    AuthenticationStatus `json:"status"`
	Session   *AuthSession         `json:"session,omitempty"`
	Challenge *ProviderChallenge   `json:"challenge,omitempty"`
}

type ProviderQuery struct {
	TenantID    TenantID    `json:"tenant_id,omitempty"`
	WorkspaceID WorkspaceID `json:"workspace_id"`
}

type PasswordLoginRequest struct {
	TenantID       TenantID       `json:"tenant_id,omitempty"`
	WorkspaceID    WorkspaceID    `json:"workspace_id"`
	ApplicationKey ApplicationKey `json:"application_key,omitempty"`
	Login          string         `json:"login"`
	Password       string         `json:"password"`
}

type BeginFederatedLoginRequest struct {
	TenantID       TenantID       `json:"tenant_id,omitempty"`
	WorkspaceID    WorkspaceID    `json:"workspace_id"`
	ApplicationKey ApplicationKey `json:"application_key,omitempty"`
	Provider       string         `json:"provider"`
	ReturnURL      string         `json:"return_url,omitempty"`
	Phone          string         `json:"phone,omitempty"`
}

type CompleteFederatedLoginRequest struct {
	Provider string            `json:"provider"`
	Values   map[string]string `json:"values"`
}

// FederatedLoginCompletion carries only the one-time authorization-code
// handoff. Provider callbacks never expose a refresh or access token in the
// browser URL or callback response.
type FederatedLoginCompletion struct {
	AuthorizationCode string `json:"authorization_code"`
	ReturnURL         string `json:"return_url"`
	State             string `json:"state,omitempty"`
}

type VerifyOTPRequest struct {
	TenantID    TenantID    `json:"tenant_id,omitempty"`
	WorkspaceID WorkspaceID `json:"workspace_id"`
	Provider    string      `json:"provider"`
	State       string      `json:"state"`
	Code        string      `json:"code"`
}

type RefreshRequest struct {
	TenantID       TenantID       `json:"tenant_id,omitempty"`
	WorkspaceID    WorkspaceID    `json:"workspace_id"`
	ApplicationKey ApplicationKey `json:"application_key"`
	SessionID      SessionID      `json:"session_id,omitempty"`
	RefreshToken   string         `json:"refresh_token,omitempty"`
}

type LogoutRequest struct {
	TenantID       TenantID       `json:"tenant_id,omitempty"`
	WorkspaceID    WorkspaceID    `json:"workspace_id"`
	ApplicationKey ApplicationKey `json:"application_key"`
	SessionID      SessionID      `json:"session_id,omitempty"`
	RefreshToken   string         `json:"refresh_token,omitempty"`
}

type CurrentSessionRequest struct {
	AccessToken string `json:"-"`
}

type ExchangeAuthorizationCodeRequest struct {
	WorkspaceID    WorkspaceID    `json:"workspace_id"`
	Code           string         `json:"code"`
	ApplicationKey ApplicationKey `json:"application_key"`
	ReturnURL      string         `json:"return_url"`
}

type SessionView struct {
	SessionID             SessionID             `json:"session_id,omitempty"`
	TenantID              TenantID              `json:"tenant_id,omitempty"`
	WorkspaceID           WorkspaceID           `json:"workspace_id"`
	SubjectID             SubjectID             `json:"subject_id"`
	AuthorizationRevision AuthorizationRevision `json:"authorization_revision,omitempty"`
	User                  User                  `json:"user"`
	Roles                 []Role                `json:"roles"`
	DefaultRole           string                `json:"default_role,omitempty"`
	Permissions           []string              `json:"permissions,omitempty"`
	MustChangePassword    bool                  `json:"must_change_password"`
}

type Authentication interface {
	Providers(context.Context, ProviderQuery) ([]Provider, error)
	LoginWithPassword(context.Context, PasswordLoginRequest) (AuthSession, error)
	BeginFederatedLogin(context.Context, BeginFederatedLoginRequest) (ProviderChallenge, error)
	CompleteFederatedLogin(context.Context, CompleteFederatedLoginRequest) (FederatedLoginCompletion, error)
	ExchangeAuthorizationCode(context.Context, ExchangeAuthorizationCodeRequest) (AuthSession, error)
	VerifyOTP(context.Context, VerifyOTPRequest) (AuthSession, error)
	RefreshSession(context.Context, RefreshRequest) (AuthSession, error)
	LogoutSession(context.Context, LogoutRequest) error
	CurrentSession(context.Context, CurrentSessionRequest) (SessionView, error)
}

// ChallengeAuthentication is an optional protocol-v3 capability. Legacy
// Authentication methods remain available for clients that do not enable MFA;
// challenge-aware clients should use this capability exclusively for login
// and OTP completion.
type ChallengeAuthentication interface {
	LoginWithPasswordOutcome(context.Context, PasswordLoginRequest) (AuthenticationOutcome, error)
	VerifyOTPOutcome(context.Context, VerifyOTPRequest) (AuthenticationOutcome, error)
}

type ChangePasswordRequest struct {
	AccessToken     string `json:"-"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	IdempotencyKey  string `json:"-"`
}

type ResetPasswordRequest struct {
	AccessToken        string      `json:"-"`
	WorkspaceID        WorkspaceID `json:"workspace_id"`
	SubjectID          SubjectID   `json:"subject_id"`
	NewPassword        string      `json:"new_password"`
	MustChangePassword bool        `json:"must_change_password"`
	IdempotencyKey     string      `json:"-"`
}

type RevokeSessionsRequest struct {
	AccessToken    string      `json:"-"`
	WorkspaceID    WorkspaceID `json:"workspace_id"`
	SubjectID      SubjectID   `json:"subject_id"`
	IdempotencyKey string      `json:"-"`
}

type CredentialManager interface {
	ChangePassword(context.Context, ChangePasswordRequest) (AuthSession, error)
	ResetPassword(context.Context, ResetPasswordRequest) error
	RevokeSessions(context.Context, RevokeSessionsRequest) error
}
