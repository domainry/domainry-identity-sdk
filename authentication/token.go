package authentication

import "context"

type VerifyTokenRequest struct {
	AccessToken string         `json:"-"`
	Issuer      string         `json:"issuer,omitempty"`
	Audience    ApplicationKey `json:"audience,omitempty"`
}

type VerifiedToken struct {
	Issuer                string                `json:"iss"`
	Audience              ApplicationKey        `json:"aud"`
	SubjectID             SubjectID             `json:"sub"`
	TenantID              TenantID              `json:"tenant_id"`
	WorkspaceID           WorkspaceID           `json:"workspace_id"`
	SessionID             SessionID             `json:"sid"`
	AuthorizationRevision AuthorizationRevision `json:"authz_revision"`
	AuthenticationTime    int64                 `json:"auth_time,omitempty"`
	AuthenticationMethods []string              `json:"amr,omitempty"`
	AssuranceLevel        string                `json:"acr,omitempty"`
	IssuedAt              int64                 `json:"iat"`
	ExpiresAt             int64                 `json:"exp"`
	TokenID               string                `json:"jti"`
}

type TokenVerifier interface {
	Verify(context.Context, VerifyTokenRequest) (VerifiedToken, error)
}
