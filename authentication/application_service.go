package authentication

import (
	"context"
	"strings"
	"time"

	"github.com/domainry/domainry-identity-sdk/authorization"
)

// ApplicationServiceGrant is an exact catalog-declared capability carried by
// a short-lived application service token. It is deliberately narrower than
// an end-user role or workspace administrator grant.
type ApplicationServiceGrant struct {
	Resource authorization.ResourceType `json:"resource"`
	Action   authorization.Action       `json:"action"`
}

type ExchangeApplicationServiceTokenRequest struct {
	Application authorization.ApplicationRef `json:"application"`
	Audience    authorization.ApplicationKey `json:"audience"`
	Grants      []ApplicationServiceGrant    `json:"grants"`
	Credential  string                       `json:"-"`
}

type ApplicationServiceToken struct {
	AccessToken  string                       `json:"access_token"`
	TokenType    string                       `json:"token_type"`
	ExpiresAt    time.Time                    `json:"expires_at"`
	Application  authorization.ApplicationRef `json:"application"`
	Audience     authorization.ApplicationKey `json:"audience"`
	CredentialID string                       `json:"credential_id"`
	Grants       []ApplicationServiceGrant    `json:"grants"`
}

type VerifyApplicationServiceTokenRequest struct {
	AccessToken string                       `json:"access_token"`
	Audience    authorization.ApplicationKey `json:"audience"`
	Grant       ApplicationServiceGrant      `json:"grant"`
}

type ApplicationServicePrincipal struct {
	SubjectID             authorization.SubjectID             `json:"subject_id"`
	Application           authorization.ApplicationRef        `json:"application"`
	Audience              authorization.ApplicationKey        `json:"audience"`
	CredentialID          string                              `json:"credential_id"`
	AuthorizationRevision authorization.AuthorizationRevision `json:"authorization_revision"`
	ExpiresAt             time.Time                           `json:"expires_at"`
}

// ApplicationServiceAuthentication exchanges a long-lived, application-bound
// static credential only at Identity and verifies the resulting short-lived
// service token at a resource service. Static credentials are never forwarded
// to downstream SaaS services.
type ApplicationServiceAuthentication interface {
	Exchange(context.Context, ExchangeApplicationServiceTokenRequest) (ApplicationServiceToken, error)
	Verify(context.Context, VerifyApplicationServiceTokenRequest) (ApplicationServicePrincipal, error)
}

func (grant ApplicationServiceGrant) Valid() bool {
	return grant.Resource.Valid() && grant.Action.Valid()
}

func (request ExchangeApplicationServiceTokenRequest) Validate() error {
	if !request.Application.TenantID.Valid() || !request.Application.WorkspaceID.Valid() || !request.Application.ApplicationKey.Valid() ||
		!request.Audience.Valid() || strings.TrimSpace(request.Credential) == "" || len(request.Grants) == 0 {
		return &authorization.Error{Code: "identity.application_service_exchange_invalid"}
	}
	seen := map[string]struct{}{}
	for _, grant := range request.Grants {
		key := string(grant.Resource) + "\x00" + string(grant.Action)
		if !grant.Valid() {
			return &authorization.Error{Code: "identity.application_service_grant_invalid"}
		}
		if _, duplicate := seen[key]; duplicate {
			return &authorization.Error{Code: "identity.application_service_grant_duplicate"}
		}
		seen[key] = struct{}{}
	}
	return nil
}
