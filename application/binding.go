// Package application binds a deployment-neutral Identity implementation to
// one Runtime application.
package application

import (
	"context"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/modulecapability"
	identity "github.com/domainry/domainry-identity-sdk"
)

// Bind scopes delegate to exactly one workspace and application key. Both the
// in-process module factory and the remote SaaS factory use this wrapper.
func Bind(delegate identity.Binding, application identity.ApplicationRef) (identity.Binding, error) {
	application.WorkspaceID = identity.WorkspaceID(strings.TrimSpace(string(application.WorkspaceID)))
	application.ApplicationKey = identity.ApplicationKey(strings.TrimSpace(string(application.ApplicationKey)))
	if delegate == nil || !application.WorkspaceID.Valid() || !application.ApplicationKey.Valid() {
		return nil, scopeError(http.StatusBadRequest, "identity.application_scope_invalid")
	}
	descriptor := delegate.Descriptor()
	if audience := strings.TrimSpace(descriptor.Audience); audience != "" && audience != string(application.ApplicationKey) {
		return nil, scopeError(http.StatusForbidden, "identity.application_scope_mismatch")
	}
	descriptor.Audience = string(application.ApplicationKey)
	return &binding{delegate: delegate, application: application, descriptor: descriptor}, nil
}

type binding struct {
	delegate    identity.Binding
	application identity.ApplicationRef
	descriptor  identity.Descriptor
}

func (value *binding) Descriptor() identity.Descriptor { return value.descriptor }
func (value *binding) CapabilitySummary(ctx context.Context) (modulecapability.ModuleSummary, error) {
	return value.delegate.CapabilitySummary(ctx)
}
func (value *binding) CapabilityCategory(ctx context.Context, key string) (modulecapability.CategoryDocument, error) {
	return value.delegate.CapabilityCategory(ctx, key)
}
func (value *binding) ValidateCapabilityCandidate(ctx context.Context, request modulecapability.ValidationRequest) (modulecapability.ValidationResult, error) {
	return value.delegate.ValidateCapabilityCandidate(ctx, request)
}
func (value *binding) Authentication() identity.Authentication {
	return authentication{binding: value}
}
func (value *binding) Tokens() identity.TokenVerifier { return tokens{binding: value} }
func (value *binding) Authorization() identity.Authorization {
	return authorization{binding: value}
}
func (value *binding) Principals() identity.PrincipalResolver { return principals{binding: value} }
func (value *binding) Directory() identity.Directory          { return directory{binding: value} }
func (value *binding) Catalog() identity.CatalogClient        { return catalog{binding: value} }
func (value *binding) Credentials() identity.CredentialManager {
	return credentials{binding: value}
}
func (value *binding) ApplicationServices() identity.ApplicationServiceAuthentication {
	return applicationServices{binding: value}
}
func (value *binding) Close(ctx context.Context) error { return value.delegate.Close(ctx) }

func (value *binding) workspace(input identity.WorkspaceID) (identity.WorkspaceID, error) {
	input = identity.WorkspaceID(strings.TrimSpace(string(input)))
	if input == "" {
		return value.application.WorkspaceID, nil
	}
	if input != value.application.WorkspaceID {
		return "", scopeError(http.StatusForbidden, "auth.workspace_mismatch")
	}
	return input, nil
}

func (value *binding) applicationKey(input identity.ApplicationKey) (identity.ApplicationKey, error) {
	input = identity.ApplicationKey(strings.TrimSpace(string(input)))
	if input == "" {
		return value.application.ApplicationKey, nil
	}
	if input != value.application.ApplicationKey {
		return "", scopeError(http.StatusForbidden, "identity.application_mismatch")
	}
	return input, nil
}

func (value *binding) applicationScope(input identity.ApplicationScope) (identity.ApplicationScope, error) {
	workspaceID, err := value.workspace(input.WorkspaceID)
	if err != nil {
		return identity.ApplicationScope{}, err
	}
	applicationKey, err := value.applicationKey(input.ApplicationKey)
	if err != nil {
		return identity.ApplicationScope{}, err
	}
	input.WorkspaceID, input.ApplicationKey = workspaceID, applicationKey
	if input.TenantID == "" {
		input.TenantID = value.application.TenantID
	} else if value.application.TenantID != "" && input.TenantID != value.application.TenantID {
		return identity.ApplicationScope{}, scopeError(http.StatusForbidden, "identity.tenant_mismatch")
	}
	return input, nil
}

func (value *binding) verifyAccessToken(ctx context.Context, accessToken string) (identity.VerifiedToken, error) {
	return value.delegate.Tokens().Verify(ctx, identity.VerifyTokenRequest{
		AccessToken: accessToken, Issuer: value.descriptor.Issuer, Audience: value.application.ApplicationKey,
	})
}

func (value *binding) verifySession(ctx context.Context, session identity.AuthSession) error {
	if identity.WorkspaceID(strings.TrimSpace(session.WorkspaceID)) != value.application.WorkspaceID || strings.TrimSpace(session.AccessToken) == "" {
		return scopeError(http.StatusBadGateway, "identity.session_scope_invalid")
	}
	verified, err := value.verifyAccessToken(ctx, session.AccessToken)
	if err != nil {
		return err
	}
	if verified.WorkspaceID != value.application.WorkspaceID || verified.Audience != value.application.ApplicationKey {
		return scopeError(http.StatusBadGateway, "identity.session_scope_invalid")
	}
	return nil
}

func scopeError(status int, code string) error {
	return &identity.Error{StatusCode: status, Code: code}
}

var _ identity.Binding = (*binding)(nil)
var _ identity.ApplicationServiceBinding = (*binding)(nil)
