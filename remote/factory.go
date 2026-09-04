package remote

import (
	"context"
	"net/http"
	"strings"

	"github.com/domainry/domainry-foundation/modulecapability"
	identity "github.com/domainry/domainry-identity-sdk"
	identityapplication "github.com/domainry/domainry-identity-sdk/application"
)

type Factory struct{ config Config }

func NewFactory(config Config) *Factory { return &Factory{config: config} }

func (factory *Factory) Open(ctx context.Context, application identity.ApplicationRef) (identity.Binding, error) {
	if ctx == nil {
		return nil, &identity.Error{Code: "identity.context_required"}
	}
	if err := ctx.Err(); err != nil {
		return nil, &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.context_unavailable", Cause: err}
	}
	config := factory.config
	if err := modulecapability.ValidateRemoteExpectation("identity", config.CapabilityContractSHA256); err != nil {
		return nil, err
	}
	config, application, err := remoteApplication(config, application)
	if err != nil {
		return nil, err
	}
	client, err := newClient(config)
	if err != nil {
		return nil, err
	}
	issuer, audience := strings.TrimSpace(config.Issuer), strings.TrimSpace(config.Audience)
	if issuer == "" || audience == "" {
		return nil, &identity.Error{Code: "identity.remote_trust_required", Message: "issuer and audience are required"}
	}
	var discovery identity.Descriptor
	if err := client.doJSON(ctx, http.MethodGet, "/identity/discovery", "", nil, &discovery); err != nil {
		return nil, err
	}
	if err := validateDiscovery(discovery, issuer); err != nil {
		return nil, err
	}
	verifier, err := newJWKSVerifier(jwksVerifierConfig{
		Issuer: issuer, Audience: audience,
		Fetch: func(ctx context.Context, output any) error {
			return client.doJSON(ctx, http.MethodGet, "/.well-known/jwks.json", "", nil, output)
		},
		Now: client.now,
	})
	if err != nil {
		return nil, err
	}
	capabilities, err := openCapabilityBinding(ctx, client, strings.TrimSpace(config.CapabilityContractSHA256))
	if err != nil {
		return nil, err
	}
	delegate := &binding{client: client, tokens: verifier, descriptor: identity.Descriptor{
		ProtocolVersion: identity.CurrentProtocolVersion, BundleVersion: identity.CurrentPolicyBundleVersion,
		AuthorizationVersion: identity.CurrentAuthorizationContractVersion, Mode: identity.DeploymentModeSaaS, Issuer: issuer, Audience: audience,
		Capabilities: []string{"authentication", "token_verification", "authorization", "principal_resolution", "identity_projection", "application_registration", "permission_reconciliation", "credentials", "oidc", "saml"},
	}, capabilities: capabilities}
	return identityapplication.Bind(delegate, application)
}

func remoteApplication(config Config, application identity.ApplicationRef) (Config, identity.ApplicationRef, error) {
	configured := identity.ApplicationRef{
		TenantID: identity.TenantID(strings.TrimSpace(config.TenantID)), WorkspaceID: identity.WorkspaceID(strings.TrimSpace(config.WorkspaceID)), ApplicationKey: identity.ApplicationKey(strings.TrimSpace(config.Audience)),
	}
	if application.WorkspaceID.Valid() || application.ApplicationKey.Valid() {
		if !application.WorkspaceID.Valid() || !application.ApplicationKey.Valid() {
			return Config{}, identity.ApplicationRef{}, &identity.Error{Code: "identity.application_scope_invalid"}
		}
		if configured.WorkspaceID != "" && configured.WorkspaceID != application.WorkspaceID || configured.ApplicationKey != "" && configured.ApplicationKey != application.ApplicationKey {
			return Config{}, identity.ApplicationRef{}, &identity.Error{Code: "identity.application_scope_mismatch"}
		}
	} else {
		application = configured
	}
	if !application.WorkspaceID.Valid() || !application.ApplicationKey.Valid() {
		return Config{}, identity.ApplicationRef{}, &identity.Error{Code: "identity.application_scope_invalid"}
	}
	if application.TenantID == "" {
		application.TenantID = identity.TenantID(application.WorkspaceID)
	}
	config.TenantID, config.WorkspaceID, config.Audience = string(application.TenantID), string(application.WorkspaceID), string(application.ApplicationKey)
	return config, application, nil
}

func validateDiscovery(descriptor identity.Descriptor, expectedIssuer string) error {
	if descriptor.ProtocolVersion != identity.CurrentProtocolVersion || descriptor.BundleVersion != identity.CurrentPolicyBundleVersion || descriptor.AuthorizationVersion != identity.CurrentAuthorizationContractVersion || descriptor.Mode != identity.DeploymentModeSaaS {
		return &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.protocol_incompatible"}
	}
	if strings.TrimSpace(descriptor.Issuer) != strings.TrimSpace(expectedIssuer) {
		return &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.issuer_mismatch"}
	}
	required := map[string]bool{"authentication": false, "token_verification": false, "authorization": false, "principal_resolution": false, "identity_projection": false, "application_registration": false, "permission_reconciliation": false}
	for _, capability := range descriptor.Capabilities {
		if _, exists := required[capability]; exists {
			required[capability] = true
		}
	}
	for _, available := range required {
		if !available {
			return &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.capability_incomplete"}
		}
	}
	return nil
}

type binding struct {
	client       *client
	tokens       identity.TokenVerifier
	descriptor   identity.Descriptor
	capabilities modulecapability.Binding
}

func (value *binding) Descriptor() identity.Descriptor { return value.descriptor }
func (value *binding) CapabilitySummary(ctx context.Context) (modulecapability.ModuleSummary, error) {
	return value.capabilities.CapabilitySummary(ctx)
}
func (value *binding) CapabilityCategory(ctx context.Context, key string) (modulecapability.CategoryDocument, error) {
	return value.capabilities.CapabilityCategory(ctx, key)
}
func (value *binding) ValidateCapabilityCandidate(ctx context.Context, request modulecapability.ValidationRequest) (modulecapability.ValidationResult, error) {
	return value.capabilities.ValidateCapabilityCandidate(ctx, request)
}
func (value *binding) Authentication() identity.Authentication {
	return authentication{client: value.client}
}
func (value *binding) Tokens() identity.TokenVerifier { return value.tokens }
func (value *binding) Authorization() identity.Authorization {
	return authorization{client: value.client}
}
func (value *binding) Principals() identity.PrincipalResolver {
	return principalResolver{client: value.client}
}
func (value *binding) Projection() identity.Projection { return projectionClient{client: value.client} }
func (value *binding) Applications() identity.ApplicationRegistry {
	return applicationRegistry{client: value.client}
}
func (value *binding) Permissions() identity.PermissionRegistry {
	return permissionRegistry{client: value.client}
}
func (value *binding) Credentials() identity.CredentialManager {
	return credentialClient{client: value.client}
}
func (value *binding) ApplicationServices() identity.ApplicationServiceAuthentication {
	return applicationServices{client: value.client}
}
func (value *binding) ApplicationServiceVerifier() identity.ApplicationServiceTokenVerifier {
	return applicationServices{client: value.client}
}
func (value *binding) Close(context.Context) error { return nil }

var _ identity.Factory = (*Factory)(nil)
var _ identity.Binding = (*binding)(nil)
var _ identity.ApplicationServiceBinding = (*binding)(nil)
var _ identity.ApplicationServiceVerificationBinding = (*binding)(nil)
