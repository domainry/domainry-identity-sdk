package remote

import (
	"context"
	"net/http"
	"strings"

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
	delegate := &binding{client: client, tokens: verifier, descriptor: identity.Descriptor{
		ProtocolVersion: identity.CurrentProtocolVersion, BundleVersion: identity.CurrentPolicyBundleVersion,
		CatalogVersion: identity.CatalogVersionV1, Mode: identity.DeploymentModeSaaS, Issuer: issuer, Audience: audience,
		Capabilities: []string{"authentication", "token_verification", "authorization", "principal_resolution", "directory_projection", "catalog", "credentials", "oidc", "saml"},
	}}
	return identityapplication.Bind(delegate, application)
}

func remoteApplication(config Config, application identity.ApplicationRef) (Config, identity.ApplicationRef, error) {
	configured := identity.ApplicationRef{
		WorkspaceID: identity.WorkspaceID(strings.TrimSpace(config.WorkspaceID)), ApplicationKey: identity.ApplicationKey(strings.TrimSpace(config.Audience)),
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
	config.WorkspaceID, config.Audience = string(application.WorkspaceID), string(application.ApplicationKey)
	return config, application, nil
}

func validateDiscovery(descriptor identity.Descriptor, expectedIssuer string) error {
	if descriptor.ProtocolVersion != identity.CurrentProtocolVersion || descriptor.BundleVersion != identity.CurrentPolicyBundleVersion || descriptor.CatalogVersion != identity.CatalogVersionV1 || descriptor.Mode != identity.DeploymentModeSaaS {
		return &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.protocol_incompatible"}
	}
	if strings.TrimSpace(descriptor.Issuer) != strings.TrimSpace(expectedIssuer) {
		return &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.issuer_mismatch"}
	}
	required := map[string]bool{"authentication": false, "token_verification": false, "authorization": false, "principal_resolution": false, "directory_projection": false, "catalog": false}
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
	client     *client
	tokens     identity.TokenVerifier
	descriptor identity.Descriptor
}

func (value *binding) Descriptor() identity.Descriptor { return value.descriptor }
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
func (value *binding) Directory() identity.Directory   { return directoryClient{client: value.client} }
func (value *binding) Catalog() identity.CatalogClient { return catalogClient{client: value.client} }
func (value *binding) Credentials() identity.CredentialManager {
	return credentialClient{client: value.client}
}
func (value *binding) ApplicationServices() identity.ApplicationServiceAuthentication {
	return applicationServices{client: value.client}
}
func (value *binding) Close(context.Context) error { return nil }

var _ identity.Factory = (*Factory)(nil)
var _ identity.Binding = (*binding)(nil)
var _ identity.ApplicationServiceBinding = (*binding)(nil)
