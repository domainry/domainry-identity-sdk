package application

import (
	"context"
	"testing"

	"github.com/domainry/domainry-foundation/modulecapability"
	identity "github.com/domainry/domainry-identity-sdk"
)

type applicationBindingTestBase struct{}

func (*applicationBindingTestBase) Descriptor() identity.Descriptor { return identity.Descriptor{} }
func (*applicationBindingTestBase) CapabilitySummary(context.Context) (modulecapability.ModuleSummary, error) {
	return modulecapability.ModuleSummary{}, nil
}
func (*applicationBindingTestBase) CapabilityCategory(context.Context, string) (modulecapability.CategoryDocument, error) {
	return modulecapability.CategoryDocument{}, nil
}
func (*applicationBindingTestBase) ValidateCapabilityCandidate(context.Context, modulecapability.ValidationRequest) (modulecapability.ValidationResult, error) {
	return modulecapability.ValidationResult{}, nil
}
func (*applicationBindingTestBase) Authentication() identity.Authentication    { return nil }
func (*applicationBindingTestBase) Tokens() identity.TokenVerifier             { return nil }
func (*applicationBindingTestBase) Authorization() identity.Authorization      { return nil }
func (*applicationBindingTestBase) Principals() identity.PrincipalResolver     { return nil }
func (*applicationBindingTestBase) Projection() identity.Projection            { return nil }
func (*applicationBindingTestBase) Applications() identity.ApplicationRegistry { return nil }
func (*applicationBindingTestBase) Permissions() identity.PermissionRegistry   { return nil }
func (*applicationBindingTestBase) Credentials() identity.CredentialManager    { return nil }
func (*applicationBindingTestBase) Close(context.Context) error                { return nil }

type applicationVerifierTestStub struct {
	request identity.VerifyApplicationServiceTokenRequest
}

func (stub *applicationVerifierTestStub) Verify(_ context.Context, request identity.VerifyApplicationServiceTokenRequest) (identity.ApplicationServicePrincipal, error) {
	stub.request = request
	return identity.ApplicationServicePrincipal{Audience: request.Audience}, nil
}

type verifierOnlyBindingTestStub struct {
	*applicationBindingTestBase
	verifier identity.ApplicationServiceTokenVerifier
}

func (stub *verifierOnlyBindingTestStub) ApplicationServiceVerifier() identity.ApplicationServiceTokenVerifier {
	return stub.verifier
}

type applicationServicesTestStub struct {
	applicationVerifierTestStub
	exchangeRequest identity.ExchangeApplicationServiceTokenRequest
}

func (stub *applicationServicesTestStub) Exchange(_ context.Context, request identity.ExchangeApplicationServiceTokenRequest) (identity.ApplicationServiceToken, error) {
	stub.exchangeRequest = request
	return identity.ApplicationServiceToken{Application: request.Application, Audience: request.Audience}, nil
}

type fullServiceBindingTestStub struct {
	*applicationBindingTestBase
	services identity.ApplicationServiceAuthentication
}

func (stub *fullServiceBindingTestStub) ApplicationServices() identity.ApplicationServiceAuthentication {
	return stub.services
}

func TestBindPreservesVerifierOnlyCapabilityWithoutAdvertisingExchange(t *testing.T) {
	verifier := &applicationVerifierTestStub{}
	scoped, err := Bind(&verifierOnlyBindingTestStub{applicationBindingTestBase: &applicationBindingTestBase{}, verifier: verifier}, identity.ApplicationRef{
		WorkspaceID: "workspace-a", ApplicationKey: "runtime-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, advertised := scoped.(identity.ApplicationServiceBinding); advertised {
		t.Fatal("verifier-only delegate advertised application service token exchange")
	}
	capability, ok := scoped.(identity.ApplicationServiceVerificationBinding)
	if !ok || capability.ApplicationServiceVerifier() == nil {
		t.Fatal("verifier-only delegate lost application service verification")
	}
	principal, err := capability.ApplicationServiceVerifier().Verify(t.Context(), identity.VerifyApplicationServiceTokenRequest{AccessToken: "token", Grant: identity.ApplicationServiceGrant{Resource: "records", Action: "read"}})
	if err != nil {
		t.Fatal(err)
	}
	if verifier.request.Audience != "runtime-a" || principal.Audience != "runtime-a" {
		t.Fatalf("scoped verification request=%+v principal=%+v", verifier.request, principal)
	}
}

func TestBindPreservesFullServiceCapabilityAndExposesNarrowVerifier(t *testing.T) {
	services := &applicationServicesTestStub{}
	application := identity.ApplicationRef{TenantID: "tenant-a", WorkspaceID: "workspace-a", ApplicationKey: "runtime-a"}
	scoped, err := Bind(&fullServiceBindingTestStub{applicationBindingTestBase: &applicationBindingTestBase{}, services: services}, application)
	if err != nil {
		t.Fatal(err)
	}
	full, fullOK := scoped.(identity.ApplicationServiceBinding)
	verifier, verifierOK := scoped.(identity.ApplicationServiceVerificationBinding)
	if !fullOK || full.ApplicationServices() == nil || !verifierOK || verifier.ApplicationServiceVerifier() == nil {
		t.Fatalf("full=%t verifier=%t", fullOK, verifierOK)
	}
	if _, err := full.ApplicationServices().Exchange(t.Context(), identity.ExchangeApplicationServiceTokenRequest{Audience: "identity"}); err != nil {
		t.Fatal(err)
	}
	if services.exchangeRequest.Application != application {
		t.Fatalf("exchange application=%+v want=%+v", services.exchangeRequest.Application, application)
	}
	if _, err := verifier.ApplicationServiceVerifier().Verify(t.Context(), identity.VerifyApplicationServiceTokenRequest{AccessToken: "token", Grant: identity.ApplicationServiceGrant{Resource: "records", Action: "read"}}); err != nil {
		t.Fatal(err)
	}
	if services.request.Audience != application.ApplicationKey {
		t.Fatalf("verification request=%+v", services.request)
	}
}

var _ identity.Binding = (*applicationBindingTestBase)(nil)
var _ identity.ApplicationServiceVerificationBinding = (*verifierOnlyBindingTestStub)(nil)
var _ identity.ApplicationServiceAuthentication = (*applicationServicesTestStub)(nil)
var _ identity.ApplicationServiceBinding = (*fullServiceBindingTestStub)(nil)
