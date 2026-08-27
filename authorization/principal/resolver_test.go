package principal_test

import (
	"context"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
	identityprincipal "github.com/domainry/domainry-identity-sdk/authorization/principal"
)

type resolverBinding struct {
	auth   *resolverAuthentication
	tokens resolverTokens
	author *resolverAuthorization
	clock  *resolverClock
}

func newResolverBinding() *resolverBinding {
	clock := &resolverClock{now: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)}
	return &resolverBinding{
		clock:  clock,
		tokens: resolverTokens{claims: identity.VerifiedToken{SubjectID: "user-1", WorkspaceID: "workspace-1", SessionID: "session-1", AuthorizationRevision: "revision-1", TokenID: "token-1", IssuedAt: clock.now.Add(-time.Minute).Unix(), ExpiresAt: clock.now.Add(time.Hour).Unix()}},
		auth:   &resolverAuthentication{session: identity.SessionView{WorkspaceID: "workspace-1", SubjectID: "user-1", AuthorizationRevision: "revision-1", User: identity.User{ID: "user-1"}, Roles: []identity.Role{{Key: "admin"}}, Permissions: []string{"workspace.admin"}}},
		author: &resolverAuthorization{bundle: identity.AccessBundle{ContractVersion: identity.PolicyBundleVersionV1, AuthorizationRevision: "revision-1", CatalogRevision: "catalog-1", ExpiresAt: clock.now.Add(5 * time.Minute), Subject: identity.Subject{WorkspaceID: "workspace-1", SubjectID: "user-1", DepartmentPath: "/company/sales", ReportingPath: "/manager/user-1"}, FunctionGrants: []identity.FunctionGrant{{Resource: "orders", Action: "read", Effect: identity.EffectAllow}}}},
	}
}

func (binding *resolverBinding) Descriptor() identity.Descriptor         { return identity.Descriptor{} }
func (binding *resolverBinding) Authentication() identity.Authentication { return binding.auth }
func (binding *resolverBinding) Tokens() identity.TokenVerifier          { return binding.tokens }
func (binding *resolverBinding) Authorization() identity.Authorization   { return binding.author }
func (*resolverBinding) Principals() identity.PrincipalResolver          { return nil }
func (*resolverBinding) Directory() identity.Directory                   { return nil }
func (*resolverBinding) Catalog() identity.CatalogClient                 { return nil }
func (*resolverBinding) Credentials() identity.CredentialManager         { return nil }
func (*resolverBinding) Close(context.Context) error                     { return nil }

type resolverClock struct{ now time.Time }

func (clock *resolverClock) Now() time.Time { return clock.now }

type resolverTokens struct{ claims identity.VerifiedToken }

func (tokens resolverTokens) Verify(context.Context, identity.VerifyTokenRequest) (identity.VerifiedToken, error) {
	return tokens.claims, nil
}

type resolverAuthentication struct {
	session identity.SessionView
	calls   int
}

func (*resolverAuthentication) Providers(context.Context, identity.ProviderQuery) ([]identity.Provider, error) {
	return nil, nil
}
func (*resolverAuthentication) LoginWithPassword(context.Context, identity.PasswordLoginRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, nil
}
func (*resolverAuthentication) BeginFederatedLogin(context.Context, identity.BeginFederatedLoginRequest) (identity.ProviderChallenge, error) {
	return identity.ProviderChallenge{}, nil
}
func (*resolverAuthentication) CompleteFederatedLogin(context.Context, identity.CompleteFederatedLoginRequest) (identity.FederatedLoginCompletion, error) {
	return identity.FederatedLoginCompletion{}, nil
}
func (*resolverAuthentication) ExchangeAuthorizationCode(context.Context, identity.ExchangeAuthorizationCodeRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, nil
}
func (*resolverAuthentication) VerifyOTP(context.Context, identity.VerifyOTPRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, nil
}
func (*resolverAuthentication) RefreshSession(context.Context, identity.RefreshRequest) (identity.AuthSession, error) {
	return identity.AuthSession{}, nil
}
func (*resolverAuthentication) LogoutSession(context.Context, identity.LogoutRequest) error {
	return nil
}
func (authentication *resolverAuthentication) CurrentSession(context.Context, identity.CurrentSessionRequest) (identity.SessionView, error) {
	authentication.calls++
	return authentication.session, nil
}

type resolverAuthorization struct {
	bundle identity.AccessBundle
	calls  int
}

func (authorization *resolverAuthorization) ResolveAccess(context.Context, identity.AccessBundleRequest) (identity.AccessBundle, error) {
	authorization.calls++
	return authorization.bundle, nil
}
func (*resolverAuthorization) Reauthorize(context.Context, identity.DecisionRequest) (identity.AccessDecision, error) {
	return identity.AccessDecision{}, nil
}

func TestResolverCachesByTokenAndAuthorizationRevision(t *testing.T) {
	binding := newResolverBinding()
	resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Clock: binding.clock, MaxCacheTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		resolved, resolveErr := resolver.Authenticate(t.Context(), "access")
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		if !resolved.Known || !resolved.HasPermission("workspace.admin") || !resolved.HasPermission("orders.read") || resolved.DepartmentPath != "/company/sales" || resolved.ReportingPath != "/manager/user-1" {
			t.Fatalf("principal=%#v", resolved)
		}
	}
	if binding.auth.calls != 1 || binding.author.calls != 1 {
		t.Fatalf("session calls=%d bundle calls=%d", binding.auth.calls, binding.author.calls)
	}
	resolver.Invalidate("user-1", "workspace-1")
	if _, err := resolver.Authenticate(t.Context(), "access"); err != nil {
		t.Fatal(err)
	}
	if binding.auth.calls != 2 || binding.author.calls != 2 {
		t.Fatalf("invalidate did not evict: session=%d bundle=%d", binding.auth.calls, binding.author.calls)
	}
}

func TestResolverRejectsBundleSubjectMismatch(t *testing.T) {
	binding := newResolverBinding()
	binding.author.bundle.Subject.SubjectID = "other-user"
	resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Clock: binding.clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Authenticate(t.Context(), "access"); err == nil {
		t.Fatal("mismatched AccessBundle was accepted")
	}
}

func TestResolverAppliesFunctionDenyOverSessionPermissions(t *testing.T) {
	binding := newResolverBinding()
	binding.auth.session.Permissions = append(binding.auth.session.Permissions, "orders.read")
	binding.author.bundle.FunctionGrants = append(binding.author.bundle.FunctionGrants, identity.FunctionGrant{Resource: "orders", Action: "read", Effect: identity.EffectDeny})
	resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Clock: binding.clock})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.Authenticate(t.Context(), "access")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.HasPermission("orders.read") {
		t.Fatalf("function deny left permission in principal: %v", resolved.Permissions)
	}
}

func TestResolverCacheReturnsDeeplyIsolatedPolicySnapshots(t *testing.T) {
	binding := newResolverBinding()
	binding.author.bundle.Subject.OrganizationScopes = map[string][]string{"team_ids": {"team-a"}}
	binding.author.bundle.DataPolicies = []identity.DataPolicy{{
		Key: "team", Resource: "orders", Action: "read", Effect: identity.EffectAllow,
		Predicate: identity.Predicate{Fact: "team_id", Operator: identity.OperatorIn, Value: []any{"team-a", map[string]any{"nested": []any{"original"}}}},
	}}
	binding.author.bundle.ReferencePolicies = []identity.ReferencePolicy{{SourceResource: "orders", Reference: "customer", TargetResource: "customer", Allowed: true, DisplayFields: []string{"name"}}}
	binding.author.bundle.ExportPolicies = []identity.ExportPolicy{{Resource: "orders", Mode: identity.ExportModeAllowList, Fields: []string{"number"}}}
	binding.author.bundle.Guardrails = []identity.Guardrail{{Key: "guard", Resource: "orders", Action: "read", Effect: identity.EffectDeny, Predicate: &identity.Predicate{Fact: "blocked", Operator: identity.OperatorEqual, Value: map[string]any{"state": []any{"original"}}}}}

	resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Clock: binding.clock, MaxCacheTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	first, err := resolver.Authenticate(t.Context(), "access")
	if err != nil {
		t.Fatal(err)
	}
	first.AccessBundle.Subject.OrganizationScopes["team_ids"][0] = "mutated"
	first.AccessBundle.DataPolicies[0].Predicate.Value.([]any)[1].(map[string]any)["nested"].([]any)[0] = "mutated"
	first.AccessBundle.ReferencePolicies[0].DisplayFields[0] = "mutated"
	first.AccessBundle.ExportPolicies[0].Fields[0] = "mutated"
	first.AccessBundle.Guardrails[0].Predicate.Value.(map[string]any)["state"].([]any)[0] = "mutated"

	second, err := resolver.Authenticate(t.Context(), "access")
	if err != nil {
		t.Fatal(err)
	}
	if got := second.AccessBundle.Subject.OrganizationScopes["team_ids"][0]; got != "team-a" {
		t.Fatalf("organization scope cache was mutated: %q", got)
	}
	if got := second.AccessBundle.DataPolicies[0].Predicate.Value.([]any)[1].(map[string]any)["nested"].([]any)[0]; got != "original" {
		t.Fatalf("predicate cache was mutated: %v", got)
	}
	if got := second.AccessBundle.ReferencePolicies[0].DisplayFields[0]; got != "name" {
		t.Fatalf("reference policy cache was mutated: %q", got)
	}
	if got := second.AccessBundle.ExportPolicies[0].Fields[0]; got != "number" {
		t.Fatalf("export policy cache was mutated: %q", got)
	}
	if got := second.AccessBundle.Guardrails[0].Predicate.Value.(map[string]any)["state"].([]any)[0]; got != "original" {
		t.Fatalf("guardrail cache was mutated: %v", got)
	}
	if binding.auth.calls != 1 || binding.author.calls != 1 {
		t.Fatalf("expected cache hit: session=%d bundle=%d", binding.auth.calls, binding.author.calls)
	}
}

var _ identity.Binding = (*resolverBinding)(nil)
