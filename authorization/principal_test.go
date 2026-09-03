package authorization

import (
	"context"
	"reflect"
	"testing"
)

func TestPrincipalPermissionAndContextStorage(t *testing.T) {
	principal := Principal{Known: true, UserID: "user-1", Permissions: []string{" order.read ", "ORDER.WRITE"}}
	if principal.HasPermission("order.read") || principal.HasPermission("order.write") {
		t.Fatalf("presentation permissions authorized a principal without an access bundle: %#v", principal.Permissions)
	}
	identity := RequestIdentity{Principal: principal, AccessToken: "secret-token"}
	ctx := WithRequestIdentity(context.Background(), identity)
	resolved, ok := RequestIdentityFromContext(ctx)
	if !ok || resolved.Principal.UserID != "user-1" || resolved.AccessToken != "secret-token" {
		t.Fatalf("request identity = %#v ok=%v", resolved, ok)
	}
	resolvedPrincipal, ok := PrincipalFromContext(ctx)
	if !ok || resolvedPrincipal.UserID != "user-1" {
		t.Fatalf("principal = %#v ok=%v", resolvedPrincipal, ok)
	}
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("empty context unexpectedly has a principal")
	}
}

func TestPrincipalPermissionUsesAccessBundleAsAuthoritativeState(t *testing.T) {
	bundle := &AccessBundle{FunctionGrants: []FunctionGrant{
		{Resource: "order", Action: "read", Effect: EffectAllow},
		{Resource: "order", Action: "delete", Effect: EffectDeny},
	}, DataPolicies: []DataPolicy{{Key: "order.read", Resource: "order", Action: "read", Effect: EffectAllow, DataScopes: []DataScope{DataScopeAll}}}}
	principal := Principal{Permissions: []string{"order.delete", "legacy.only"}, AccessBundle: bundle}
	if !principal.HasPermission("order.read") || principal.HasPermission("order.delete") || principal.HasPermission("legacy.only") {
		t.Fatalf("access bundle was not authoritative: %#v", principal)
	}
}

func TestPrincipalPermissionRequiresSameExactDataPolicy(t *testing.T) {
	principal := Principal{AccessBundle: &AccessBundle{
		FunctionGrants: []FunctionGrant{{Resource: "order", Action: "read", Effect: EffectAllow}, {Resource: "order", Action: "update", Effect: EffectAllow}},
		DataPolicies:   []DataPolicy{{Key: "order.read", Resource: "order", Action: "read", Effect: EffectAllow, DataScopes: []DataScope{DataScopeAll}}},
	}}
	if !principal.HasPermission("order.read") {
		t.Fatal("exact function and data grant was denied")
	}
	if principal.HasPermission("order.update") {
		t.Fatal("function-only grant bypassed the required per-Permission data scope")
	}
	principal.AccessBundle.Guardrails = []Guardrail{{Key: "deny-read", Resource: "order", Action: "read", Effect: EffectDeny}}
	if principal.HasPermission("order.read") {
		t.Fatal("unconditional guardrail did not deny the exact scoped Permission")
	}
}

func TestPrincipalPermissionRejectsWildcardAuthority(t *testing.T) {
	principal := Principal{AccessBundle: &AccessBundle{FunctionGrants: []FunctionGrant{{Resource: "*", Action: "*", Effect: EffectAllow}}}}
	if principal.HasPermission("customer.read") || principal.HasPermission("platform.workflow.definition.read") {
		t.Fatalf("wildcard grant authorized a concrete permission: %#v", principal.AccessBundle.FunctionGrants)
	}
}

func TestPrincipalExcludesRuntimeInvocationState(t *testing.T) {
	principal := reflect.TypeFor[Principal]()
	for _, forbidden := range []string{
		"RequestID", "CorrelationID", "CausationID", "AutomationDepth",
		"VisitedRuleKeys", "SurfaceKey", "BusinessProfiles", "RequestContexts",
	} {
		if _, found := principal.FieldByName(forbidden); found {
			t.Fatalf("runtime invocation field %q leaked into Identity Principal", forbidden)
		}
	}
}
