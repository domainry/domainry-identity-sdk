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
	}}
	principal := Principal{Permissions: []string{"order.delete", "legacy.only"}, AccessBundle: bundle}
	if !principal.HasPermission("order.read") || principal.HasPermission("order.delete") || principal.HasPermission("legacy.only") {
		t.Fatalf("access bundle was not authoritative: %#v", principal)
	}
}

func TestPrincipalPermissionSupportsExplicitGlobalWildcardGrant(t *testing.T) {
	principal := Principal{AccessBundle: &AccessBundle{FunctionGrants: []FunctionGrant{{Resource: "*", Action: "*", Effect: EffectAllow}}}}
	if !principal.HasPermission("customer.read") || !principal.HasPermission("platform.workflow.definition.read") {
		t.Fatalf("global wildcard did not match concrete permission: %#v", principal.AccessBundle.FunctionGrants)
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
