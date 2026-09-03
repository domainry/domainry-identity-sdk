package authorization

import (
	"testing"
	"time"
)

func TestDeriveExecutionAccessAddsOnlyDeclaredExecutionCapability(t *testing.T) {
	now := time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)
	bundle := AccessBundle{
		ContractVersion: CurrentPolicyBundleVersion, AuthorizationRevision: "auth-1", ExpiresAt: now.Add(time.Hour),
		Subject:       Subject{WorkspaceID: "workspace", SubjectID: "user"},
		DataPolicies:  []DataPolicy{{Key: "owned", Resource: "customer", Action: "update", Effect: EffectAllow, Predicate: Predicate{Fact: "owner_id", Operator: OperatorEqual, Value: "$subject.id"}}},
		FieldPolicies: []FieldPolicy{{Resource: "customer", Field: "name", Read: true}},
	}
	derived, err := DeriveExecutionAccess(bundle, ExecutionGrant{Resource: "customer", Action: "update", Fields: []string{"name", "status"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(derived.FunctionGrants) != 1 || len(derived.DataPolicies) != 1 || len(derived.FieldPolicies) != 2 {
		t.Fatalf("unexpected derived bundle: %#v", derived)
	}
	if !derived.FieldPolicies[0].Write || bundle.FieldPolicies[0].Write {
		t.Fatalf("derivation must write-enable the clone only: source=%#v derived=%#v", bundle.FieldPolicies, derived.FieldPolicies)
	}
	if derived.FieldPolicies[1].Field != "status" || !derived.FieldPolicies[1].Write {
		t.Fatalf("missing declared effect field: %#v", derived.FieldPolicies)
	}
}

func TestDeriveExecutionAccessCannotOverrideFunctionDeny(t *testing.T) {
	now := time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)
	bundle := AccessBundle{
		ContractVersion: CurrentPolicyBundleVersion, AuthorizationRevision: "auth-1", ExpiresAt: now.Add(time.Hour),
		Subject:        Subject{WorkspaceID: "workspace", SubjectID: "user"},
		FunctionGrants: []FunctionGrant{{Resource: "customer", Action: "update", Effect: EffectDeny}},
	}
	if _, err := DeriveExecutionAccess(bundle, ExecutionGrant{Resource: "customer", Action: "update"}, now); err == nil {
		t.Fatal("explicit deny was overridden")
	}
}

func TestDeriveExecutionAccessProjectsOnlyExactSourceScope(t *testing.T) {
	now := time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)
	bundle := AccessBundle{
		ContractVersion: CurrentPolicyBundleVersion, AuthorizationRevision: "auth-1", ExpiresAt: now.Add(time.Hour),
		Subject: Subject{WorkspaceID: "workspace", SubjectID: "user"},
		FunctionGrants: []FunctionGrant{
			{Resource: "customer", Action: "activate", Effect: EffectAllow},
			{Resource: "customer", Action: "update", Effect: EffectAllow},
		},
		DataPolicies: []DataPolicy{
			{Key: "activation-owner", Resource: "customer", Action: "activate", Effect: EffectAllow, Predicate: Predicate{Fact: "owner_user_id", Operator: OperatorEqual, Value: "$subject.id"}},
			{Key: "direct-update-all", Resource: "customer", Action: "update", Effect: EffectAllow, Predicate: Predicate{Fact: "id", Operator: OperatorExists, Value: true}},
		},
	}
	derived, err := DeriveExecutionAccess(bundle, ExecutionGrant{
		Resource: "customer", Action: "update", SourceResource: "customer", SourceAction: "activate",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(derived.DataPolicies) != 2 || derived.DataPolicies[1].Action != "update" || derived.DataPolicies[1].Predicate.Fact != "owner_user_id" {
		t.Fatalf("derived policies=%#v", derived.DataPolicies)
	}
	if len(bundle.DataPolicies) != 2 || bundle.DataPolicies[1].Key != "direct-update-all" {
		t.Fatalf("source bundle mutated=%#v", bundle.DataPolicies)
	}
}

func TestDeriveExecutionAccessRejectsIncompleteOrUngrantedSource(t *testing.T) {
	now := time.Date(2026, 8, 27, 1, 2, 3, 0, time.UTC)
	bundle := AccessBundle{ContractVersion: CurrentPolicyBundleVersion, AuthorizationRevision: "auth-1", ExpiresAt: now.Add(time.Hour), Subject: Subject{WorkspaceID: "workspace", SubjectID: "user"}}
	if _, err := DeriveExecutionAccess(bundle, ExecutionGrant{Resource: "customer", Action: "update", SourceResource: "customer"}, now); err == nil {
		t.Fatal("incomplete execution source accepted")
	}
	if _, err := DeriveExecutionAccess(bundle, ExecutionGrant{Resource: "customer", Action: "update", SourceResource: "customer", SourceAction: "activate"}, now); err == nil {
		t.Fatal("ungranted execution source accepted")
	}
}
