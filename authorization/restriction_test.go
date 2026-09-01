package authorization

import "testing"

func TestRestrictAccessIntersectsCredentialScopesAndPreservesDenies(t *testing.T) {
	bundle := AccessBundle{
		FunctionGrants: []FunctionGrant{
			{Resource: "customer", Action: "read", Effect: EffectAllow},
			{Resource: "customer", Action: "update", Effect: EffectAllow},
			{Resource: "invoice", Action: "read", Effect: EffectDeny},
		},
		DataPolicies: []DataPolicy{
			{Key: "customer-read", Resource: "customer", Action: "read", Effect: EffectAllow},
			{Key: "customer-write", Resource: "customer", Action: "write", Effect: EffectAllow},
		},
		FieldPolicies:     []FieldPolicy{{Resource: "customer", Field: "name", Read: true, Write: true, Export: true}},
		ReferencePolicies: []ReferencePolicy{{SourceResource: "customer", Reference: "owner", Allowed: true}},
		ExportPolicies:    []ExportPolicy{{Resource: "customer", Mode: ExportModeAllowList, Fields: []string{"name"}}},
		Guardrails:        []Guardrail{{Key: "global-deny", Effect: EffectDeny}},
	}
	derived := RestrictAccess(bundle, []string{"customer.read"})
	if len(derived.FunctionGrants) != 2 || len(derived.DataPolicies) != 2 || len(derived.FieldPolicies) != 1 {
		t.Fatalf("unexpected restricted bundle: %#v", derived)
	}
	if !derived.FieldPolicies[0].Read || derived.FieldPolicies[0].Write || derived.FieldPolicies[0].Export {
		t.Fatalf("field rights escaped scope intersection: %#v", derived.FieldPolicies[0])
	}
	if len(derived.ReferencePolicies) != 1 || len(derived.ExportPolicies) != 0 || len(derived.Guardrails) != 1 {
		t.Fatalf("related policies were not restricted correctly: %#v", derived)
	}
}
