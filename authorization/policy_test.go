package authorization

import (
	"bytes"
	"testing"
	"time"
)

func TestAccessBundleCanonicalJSONIsOrderIndependent(t *testing.T) {
	now := time.Date(2026, 8, 27, 1, 0, 0, 0, time.UTC)
	first := AccessBundle{
		ContractVersion: CurrentPolicyBundleVersion, CatalogRevision: "catalog-1", AuthorizationRevision: "authz-1", ExpiresAt: now.Add(time.Hour),
		Subject:        Subject{WorkspaceID: "workspace-1", SubjectID: "user-1", ReportingSubjectIDs: []SubjectID{"user-3", "user-2"}, OrganizationScopes: map[string][]string{"team_ids": {"team-b", "team-a"}}},
		FunctionGrants: []FunctionGrant{{Resource: "order", Action: "update", Effect: EffectDeny}, {Resource: "order", Action: "read", Effect: EffectAllow}},
		DataPolicies: []DataPolicy{
			{Key: "team", Resource: "order", Action: "read", Effect: EffectAllow, Predicate: Predicate{Any: []Predicate{{Fact: "team_id", Operator: OperatorIn, Value: []string{"team-b", "team-a"}}, {Fact: "owner_id", Operator: OperatorEqual, Value: "$subject.id"}}}},
			{Key: "blocked", Resource: "order", Action: "read", Effect: EffectDeny, Predicate: Predicate{Fact: "status", Operator: OperatorEqual, Value: "blocked"}},
		},
		FieldPolicies:     []FieldPolicy{{Resource: "order", Field: "total", Read: true}, {Resource: "order", Field: "number", Read: true, Export: true}},
		ReferencePolicies: []ReferencePolicy{{SourceResource: "order", Reference: "customer", TargetResource: "customer", Allowed: true, DisplayFields: []string{"number", "name"}}},
		ExportPolicies:    []ExportPolicy{{Resource: "order", Mode: ExportModeAllowList, Fields: []string{"number", "id"}}},
		Guardrails:        []Guardrail{{Key: "locked", Resource: "order", Action: "update", Effect: EffectDeny, Predicate: &Predicate{All: []Predicate{{Fact: "locked", Operator: OperatorEqual, Value: true}, {Fact: "status", Operator: OperatorNotEqual, Value: "draft"}}}}},
	}
	second := first
	second.Subject.ReportingSubjectIDs = []SubjectID{"user-2", "user-3"}
	second.Subject.OrganizationScopes = map[string][]string{"team_ids": {"team-a", "team-b"}}
	second.FunctionGrants = []FunctionGrant{first.FunctionGrants[1], first.FunctionGrants[0]}
	second.DataPolicies = []DataPolicy{first.DataPolicies[1], first.DataPolicies[0]}
	second.DataPolicies[1].Predicate.Any = []Predicate{first.DataPolicies[0].Predicate.Any[1], {Fact: "team_id", Operator: OperatorIn, Value: []string{"team-a", "team-b"}}}
	second.FieldPolicies = []FieldPolicy{first.FieldPolicies[1], first.FieldPolicies[0]}
	second.ReferencePolicies = append([]ReferencePolicy(nil), first.ReferencePolicies...)
	second.ReferencePolicies[0].DisplayFields = []string{"name", "number"}
	second.ExportPolicies = append([]ExportPolicy(nil), first.ExportPolicies...)
	second.ExportPolicies[0].Fields = []string{"id", "number"}
	second.Guardrails = append([]Guardrail(nil), first.Guardrails...)
	secondGuardrail := *first.Guardrails[0].Predicate
	secondGuardrail.All = []Predicate{first.Guardrails[0].Predicate.All[1], first.Guardrails[0].Predicate.All[0]}
	second.Guardrails[0].Predicate = &secondGuardrail

	firstJSON, err := first.CanonicalJSON(now)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.CanonicalJSON(now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("canonical bundles differ:\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestAccessBundleRejectsAmbiguousEffectivePolicies(t *testing.T) {
	now := time.Now().UTC()
	base := AccessBundle{ContractVersion: CurrentPolicyBundleVersion, CatalogRevision: "catalog", AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute), Subject: Subject{WorkspaceID: "workspace", SubjectID: "user"}}
	duplicateFunction := base
	duplicateFunction.FunctionGrants = []FunctionGrant{{Resource: "order", Action: "read", Effect: EffectAllow}, {Resource: "order", Action: "read", Effect: EffectAllow}}
	if err := duplicateFunction.Validate(now); err == nil {
		t.Fatal("duplicate function grant accepted")
	}
	duplicateData := base
	duplicateData.DataPolicies = []DataPolicy{
		{Key: "same", Resource: "order", Action: "read", Effect: EffectAllow, Predicate: Predicate{Fact: "id", Operator: OperatorExists, Value: true}},
		{Key: "same", Resource: "order", Action: "read", Effect: EffectDeny, Predicate: Predicate{Fact: "id", Operator: OperatorExists, Value: true}},
	}
	if err := duplicateData.Validate(now); err == nil {
		t.Fatal("duplicate data policy key accepted")
	}
	ambiguousGuardrail := base
	ambiguousGuardrail.Guardrails = []Guardrail{{Key: "ambiguous", Action: "read", Effect: EffectDeny}}
	if err := ambiguousGuardrail.Validate(now); err == nil {
		t.Fatal("resource-free action guardrail accepted")
	}
	ambiguousGuardrail.Guardrails = []Guardrail{{Key: "ambiguous", Effect: EffectDeny, Predicate: &Predicate{Fact: "status", Operator: OperatorEqual, Value: "blocked"}}}
	if err := ambiguousGuardrail.Validate(now); err == nil {
		t.Fatal("resource-free predicate guardrail accepted")
	}
}

func TestAccessBundleV2PreservesContextualAndRelationshipPolicy(t *testing.T) {
	now := time.Now().UTC()
	predicate := Predicate{
		Fact: "owner_id", Operator: OperatorEqual, Value: "$context.business_profile_id",
		Path: []RelationSegment{{Direction: RelationForward, Reference: "account_id", TargetResource: "account"}},
	}
	bundle := AccessBundle{
		ContractVersion: CurrentPolicyBundleVersion, CatalogRevision: "catalog", AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
		Subject:      Subject{WorkspaceID: "workspace", SubjectID: "user"},
		DataPolicies: []DataPolicy{{Key: "owned-account", Resource: "invoice", Action: "read", Effect: EffectAllow, Predicate: predicate, AuditDenial: true}},
		FieldPolicies: []FieldPolicy{{
			Resource: "invoice", Field: "phone", Read: true, Masked: true, Reason: "personal data",
			Rules: []FieldRule{{Key: "owner-clear", Priority: 100, Actions: []Action{"export", "read"}, Effect: FieldEffectAllow, Predicate: &predicate}},
		}},
		ReferencePolicies: []ReferencePolicy{{SourceResource: "invoice", Reference: "account_id", TargetResource: "account", Allowed: false, Reason: "restricted account"}},
		Guardrails:        []Guardrail{{Key: "deny-phone-export", Resource: "invoice", Action: "export", Field: "phone", Effect: EffectDeny, Reason: "export restricted"}},
	}
	first, err := bundle.CanonicalJSON(now)
	if err != nil {
		t.Fatal(err)
	}
	bundle.FieldPolicies[0].Rules[0].Actions = []Action{"read", "export"}
	second, err := bundle.CanonicalJSON(now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical V2 policies differ:\n%s\n%s", first, second)
	}
	legacy := bundle
	legacy.ContractVersion = PolicyBundleVersionV1
	if err := legacy.Validate(now); err == nil {
		t.Fatal("V1 bundle was accepted by the V2 evaluator")
	}
}
