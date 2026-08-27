package evaluator

import (
	"reflect"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestEvaluatorEnforcesFunctionDataFieldReferenceAndExportPolicies(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion: identity.PolicyBundleVersionV1, CatalogRevision: "catalog-1", AuthorizationRevision: "authz-1", ExpiresAt: now.Add(time.Minute),
		Subject:           identity.Subject{WorkspaceID: "workspace-a", SubjectID: "user-1", DepartmentID: "department-a"},
		FunctionGrants:    []identity.FunctionGrant{{Resource: "invoice", Action: "read", Effect: identity.EffectAllow}},
		DataPolicies:      []identity.DataPolicy{{Key: "same-department", Resource: "invoice", Action: "read", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "department_id", Operator: identity.OperatorEqual, Value: "$subject.department_id"}}},
		FieldPolicies:     []identity.FieldPolicy{{Resource: "invoice", Field: "number", Read: true, Export: true}, {Resource: "invoice", Field: "amount", Read: true, Write: true}},
		ReferencePolicies: []identity.ReferencePolicy{{SourceResource: "invoice", Reference: "customer", TargetResource: "customer", Allowed: true, DisplayFields: []string{"name"}}},
		ExportPolicies:    []identity.ExportPolicy{{Resource: "invoice", Mode: "allow_list", Fields: []string{"number"}}},
	}
	decision, err := Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read"}, identity.ResourceFacts{"department_id": "department-a"}, now)
	if err != nil || !decision.Allowed {
		t.Fatalf("allowed decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read"}, identity.ResourceFacts{"department_id": "department-b"}, now)
	if err != nil || decision.Allowed || decision.Code != "data_policy_not_granted" {
		t.Fatalf("denied decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read", FieldKey: "amount"}, identity.ResourceFacts{"department_id": "department-a"}, now)
	if err != nil || !decision.Allowed {
		t.Fatalf("readable field decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read", FieldKey: "secret"}, identity.ResourceFacts{"department_id": "department-a"}, now)
	if err != nil || decision.Allowed || decision.Code != "field_not_granted" {
		t.Fatalf("unknown field decision=%+v err=%v", decision, err)
	}
	if got := ReadableFields(bundle, "invoice"); !reflect.DeepEqual(got, []string{"amount", "number"}) {
		t.Fatalf("readable fields=%v", got)
	}
	if got := WritableFields(bundle, "invoice"); !reflect.DeepEqual(got, []string{"amount"}) {
		t.Fatalf("writable fields=%v", got)
	}
	if got := ExportableFields(bundle, "invoice"); !reflect.DeepEqual(got, []string{"number"}) {
		t.Fatalf("exportable fields=%v", got)
	}
	if got := AllowedReferences(bundle, "invoice"); len(got) != 1 || got[0].Reference != "customer" {
		t.Fatalf("references=%v", got)
	}
}

func TestEvaluatorAndSQLCompilerFailClosed(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{ContractVersion: identity.PolicyBundleVersionV1, CatalogRevision: "catalog", AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute), Subject: identity.Subject{WorkspaceID: "workspace", SubjectID: "subject"}, FunctionGrants: []identity.FunctionGrant{{Resource: "invoice", Action: "read", Effect: identity.EffectAllow}}, DataPolicies: []identity.DataPolicy{{Key: "unsupported", Resource: "invoice", Action: "read", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "owner_id", Operator: "regex", Value: ".*"}}}}
	if _, err := Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read"}, identity.ResourceFacts{"owner_id": "subject"}, now); err == nil {
		t.Fatal("unsupported operator did not fail closed")
	}
	bundle.DataPolicies[0].Predicate.Operator = identity.OperatorEqual
	bundle.DataPolicies[0].Predicate.Value = "$subject.id"
	filter, err := CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil {
		t.Fatal(err)
	}
	sqlFilter, err := CompileSQL(filter, bundle.Subject, func(fact string) (string, bool) {
		if fact == "owner_id" {
			return `"owner_id"`, true
		}
		return "", false
	})
	if err != nil || sqlFilter.Clause != `("owner_id" = ?)` || !reflect.DeepEqual(sqlFilter.Args, []any{"subject"}) {
		t.Fatalf("sql=%+v err=%v", sqlFilter, err)
	}
}

func TestFunctionGrantDoesNotInventRecordAccess(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion: identity.PolicyBundleVersionV1, CatalogRevision: "catalog", AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
		Subject:        identity.Subject{WorkspaceID: "workspace", SubjectID: "subject"},
		FunctionGrants: []identity.FunctionGrant{{Resource: "invoice", Action: "read", Effect: identity.EffectAllow}},
	}
	decision, err := Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read"}, identity.ResourceFacts{"id": "invoice-1"}, now)
	if err != nil || decision.Allowed || decision.Code != "data_policy_not_granted" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	filter, err := CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileSQL(filter, bundle.Subject, func(string) (string, bool) { return "", false })
	if err != nil || compiled.Clause != "0 = 1" || len(compiled.Args) != 0 {
		t.Fatalf("filter=%+v err=%v", compiled, err)
	}
}

func TestRecordFilterRequiresCurrentFunctionGrantAndAppliesGuardrails(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion: identity.PolicyBundleVersionV1, CatalogRevision: "catalog", AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
		Subject:      identity.Subject{WorkspaceID: "workspace", SubjectID: "subject", DepartmentPath: "/company/sales"},
		DataPolicies: []identity.DataPolicy{{Key: "all", Resource: "invoice", Action: "read", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "id", Operator: identity.OperatorExists, Value: true}}},
	}
	filter, err := CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileSQL(filter, bundle.Subject, func(string) (string, bool) { return `"id"`, true })
	if err != nil || compiled.Clause != "0 = 1" {
		t.Fatalf("missing function grant filter=%+v err=%v", compiled, err)
	}

	bundle.FunctionGrants = []identity.FunctionGrant{{Resource: "invoice", Action: "read", Effect: identity.EffectAllow}}
	bundle.Guardrails = []identity.Guardrail{{Key: "outside-department", Resource: "invoice", Action: "read", Effect: identity.EffectDeny, Predicate: &identity.Predicate{Fact: "department_path", Operator: identity.OperatorPrefix, Value: "$subject.department_path"}}}
	filter, err = CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err = CompileSQL(filter, bundle.Subject, func(fact string) (string, bool) {
		switch fact {
		case "id":
			return `"id"`, true
		case "department_path":
			return `"department_path"`, true
		default:
			return "", false
		}
	})
	if err != nil || compiled.Clause != `("id" IS NOT NULL) AND NOT ("department_path" LIKE ? ESCAPE '\')` || !reflect.DeepEqual(compiled.Args, []any{"/company/sales%"}) {
		t.Fatalf("guardrail filter=%+v err=%v", compiled, err)
	}

	bundle.FunctionGrants = append(bundle.FunctionGrants, identity.FunctionGrant{Resource: "invoice", Action: "read", Effect: identity.EffectDeny})
	filter, err = CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err = CompileSQL(filter, bundle.Subject, func(string) (string, bool) { return `"id"`, true })
	if err != nil || compiled.Clause != "0 = 1" {
		t.Fatalf("deny grant filter=%+v err=%v", compiled, err)
	}

	bundle.ExpiresAt = now.Add(-time.Second)
	if _, err := CompileRecordFilter(bundle, "invoice", "read", now); err == nil {
		t.Fatal("expired access bundle compiled into a record filter")
	}
}

func TestSQLPrefixEscapesWildcardInput(t *testing.T) {
	filter := RecordFilter{Allow: []identity.Predicate{{Fact: "path", Operator: identity.OperatorPrefix, Value: `sales%_\`}}}
	compiled, err := CompileSQL(filter, identity.Subject{}, func(string) (string, bool) { return `"path"`, true })
	if err != nil || compiled.Clause != `("path" LIKE ? ESCAPE '\')` || !reflect.DeepEqual(compiled.Args, []any{`sales\%\_\\%`}) {
		t.Fatalf("prefix filter=%+v err=%v", compiled, err)
	}
}

func TestFieldReferenceAndExportHelpersFailClosed(t *testing.T) {
	bundle := identity.AccessBundle{
		FieldPolicies: []identity.FieldPolicy{{Resource: "invoice", Field: "number", Read: true, Export: true}},
		ReferencePolicies: []identity.ReferencePolicy{
			{SourceResource: "invoice", Reference: "customer", TargetResource: "customer", Allowed: true},
			{SourceResource: "invoice", Reference: "customer", TargetResource: "customer", Allowed: false},
		},
		ExportPolicies: []identity.ExportPolicy{{Resource: "invoice", Mode: identity.ExportModeAllowList}},
	}
	if fields := ExportableFields(bundle, "invoice"); len(fields) != 0 {
		t.Fatalf("empty allow-list exported fields: %v", fields)
	}
	if references := AllowedReferences(bundle, "invoice"); len(references) != 0 {
		t.Fatalf("deny did not override reference grant: %v", references)
	}
	bundle.ExportPolicies[0].Mode = "unsupported"
	if fields := ExportableFields(bundle, "invoice"); len(fields) != 0 {
		t.Fatalf("unsupported export mode did not fail closed: %v", fields)
	}
}

func TestEvaluatorResolvesDepartmentTreeAndOrganizationScopes(t *testing.T) {
	subject := identity.Subject{DepartmentPath: "/company/sales", OrganizationScopes: map[string][]string{"team_ids": {"team-a", "team-b"}}}
	department, err := EvaluatePredicate(identity.Predicate{Fact: "department_path", Operator: identity.OperatorPrefix, Value: "$subject.department_path"}, identity.ResourceFacts{"department_path": "/company/sales/east"}, subject)
	if err != nil || !department {
		t.Fatalf("department match=%v err=%v", department, err)
	}
	team, err := EvaluatePredicate(identity.Predicate{Fact: "team_id", Operator: identity.OperatorIn, Value: "$subject.organization_scopes.team_ids"}, identity.ResourceFacts{"team_id": "team-b"}, subject)
	if err != nil || !team {
		t.Fatalf("team match=%v err=%v", team, err)
	}
}
