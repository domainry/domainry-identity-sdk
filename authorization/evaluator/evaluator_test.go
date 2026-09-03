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
		ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: "authz-1", ExpiresAt: now.Add(time.Minute),
		Subject:           identity.Subject{WorkspaceID: "workspace-a", SubjectID: "user-1", OrgID: "department-a"},
		FunctionGrants:    []identity.FunctionGrant{{Resource: "invoice", Action: "read", Effect: identity.EffectAllow}},
		DataPolicies:      []identity.DataPolicy{{Key: "same-department", Resource: "invoice", Action: "read", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "org_id", Operator: identity.OperatorEqual, Value: "$subject.org_id"}}},
		FieldPolicies:     []identity.FieldPolicy{{Resource: "invoice", Field: "number", Read: true, Export: true}, {Resource: "invoice", Field: "amount", Read: true, Write: true}},
		ReferencePolicies: []identity.ReferencePolicy{{SourceResource: "invoice", Reference: "customer", TargetResource: "customer", Allowed: true, DisplayFields: []string{"name"}}},
		ExportPolicies:    []identity.ExportPolicy{{Resource: "invoice", Mode: "allow_list", Fields: []string{"number"}}},
	}
	decision, err := Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read"}, identity.ResourceFacts{"org_id": "department-a"}, now)
	if err != nil || !decision.Allowed {
		t.Fatalf("allowed decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read"}, identity.ResourceFacts{"org_id": "department-b"}, now)
	if err != nil || decision.Allowed || decision.Code != "data_policy_not_granted" {
		t.Fatalf("denied decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read", FieldKey: "amount"}, identity.ResourceFacts{"org_id": "department-a"}, now)
	if err != nil || !decision.Allowed {
		t.Fatalf("readable field decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read", FieldKey: "secret"}, identity.ResourceFacts{"org_id": "department-a"}, now)
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
	bundle := identity.AccessBundle{ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute), Subject: identity.Subject{WorkspaceID: "workspace", SubjectID: "subject"}, FunctionGrants: []identity.FunctionGrant{{Resource: "invoice", Action: "read", Effect: identity.EffectAllow}}, DataPolicies: []identity.DataPolicy{{Key: "unsupported", Resource: "invoice", Action: "read", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "owner_id", Operator: "regex", Value: ".*"}}}}
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
		ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
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

func TestAllDataScopeCompilesWithoutARecordWhereClause(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
		Subject:        identity.Subject{WorkspaceID: "workspace", SubjectID: "subject"},
		FunctionGrants: []identity.FunctionGrant{{Resource: "invoice", Action: "read", Effect: identity.EffectAllow}},
		DataPolicies: []identity.DataPolicy{{
			Key: "invoice-read-all", Resource: "invoice", Action: "read", Effect: identity.EffectAllow,
			DataScopes: []identity.DataScope{identity.DataScopeAll},
		}},
	}

	filter, err := CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil || !filter.Unrestricted {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
	compiled, err := CompileSQL(filter, bundle.Subject, func(string) (string, bool) { return "", false })
	if err != nil || compiled.Clause != "" || len(compiled.Args) != 0 {
		t.Fatalf("all compiled an additional record predicate: filter=%+v err=%v", compiled, err)
	}

	bundle.DataPolicies = append(bundle.DataPolicies, identity.DataPolicy{
		Key: "invoice-read-deny-owner", Resource: "invoice", Action: "read", Effect: identity.EffectDeny,
		DataScopes: []identity.DataScope{identity.DataScopeOwner},
		Predicate:  identity.Predicate{Fact: "owner_user_id", Operator: identity.OperatorEqual, Value: "$subject.id"},
	})
	filter, err = CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil || !filter.Unrestricted {
		t.Fatalf("all plus deny filter=%+v err=%v", filter, err)
	}
	compiled, err = CompileSQL(filter, bundle.Subject, func(fact string) (string, bool) {
		return `"` + fact + `"`, fact == "owner_user_id"
	})
	if err != nil || compiled.Clause != `NOT ("owner_user_id" = ?)` || !reflect.DeepEqual(compiled.Args, []any{"subject"}) {
		t.Fatalf("all plus deny compiled=%+v err=%v", compiled, err)
	}
}

func TestEvaluatorAppliesExactBundleEntriesWithoutWeakeningExplicitDenies(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
		Subject:        identity.Subject{WorkspaceID: "workspace", SubjectID: "subject"},
		FunctionGrants: []identity.FunctionGrant{{Resource: "invoice", Action: "read", Effect: identity.EffectAllow}, {Resource: "invoice", Action: "delete", Effect: identity.EffectDeny}},
		DataPolicies:   []identity.DataPolicy{{Key: "invoice-read", Resource: "invoice", Action: "read", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "id", Operator: identity.OperatorExists, Value: true}}},
		FieldPolicies:  []identity.FieldPolicy{{Resource: "*", Field: "*", Read: true, Write: true, Export: true}, {Resource: "invoice", Field: "secret", Read: false}},
	}
	decision, err := Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read", FieldKey: "number"}, identity.ResourceFacts{"id": "invoice-1"}, now)
	if err != nil || !decision.Allowed {
		t.Fatalf("wildcard read decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "read", FieldKey: "secret"}, identity.ResourceFacts{"id": "invoice-1"}, now)
	if err != nil || decision.Allowed || decision.Code != "field_not_granted" {
		t.Fatalf("exact field restriction decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(bundle, identity.AccessRequest{ObjectKey: "invoice", Action: "delete"}, identity.ResourceFacts{"id": "invoice-1"}, now)
	if err != nil || decision.Allowed || decision.Code != "function_denied" {
		t.Fatalf("exact function deny decision=%+v err=%v", decision, err)
	}
	filter, err := CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil || len(filter.Allow) != 1 {
		t.Fatalf("wildcard filter=%+v err=%v", filter, err)
	}
}

func TestAllowedReferencesMergesFieldsAndAppliesFieldGuardrail(t *testing.T) {
	bundle := identity.AccessBundle{ReferencePolicies: []identity.ReferencePolicy{
		{SourceResource: "order", Reference: "customer", TargetResource: "account", Allowed: true, DisplayFields: []string{"name"}, Reason: "first"},
		{SourceResource: "order", Reference: "customer", TargetResource: "account", Allowed: true, DisplayFields: []string{"code", "name"}},
	}}
	references := AllowedReferences(bundle, "order")
	if len(references) != 1 || !reflect.DeepEqual(references[0].DisplayFields, []string{"name", "code"}) || references[0].Reason != "first" {
		t.Fatalf("merged references=%+v", references)
	}
	bundle.Guardrails = []identity.Guardrail{{Key: "hide-customer", Resource: "order", Action: "read", Field: "customer", Effect: identity.EffectDeny}}
	if references = AllowedReferences(bundle, "order"); len(references) != 0 {
		t.Fatalf("guarded references=%+v", references)
	}
}

func TestRecordFilterRequiresCurrentFunctionGrantAndAppliesGuardrails(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
		Subject:      identity.Subject{WorkspaceID: "workspace", SubjectID: "subject", OrgScopeIDs: []string{"sales", "sales-east"}},
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
	bundle.Guardrails = []identity.Guardrail{{Key: "organization-block", Resource: "invoice", Action: "read", Effect: identity.EffectDeny, Predicate: &identity.Predicate{Fact: "owner_org_id", Operator: identity.OperatorIn, Value: "$subject.org_scope_ids"}}}
	filter, err = CompileRecordFilter(bundle, "invoice", "read", now)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err = CompileSQL(filter, bundle.Subject, func(fact string) (string, bool) {
		switch fact {
		case "id":
			return `"id"`, true
		case "owner_org_id":
			return `"owner_org_id"`, true
		default:
			return "", false
		}
	})
	if err != nil || compiled.Clause != `("id" IS NOT NULL) AND NOT ("owner_org_id" IN (?,?))` || !reflect.DeepEqual(compiled.Args, []any{"sales", "sales-east"}) {
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

func TestWriteDataPolicyAuthorizesExactMutationOperationsOnlyAfterFunctionGrant(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
		Subject: identity.Subject{WorkspaceID: "workspace", SubjectID: "wechat-user"},
		FunctionGrants: []identity.FunctionGrant{
			{Resource: "course_favorite", Action: "create", Effect: identity.EffectAllow},
			{Resource: "member", Action: "self_enroll", Effect: identity.EffectAllow},
		},
		DataPolicies: []identity.DataPolicy{
			{Key: "favorite-owner", Resource: "course_favorite", Action: "create", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "identity_user_id", Operator: identity.OperatorEqual, Value: "$subject.id"}},
			{Key: "member-owner", Resource: "member", Action: "self_enroll", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "identity_user_id", Operator: identity.OperatorEqual, Value: "$subject.id"}},
		},
	}

	for _, request := range []identity.AccessRequest{
		{ObjectKey: "course_favorite", Action: "create"},
		{ObjectKey: "member", Action: "self_enroll"},
	} {
		decision, err := Evaluate(bundle, request, identity.ResourceFacts{"identity_user_id": "wechat-user"}, now)
		if err != nil || !decision.Allowed {
			t.Fatalf("request=%+v decision=%+v err=%v", request, decision, err)
		}
		filter, err := CompileRecordFilter(bundle, identity.ResourceType(request.ObjectKey), identity.Action(request.Action), now)
		if err != nil || len(filter.Allow) != 1 {
			t.Fatalf("request=%+v filter=%+v err=%v", request, filter, err)
		}
	}

	withoutExactFunction := bundle
	withoutExactFunction.FunctionGrants = []identity.FunctionGrant{{Resource: "course_favorite", Action: "read", Effect: identity.EffectAllow}}
	decision, err := Evaluate(withoutExactFunction, identity.AccessRequest{ObjectKey: "course_favorite", Action: "create"}, identity.ResourceFacts{"identity_user_id": "wechat-user"}, now)
	if err != nil || decision.Allowed || decision.Code != "function_not_granted" {
		t.Fatalf("write data policy widened function authority: decision=%+v err=%v", decision, err)
	}

	readRequest := bundle
	readRequest.FunctionGrants = []identity.FunctionGrant{{Resource: "course_favorite", Action: "read", Effect: identity.EffectAllow}}
	decision, err = Evaluate(readRequest, identity.AccessRequest{ObjectKey: "course_favorite", Action: "read"}, identity.ResourceFacts{"identity_user_id": "wechat-user"}, now)
	if err != nil || decision.Allowed || decision.Code != "data_policy_not_granted" {
		t.Fatalf("write data policy authorized read: decision=%+v err=%v", decision, err)
	}
}

func TestWriteDataPolicyCarriesAuditDenialAcrossMutationActions(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: "authz", ExpiresAt: now.Add(time.Minute),
		Subject:      identity.Subject{WorkspaceID: "workspace", SubjectID: "subject"},
		DataPolicies: []identity.DataPolicy{{Key: "owned-create", Resource: "favorite", Action: "create", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "owner_id", Operator: identity.OperatorEqual, Value: "$subject.id"}, AuditDenial: true}},
	}
	required, err := AuditDenialRequired(bundle, "favorite", "create", now)
	if err != nil || !required {
		t.Fatalf("create required=%v err=%v", required, err)
	}
	required, err = AuditDenialRequired(bundle, "favorite", "update", now)
	if err != nil || required {
		t.Fatalf("create audit policy leaked to update: required=%v err=%v", required, err)
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

func TestEvaluatorResolvesOrganizationTreeIDs(t *testing.T) {
	subject := identity.Subject{OrgScopeIDs: []string{"sales", "sales-east"}}
	matched, err := EvaluatePredicate(identity.Predicate{Fact: "owner_org_id", Operator: identity.OperatorIn, Value: "$subject.org_scope_ids"}, identity.ResourceFacts{"owner_org_id": "sales-east"}, subject)
	if err != nil || !matched {
		t.Fatalf("organization match=%v err=%v", matched, err)
	}
}

func TestEvaluatorResolvesSupportOrganizationTreeIDs(t *testing.T) {
	subject := identity.Subject{SupportOrgID: "sales", SupportOrgScopeIDs: []string{"sales", "sales-east"}}
	matched, err := EvaluatePredicate(identity.Predicate{Fact: "owner_org_id", Operator: identity.OperatorIn, Value: "$subject.support_org_scope_ids"}, identity.ResourceFacts{"owner_org_id": "sales-east"}, subject)
	if err != nil || !matched {
		t.Fatalf("support organization match=%v err=%v", matched, err)
	}
}

func TestContextualFieldEvaluatorOwnsPriorityMaskAndGuardrailSemantics(t *testing.T) {
	predicate := identity.Predicate{Fact: "owner_id", Operator: identity.OperatorEqual, Value: "$subject.id"}
	bundle := identity.AccessBundle{
		FieldPolicies: []identity.FieldPolicy{{
			Resource: "member", Field: "phone", Read: true, Masked: true, Reason: "personal data",
			Rules: []identity.FieldRule{
				{Key: "fallback-hide", Priority: 10, Actions: []identity.Action{"read"}, Effect: identity.FieldEffectHide, AuditDenial: true},
				{Key: "owner-clear", Priority: 100, Actions: []identity.Action{"read"}, Effect: identity.FieldEffectAllow, Predicate: &predicate},
			},
		}},
	}
	decision, err := EvaluateField(bundle, FieldRequest{Resource: "member", Field: "phone", Action: "read"}, func(value identity.Predicate) (bool, error) {
		return value.Fact == "owner_id", nil
	})
	if err != nil || decision.Effect != identity.FieldEffectAllow || decision.RuleKey != "owner-clear" {
		t.Fatalf("owner decision=%+v err=%v", decision, err)
	}
	decision, err = EvaluateField(bundle, FieldRequest{Resource: "member", Field: "phone", Action: "read"}, func(identity.Predicate) (bool, error) { return false, nil })
	if err != nil || decision.Effect != identity.FieldEffectHide || decision.RuleKey != "fallback-hide" || !decision.AuditDenial {
		t.Fatalf("fallback decision=%+v err=%v", decision, err)
	}
	bundle.Guardrails = []identity.Guardrail{{Key: "deny-phone", Resource: "member", Action: "read", Field: "phone", Effect: identity.EffectDeny, Reason: "legal hold"}}
	decision, err = EvaluateField(bundle, FieldRequest{Resource: "member", Field: "phone", Action: "read"}, nil)
	if err != nil || decision.Effect != identity.FieldEffectHide || decision.RuleKey != "deny-phone" || decision.Reason != "legal hold" {
		t.Fatalf("guardrail decision=%+v err=%v", decision, err)
	}
}

func TestFieldRequiresPolicyEvaluationIdentifiesRulesAndGuardrails(t *testing.T) {
	bundle := identity.AccessBundle{
		FieldPolicies: []identity.FieldPolicy{
			{Resource: "invoice", Field: "number", Read: true},
			{Resource: "invoice", Field: "amount", Read: true, Rules: []identity.FieldRule{{Key: "owner-only", Actions: []identity.Action{"read"}, Effect: identity.FieldEffectAllow}}},
		},
		Guardrails: []identity.Guardrail{{Key: "hide-secret", Resource: "invoice", Field: "secret", Action: "read", Effect: identity.EffectDeny}},
	}
	if FieldRequiresPolicyEvaluation(bundle, FieldRequest{Resource: "invoice", Field: "number", Action: "read"}) {
		t.Fatal("static field envelope was treated as dynamic")
	}
	if !FieldRequiresPolicyEvaluation(bundle, FieldRequest{Resource: "invoice", Field: "amount", Action: "read"}) {
		t.Fatal("matching field rule was not detected")
	}
	if !FieldRequiresPolicyEvaluation(bundle, FieldRequest{Resource: "invoice", Field: "secret", Action: "read"}) {
		t.Fatal("matching field guardrail was not detected")
	}
	if FieldRequiresPolicyEvaluation(bundle, FieldRequest{Resource: "invoice", Field: "amount", Action: "export"}) {
		t.Fatal("rule for another action was treated as applicable")
	}
}

func TestEvaluatorResolvesBusinessClaimsAndRequiresRelationAdapter(t *testing.T) {
	context := EvaluationContext{Subject: identity.Subject{SubjectID: "user"}, BusinessClaims: map[string]any{"business_profile_id": "member-1"}}
	direct := identity.Predicate{Fact: "member_id", Operator: identity.OperatorEqual, Value: "$context.business_profile_id"}
	matched, err := EvaluatePredicateWithContext(direct, identity.ResourceFacts{"member_id": "member-1"}, context)
	if err != nil || !matched {
		t.Fatalf("application claim match=%v err=%v", matched, err)
	}
	missing, err := EvaluatePredicateWithContext(direct, identity.ResourceFacts{"member_id": "member-1"}, EvaluationContext{})
	if err != nil || missing {
		t.Fatalf("missing application claim match=%v err=%v", missing, err)
	}
	relation := direct
	relation.Path = []identity.RelationSegment{{Direction: identity.RelationForward, Reference: "account_id", TargetResource: "account"}}
	if _, err := EvaluatePredicateWithContext(relation, identity.ResourceFacts{"member_id": "member-1"}, context); err == nil {
		t.Fatal("relationship predicate bypassed the Runtime relation adapter")
	}
}

func TestAuditDenialRequiredMatchesResourceAndAction(t *testing.T) {
	now := time.Now().UTC()
	bundle := identity.AccessBundle{
		ContractVersion:       identity.CurrentPolicyBundleVersion,
		AuthorizationRevision: "authorization",
		ExpiresAt:             now.Add(time.Hour),
		Subject:               identity.Subject{WorkspaceID: "workspace", SubjectID: "user"},
		DataPolicies: []identity.DataPolicy{
			{Key: "order-read", Resource: "order", Action: "read", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "id", Operator: identity.OperatorExists, Value: true}},
			{Key: "order-update", Resource: "order", Action: "update", Effect: identity.EffectAllow, Predicate: identity.Predicate{Fact: "id", Operator: identity.OperatorExists, Value: true}, AuditDenial: true},
		},
	}
	if required, err := AuditDenialRequired(bundle, "order", "read", now); err != nil || required {
		t.Fatalf("read audit decision required=%v err=%v", required, err)
	}
	if required, err := AuditDenialRequired(bundle, "order", "update", now); err != nil || !required {
		t.Fatalf("update audit decision required=%v err=%v", required, err)
	}
}
