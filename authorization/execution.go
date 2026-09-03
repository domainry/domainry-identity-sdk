package authorization

import (
	"strings"
	"time"
)

// ExecutionGrant is a narrowly scoped capability delegated to a trusted
// application operation after the caller has already been authorized to run
// that operation. It can add one function verb and write access to declared
// effect fields, but it never widens record predicates, exports, references,
// or guardrails.
type ExecutionGrant struct {
	Resource       ResourceType
	Action         Action
	Fields         []string
	SourceResource ResourceType
	SourceAction   Action
}

// DeriveExecutionAccess returns an isolated bundle for one trusted operation.
// An explicit function deny is authoritative and cannot be overridden.
func DeriveExecutionAccess(bundle AccessBundle, grant ExecutionGrant, now time.Time) (AccessBundle, error) {
	if err := bundle.Validate(now); err != nil {
		return AccessBundle{}, err
	}
	if !grant.Resource.Valid() || !grant.Action.Valid() {
		return AccessBundle{}, &Error{Code: "identity.execution_grant_invalid"}
	}
	sourceSpecified := grant.SourceResource != "" || grant.SourceAction != ""
	if sourceSpecified && (!grant.SourceResource.Valid() || !grant.SourceAction.Valid()) {
		return AccessBundle{}, &Error{Code: "identity.execution_source_invalid"}
	}

	derived := cloneAccessBundle(bundle)
	if sourceSpecified {
		sourceAllowed := false
		for _, existing := range derived.FunctionGrants {
			if existing.Resource != grant.SourceResource || existing.Action != grant.SourceAction {
				continue
			}
			if existing.Effect == EffectDeny {
				return AccessBundle{}, &Error{Code: "identity.execution_source_denied"}
			}
			sourceAllowed = sourceAllowed || existing.Effect == EffectAllow
		}
		if !sourceAllowed {
			return AccessBundle{}, &Error{Code: "identity.execution_source_not_granted"}
		}
	}
	functionAllowed := false
	for _, existing := range derived.FunctionGrants {
		if existing.Resource != grant.Resource || existing.Action != grant.Action {
			continue
		}
		if existing.Effect == EffectDeny {
			return AccessBundle{}, &Error{Code: "identity.execution_grant_denied"}
		}
		functionAllowed = functionAllowed || existing.Effect == EffectAllow
	}
	if !functionAllowed {
		derived.FunctionGrants = append(derived.FunctionGrants, FunctionGrant{Resource: grant.Resource, Action: grant.Action, Effect: EffectAllow})
	}
	if sourceSpecified && (grant.SourceResource != grant.Resource || grant.SourceAction != grant.Action) {
		derived.DataPolicies = deriveExecutionDataPolicies(bundle.DataPolicies, grant)
	}

	seenFields := map[string]struct{}{}
	for _, rawField := range grant.Fields {
		field := strings.TrimSpace(rawField)
		if field == "" {
			continue
		}
		if _, duplicate := seenFields[field]; duplicate {
			continue
		}
		seenFields[field] = struct{}{}
		found := false
		for index := range derived.FieldPolicies {
			policy := &derived.FieldPolicies[index]
			if policy.Resource == grant.Resource && strings.TrimSpace(policy.Field) == field {
				policy.Write = true
				found = true
				break
			}
		}
		if !found {
			derived.FieldPolicies = append(derived.FieldPolicies, FieldPolicy{Resource: grant.Resource, Field: field, Write: true})
		}
	}
	if err := derived.Validate(now); err != nil {
		return AccessBundle{}, err
	}
	return derived, nil
}

// deriveExecutionDataPolicies projects only the already-authorized source
// operation's predicates onto one compiler-declared internal effect. Existing
// target allows are removed so broader CRUD authority cannot widen the source
// Action's scope; explicit target denies remain authoritative.
func deriveExecutionDataPolicies(policies []DataPolicy, grant ExecutionGrant) []DataPolicy {
	result := make([]DataPolicy, 0, len(policies)*2)
	keys := map[string]struct{}{}
	appendPolicy := func(policy DataPolicy) {
		if _, duplicate := keys[policy.Key]; duplicate {
			return
		}
		keys[policy.Key] = struct{}{}
		result = append(result, policy)
	}
	for _, policy := range policies {
		if policy.Resource == grant.Resource && policy.Action == grant.Action && policy.Effect == EffectAllow {
			continue
		}
		appendPolicy(policy)
	}
	for _, policy := range policies {
		if policy.Resource != grant.SourceResource || policy.Action != grant.SourceAction {
			continue
		}
		projected := policy
		projected.Key = policy.Key + ".execution." + string(grant.Resource) + "." + string(grant.Action)
		projected.Resource = grant.Resource
		projected.Action = grant.Action
		projected.Predicate = clonePredicate(policy.Predicate)
		appendPolicy(projected)
	}
	return result
}

func cloneAccessBundle(bundle AccessBundle) AccessBundle {
	clone := bundle
	clone.Subject.OrgScopeIDs = append([]string(nil), bundle.Subject.OrgScopeIDs...)
	clone.Subject.ReportingScopeUserIDs = append([]SubjectID(nil), bundle.Subject.ReportingScopeUserIDs...)
	clone.FunctionGrants = append([]FunctionGrant(nil), bundle.FunctionGrants...)
	clone.DataPolicies = append([]DataPolicy(nil), bundle.DataPolicies...)
	for index := range clone.DataPolicies {
		clone.DataPolicies[index].Predicate = clonePredicate(clone.DataPolicies[index].Predicate)
	}
	clone.FieldPolicies = append([]FieldPolicy(nil), bundle.FieldPolicies...)
	for index := range clone.FieldPolicies {
		clone.FieldPolicies[index] = cloneFieldPolicy(clone.FieldPolicies[index])
	}
	clone.ReferencePolicies = append([]ReferencePolicy(nil), bundle.ReferencePolicies...)
	for index := range clone.ReferencePolicies {
		clone.ReferencePolicies[index].DisplayFields = append([]string(nil), clone.ReferencePolicies[index].DisplayFields...)
	}
	clone.ExportPolicies = append([]ExportPolicy(nil), bundle.ExportPolicies...)
	for index := range clone.ExportPolicies {
		clone.ExportPolicies[index].Fields = append([]string(nil), clone.ExportPolicies[index].Fields...)
	}
	clone.Guardrails = append([]Guardrail(nil), bundle.Guardrails...)
	for index := range clone.Guardrails {
		if clone.Guardrails[index].Predicate != nil {
			predicate := clonePredicate(*clone.Guardrails[index].Predicate)
			clone.Guardrails[index].Predicate = &predicate
		}
	}
	return clone
}

func cloneFieldPolicy(policy FieldPolicy) FieldPolicy {
	policy.Rules = append([]FieldRule(nil), policy.Rules...)
	for index := range policy.Rules {
		policy.Rules[index].Actions = append([]Action(nil), policy.Rules[index].Actions...)
		if policy.Rules[index].Predicate != nil {
			predicate := clonePredicate(*policy.Rules[index].Predicate)
			policy.Rules[index].Predicate = &predicate
		}
		if policy.Rules[index].MaskStrategy != nil {
			strategy := *policy.Rules[index].MaskStrategy
			policy.Rules[index].MaskStrategy = &strategy
		}
	}
	return policy
}

func clonePredicate(predicate Predicate) Predicate {
	predicate.Path = append([]RelationSegment(nil), predicate.Path...)
	predicate.All = append([]Predicate(nil), predicate.All...)
	for index := range predicate.All {
		predicate.All[index] = clonePredicate(predicate.All[index])
	}
	predicate.Any = append([]Predicate(nil), predicate.Any...)
	for index := range predicate.Any {
		predicate.Any[index] = clonePredicate(predicate.Any[index])
	}
	if predicate.Not != nil {
		nested := clonePredicate(*predicate.Not)
		predicate.Not = &nested
	}
	switch values := predicate.Value.(type) {
	case []string:
		predicate.Value = append([]string(nil), values...)
	case []any:
		predicate.Value = append([]any(nil), values...)
	}
	return predicate
}
