package evaluator

import (
	"sort"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk/authorization"
)

type FieldRequest struct {
	Resource identity.ResourceType
	Field    string
	Action   identity.Action
}

type FieldDecision struct {
	Effect       identity.FieldEffect
	RuleKey      string
	Reason       string
	MaskStrategy *identity.MaskStrategy
	AuditDenial  bool
}

type PredicateMatcher func(identity.Predicate) (bool, error)

// FieldRequiresPolicyEvaluation reports whether a field/action has rule or
// guardrail semantics that cannot be represented by the static field envelope
// alone. Query planners use this to avoid bypassing SDK policy evaluation with
// an unsafe raw-SQL pushdown.
func FieldRequiresPolicyEvaluation(bundle identity.AccessBundle, request FieldRequest) bool {
	resource := request.Resource
	field := strings.TrimSpace(request.Field)
	action := identity.Action(strings.ToLower(strings.TrimSpace(string(request.Action))))
	if !resource.Valid() || field == "" || !action.Valid() {
		return true
	}
	for _, guardrail := range bundle.Guardrails {
		if resourceMatches(guardrail.Resource, resource) && fieldMatches(guardrail.Field, field) && fieldActionMatches(guardrail.Action, action) {
			return true
		}
	}
	for _, policy := range bundle.FieldPolicies {
		if !resourceMatches(policy.Resource, resource) || !fieldMatches(policy.Field, field) {
			continue
		}
		for _, rule := range policy.Rules {
			if containsAction(rule.Actions, action) {
				return true
			}
		}
	}
	return false
}

// EvaluateField owns field-policy ordering and effects. A Runtime supplies a
// PredicateMatcher because only it can resolve application record relations;
// it must not reimplement priority or allow/deny/mask semantics.
func EvaluateField(bundle identity.AccessBundle, request FieldRequest, matches PredicateMatcher) (FieldDecision, error) {
	resource := request.Resource
	field := strings.TrimSpace(request.Field)
	action := identity.Action(strings.ToLower(strings.TrimSpace(string(request.Action))))
	if !resource.Valid() || field == "" || !action.Valid() {
		return FieldDecision{}, &identity.Error{Code: "identity.field_request_invalid"}
	}

	for _, guardrail := range bundle.Guardrails {
		if !resourceMatches(guardrail.Resource, resource) || !fieldMatches(guardrail.Field, field) || !fieldActionMatches(guardrail.Action, action) {
			continue
		}
		matched := true
		var err error
		if guardrail.Predicate != nil {
			if matches == nil {
				return FieldDecision{}, &identity.Error{Code: "identity.policy_predicate_matcher_required"}
			}
			matched, err = matches(*guardrail.Predicate)
		}
		if err != nil {
			return FieldDecision{}, err
		}
		if matched {
			return FieldDecision{Effect: identity.FieldEffectHide, RuleKey: guardrail.Key, Reason: guardrail.Reason}, nil
		}
	}

	var policy *identity.FieldPolicy
	policyScore := -1
	for index := range bundle.FieldPolicies {
		candidate := &bundle.FieldPolicies[index]
		if !resourceMatches(candidate.Resource, resource) || !fieldMatches(candidate.Field, field) {
			continue
		}
		score := 0
		if candidate.Resource == resource {
			score += 2
		}
		if strings.TrimSpace(candidate.Field) == field {
			score++
		}
		if score > policyScore {
			policy = candidate
			policyScore = score
		}
	}
	if policy == nil {
		return FieldDecision{Effect: identity.FieldEffectHide}, nil
	}
	decision := baselineFieldDecision(*policy, action)
	rules := append([]identity.FieldRule(nil), policy.Rules...)
	sort.SliceStable(rules, func(left, right int) bool { return rules[left].Priority > rules[right].Priority })
	for _, rule := range rules {
		if !containsAction(rule.Actions, action) {
			continue
		}
		matched := true
		var err error
		if rule.Predicate != nil {
			if matches == nil {
				return FieldDecision{}, &identity.Error{Code: "identity.policy_predicate_matcher_required"}
			}
			matched, err = matches(*rule.Predicate)
		}
		if err != nil {
			return FieldDecision{}, err
		}
		if !matched {
			continue
		}
		return FieldDecision{
			Effect: rule.Effect, RuleKey: rule.Key, Reason: policy.Reason,
			MaskStrategy: cloneMaskStrategy(rule.MaskStrategy), AuditDenial: rule.AuditDenial,
		}, nil
	}
	return decision, nil
}

func baselineFieldDecision(policy identity.FieldPolicy, action identity.Action) FieldDecision {
	allowed := false
	switch action {
	case "read", "list", "view", "search", "report", "audit":
		allowed = policy.Read
	case "export":
		allowed = policy.Export
	default:
		allowed = policy.Write
	}
	if !allowed {
		return FieldDecision{Effect: identity.FieldEffectHide, Reason: policy.Reason}
	}
	if policy.Masked && action != "write" && action != "update" && action != "create" {
		return FieldDecision{Effect: identity.FieldEffectMask, Reason: policy.Reason}
	}
	return FieldDecision{Effect: identity.FieldEffectAllow, Reason: policy.Reason}
}

func containsAction(values []identity.Action, expected identity.Action) bool {
	for _, candidate := range values {
		if fieldActionMatches(candidate, expected) {
			return true
		}
	}
	return false
}

func fieldActionMatches(candidate, expected identity.Action) bool {
	candidate = identity.Action(strings.ToLower(strings.TrimSpace(string(candidate))))
	expected = identity.Action(strings.ToLower(strings.TrimSpace(string(expected))))
	if candidate == expected || candidate == "*" {
		return true
	}
	return candidate == "write" && (expected == "create" || expected == "update") || expected == "write" && (candidate == "create" || candidate == "update")
}

func fieldMatches(configured, requested string) bool {
	configured = strings.TrimSpace(configured)
	requested = strings.TrimSpace(requested)
	return configured == requested || configured == "*"
}

func cloneMaskStrategy(value *identity.MaskStrategy) *identity.MaskStrategy {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
