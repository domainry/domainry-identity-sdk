// Package evaluator enforces Identity access bundles locally inside a
// business Runtime. It never calls Identity and fails closed on unsupported
// policy input.
package evaluator

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	identity "github.com/domainry/domainry-identity-sdk/authorization"
)

type Decision struct {
	Allowed     bool
	Code        string
	PolicyKey   string
	Reason      string
	AuditDenial bool
}

// AuditDenialRequired reports whether a denial for the requested resource and
// action is configured as auditable. It is intentionally independent of
// record facts so callers can decide after a not-found projection without
// reconstructing Identity policy semantics.
func AuditDenialRequired(bundle identity.AccessBundle, resource identity.ResourceType, dataAction identity.DataAction, now time.Time) (bool, error) {
	if err := bundle.Validate(now); err != nil {
		return false, err
	}
	if !resource.Valid() || !dataAction.Valid() {
		return false, &identity.Error{Code: "identity.access_request_invalid"}
	}
	for _, policy := range bundle.DataPolicies {
		if resourceMatches(policy.Resource, resource) && policy.Action == dataAction && policy.AuditDenial {
			return true, nil
		}
	}
	return false, nil
}

func Evaluate(bundle identity.AccessBundle, request identity.AccessRequest, facts identity.ResourceFacts, now time.Time) (Decision, error) {
	return EvaluateWithContext(bundle, request, facts, EvaluationContext{Subject: bundle.Subject}, now)
}

// EvaluateWithContext evaluates one complete function/data/field request. The
// caller may add business claims (for example an active business
// profile) without mutating the Identity-issued AccessBundle.
func EvaluateWithContext(bundle identity.AccessBundle, request identity.AccessRequest, facts identity.ResourceFacts, evaluation EvaluationContext, now time.Time) (Decision, error) {
	if err := bundle.Validate(now); err != nil {
		return Decision{Code: "access_bundle_invalid"}, err
	}
	resource, action := identity.ResourceType(strings.TrimSpace(request.ObjectKey)), identity.Action(strings.TrimSpace(request.Action))
	dataAction := identity.DataAction(strings.TrimSpace(string(request.DataAction)))
	if !resource.Valid() || !action.Valid() || !dataAction.Valid() {
		return Decision{Code: "access_request_invalid"}, &identity.Error{Code: "identity.access_request_invalid"}
	}
	functionAllowed := false
	for _, grant := range bundle.FunctionGrants {
		if grant.Resource != resource || grant.Action != action {
			continue
		}
		if grant.Effect == identity.EffectDeny {
			return Decision{Code: "function_denied"}, nil
		}
		functionAllowed = true
	}
	if !functionAllowed {
		return Decision{Code: "function_not_granted"}, nil
	}
	for _, guardrail := range bundle.Guardrails {
		if guardrail.Resource != "" && !resourceMatches(guardrail.Resource, resource) || guardrail.Action != "" && !actionMatches(guardrail.Action, action) {
			continue
		}
		if strings.TrimSpace(guardrail.Field) != "" {
			// A field restriction must not deny the containing record. It is
			// evaluated by EvaluateField below when a field was requested.
			continue
		}
		matches := true
		var err error
		if guardrail.Predicate != nil {
			matches, err = EvaluatePredicateWithContext(*guardrail.Predicate, facts, evaluation)
		}
		if err != nil {
			return Decision{Code: "guardrail_invalid"}, err
		}
		if matches {
			return Decision{Code: "guardrail_denied", PolicyKey: guardrail.Key, Reason: guardrail.Reason}, nil
		}
	}
	matchedAllow, hasPolicies, auditDenial := false, false, false
	for _, policy := range bundle.DataPolicies {
		if !resourceMatches(policy.Resource, resource) || policy.Action != dataAction {
			continue
		}
		hasPolicies = true
		auditDenial = auditDenial || policy.AuditDenial
		matches, err := EvaluatePredicateWithContext(policy.Predicate, facts, evaluation)
		if err != nil {
			return Decision{Code: "data_policy_invalid"}, err
		}
		if matches && policy.Effect == identity.EffectDeny {
			return Decision{Code: "data_policy_denied", PolicyKey: policy.Key, AuditDenial: policy.AuditDenial}, nil
		}
		matchedAllow = matchedAllow || matches && policy.Effect == identity.EffectAllow
	}
	// Function permission never implies record visibility. Even an unrestricted
	// scope is represented by an explicit allow predicate (for example, id
	// exists), so an absent data policy fails closed.
	if !hasPolicies || !matchedAllow {
		return Decision{Code: "data_policy_not_granted", AuditDenial: auditDenial}, nil
	}
	if field := strings.TrimSpace(request.FieldKey); field != "" {
		fieldDecision, err := EvaluateField(bundle, FieldRequest{Resource: resource, Field: field, Action: identity.Action(request.Action)}, func(predicate identity.Predicate) (bool, error) {
			return EvaluatePredicateWithContext(predicate, facts, evaluation)
		})
		if err != nil {
			return Decision{Code: "field_policy_invalid"}, err
		}
		if fieldDecision.Effect != identity.FieldEffectAllow && fieldDecision.Effect != identity.FieldEffectMask {
			return Decision{Code: "field_not_granted", PolicyKey: fieldDecision.RuleKey, Reason: fieldDecision.Reason, AuditDenial: fieldDecision.AuditDenial}, nil
		}
	}
	return Decision{Allowed: true, Code: "allowed"}, nil
}

func EvaluatePredicate(predicate identity.Predicate, facts identity.ResourceFacts, subject identity.Subject) (bool, error) {
	return EvaluatePredicateWithContext(predicate, facts, EvaluationContext{Subject: subject})
}

func EvaluatePredicateWithContext(predicate identity.Predicate, facts identity.ResourceFacts, evaluation EvaluationContext) (bool, error) {
	if err := predicate.Validate(); err != nil {
		return false, err
	}
	if len(predicate.Path) > 0 {
		return false, &identity.Error{Code: "identity.policy_relation_resolver_required"}
	}
	if len(predicate.All) > 0 {
		for _, child := range predicate.All {
			match, err := EvaluatePredicateWithContext(child, facts, evaluation)
			if err != nil || !match {
				return false, err
			}
		}
		return true, nil
	}
	if len(predicate.Any) > 0 {
		for _, child := range predicate.Any {
			match, err := EvaluatePredicateWithContext(child, facts, evaluation)
			if err != nil {
				return false, err
			}
			if match {
				return true, nil
			}
		}
		return false, nil
	}
	if predicate.Not != nil {
		match, err := EvaluatePredicateWithContext(*predicate.Not, facts, evaluation)
		return !match, err
	}
	actual, exists := facts[predicate.Fact]
	expected, err := ResolveValue(predicate.Value, evaluation)
	if err != nil {
		return false, err
	}
	if IsMissingValue(expected) {
		return false, nil
	}
	switch predicate.Operator {
	case identity.OperatorExists:
		want, ok := expected.(bool)
		if !ok {
			return false, &identity.Error{Code: "identity.policy_value_invalid"}
		}
		return exists == want, nil
	case identity.OperatorEqual:
		return exists && scalarEqual(actual, expected), nil
	case identity.OperatorNotEqual:
		return exists && !scalarEqual(actual, expected), nil
	case identity.OperatorIn, identity.OperatorNotIn:
		match, ok := contains(expected, actual)
		if !ok {
			return false, &identity.Error{Code: "identity.policy_value_invalid"}
		}
		if predicate.Operator == identity.OperatorNotIn {
			match = !match
		}
		return exists && match, nil
	case identity.OperatorPrefix:
		left, leftOK := actual.(string)
		right, rightOK := expected.(string)
		return exists && leftOK && rightOK && strings.HasPrefix(left, right), nil
	case identity.OperatorContains:
		match, ok := contains(actual, expected)
		if !ok {
			return false, &identity.Error{Code: "identity.policy_value_invalid"}
		}
		return exists && match, nil
	default:
		return false, &identity.Error{Code: "identity.policy_operator_unsupported"}
	}
}

func ReadableFields(bundle identity.AccessBundle, resource identity.ResourceType) []string {
	return fields(bundle, resource, func(policy identity.FieldPolicy) bool { return policy.Read })
}

func WritableFields(bundle identity.AccessBundle, resource identity.ResourceType) []string {
	return fields(bundle, resource, func(policy identity.FieldPolicy) bool { return policy.Write })
}

func ExportableFields(bundle identity.AccessBundle, resource identity.ResourceType) []string {
	denied := false
	hasAllowList := false
	allowList := map[string]bool{}
	for _, policy := range bundle.ExportPolicies {
		if !resourceMatches(policy.Resource, resource) {
			continue
		}
		switch policy.Mode {
		case identity.ExportModeDeny:
			denied = true
		case identity.ExportModeAllowList:
			hasAllowList = true
			for _, field := range policy.Fields {
				allowList[field] = true
			}
		default:
			return []string{}
		}
	}
	if denied {
		return []string{}
	}
	return fields(bundle, resource, func(policy identity.FieldPolicy) bool {
		return policy.Export && (!hasAllowList || allowList[policy.Field])
	})
}

func fields(bundle identity.AccessBundle, resource identity.ResourceType, allowed func(identity.FieldPolicy) bool) []string {
	set := map[string]bool{}
	for _, policy := range bundle.FieldPolicies {
		if resourceMatches(policy.Resource, resource) && strings.TrimSpace(policy.Field) != "" && allowed(policy) {
			set[policy.Field] = true
		}
	}
	result := make([]string, 0, len(set))
	for field := range set {
		result = append(result, field)
	}
	sort.Strings(result)
	return result
}

func AllowedReferences(bundle identity.AccessBundle, resource identity.ResourceType) []identity.ReferencePolicy {
	allowed := map[string]identity.ReferencePolicy{}
	denied := map[string]bool{}
	for _, policy := range bundle.ReferencePolicies {
		if !resourceMatches(policy.SourceResource, resource) {
			continue
		}
		if !policy.Allowed || referenceGuardrailDenied(bundle, resource, policy.Reference) {
			denied[policy.Reference] = true
			for key, existing := range allowed {
				if existing.Reference == policy.Reference {
					delete(allowed, key)
				}
			}
			continue
		}
		if !denied[policy.Reference] {
			key := strings.TrimSpace(policy.Reference) + "\x00" + strings.TrimSpace(string(policy.TargetResource))
			if existing, found := allowed[key]; found {
				existing.DisplayFields = appendUniqueStrings(existing.DisplayFields, policy.DisplayFields...)
				if existing.Reason == "" {
					existing.Reason = policy.Reason
				}
				allowed[key] = existing
			} else {
				policy.DisplayFields = appendUniqueStrings(nil, policy.DisplayFields...)
				allowed[key] = policy
			}
		}
	}
	result := make([]identity.ReferencePolicy, 0, len(allowed))
	for _, policy := range allowed {
		result = append(result, policy)
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].Reference + "\x00" + string(result[i].TargetResource)
		right := result[j].Reference + "\x00" + string(result[j].TargetResource)
		return left < right
	})
	return result
}

func resourceMatches(configured, requested identity.ResourceType) bool {
	return configured == requested || configured == "*"
}

func actionMatches(configured, requested identity.Action) bool {
	return configured == requested || configured == "*"
}

func referenceGuardrailDenied(bundle identity.AccessBundle, resource identity.ResourceType, reference string) bool {
	for _, guardrail := range bundle.Guardrails {
		if guardrail.Effect != identity.EffectDeny || !resourceMatches(guardrail.Resource, resource) ||
			strings.TrimSpace(guardrail.Field) != strings.TrimSpace(reference) ||
			!actionMatches(guardrail.Action, "read") || guardrail.Predicate != nil {
			continue
		}
		return true
	}
	return false
}

func appendUniqueStrings(existing []string, values ...string) []string {
	seen := make(map[string]bool, len(existing)+len(values))
	for _, value := range existing {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			existing = append(existing, value)
			seen[value] = true
		}
	}
	return existing
}

func resolveSubjectValue(value any, subject identity.Subject) any {
	resolved, err := ResolveValue(value, EvaluationContext{Subject: subject})
	if err != nil {
		return value
	}
	return resolved
}

func resolveIdentitySubjectValue(value any, subject identity.Subject) any {
	text, ok := value.(string)
	if !ok || !strings.HasPrefix(text, "$subject.") {
		return value
	}
	switch strings.TrimPrefix(text, "$subject.") {
	case "id":
		return string(subject.SubjectID)
	case "workspace_id":
		return string(subject.WorkspaceID)
	case "department_id":
		return subject.DepartmentID
	case "department_path":
		return subject.DepartmentPath
	case "reporting_path":
		return subject.ReportingPath
	case "workforce_profile_id":
		return subject.WorkforceProfileID
	case "reporting_subject_ids":
		values := make([]string, len(subject.ReportingSubjectIDs))
		for index, id := range subject.ReportingSubjectIDs {
			values[index] = string(id)
		}
		return values
	default:
		if scope, exists := strings.CutPrefix(strings.TrimPrefix(text, "$subject."), "organization_scopes."); exists {
			return append([]string(nil), subject.OrganizationScopes[scope]...)
		}
		return value
	}
}

func scalarEqual(left, right any) bool {
	return reflect.DeepEqual(normalizeNumber(left), normalizeNumber(right))
}

func normalizeNumber(value any) any {
	var text string
	switch number := value.(type) {
	case json.Number:
		text = string(number)
	case int:
		text = strconv.FormatInt(int64(number), 10)
	case int8:
		text = strconv.FormatInt(int64(number), 10)
	case int16:
		text = strconv.FormatInt(int64(number), 10)
	case int32:
		text = strconv.FormatInt(int64(number), 10)
	case int64:
		text = strconv.FormatInt(number, 10)
	case uint:
		text = strconv.FormatUint(uint64(number), 10)
	case uint8:
		text = strconv.FormatUint(uint64(number), 10)
	case uint16:
		text = strconv.FormatUint(uint64(number), 10)
	case uint32:
		text = strconv.FormatUint(uint64(number), 10)
	case uint64:
		text = strconv.FormatUint(number, 10)
	case float32:
		text = strconv.FormatFloat(float64(number), 'g', -1, 32)
	case float64:
		text = strconv.FormatFloat(number, 'g', -1, 64)
	default:
		return value
	}
	rational, ok := new(big.Rat).SetString(text)
	if !ok {
		return fmt.Sprintf("invalid-number:%s", text)
	}
	return "number:" + rational.RatString()
}

func contains(container, expected any) (bool, bool) {
	value := reflect.ValueOf(container)
	if !value.IsValid() || value.Kind() != reflect.Array && value.Kind() != reflect.Slice {
		return false, false
	}
	for index := 0; index < value.Len(); index++ {
		if scalarEqual(value.Index(index).Interface(), expected) {
			return true, true
		}
	}
	return false, true
}
