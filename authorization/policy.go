package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (bundle AccessBundle) Validate(now time.Time) error {
	if bundle.ContractVersion != CurrentPolicyBundleVersion {
		return &Error{Code: "identity.access_bundle_version_unsupported"}
	}
	if !bundle.AuthorizationRevision.Valid() || !bundle.Subject.WorkspaceID.Valid() || !bundle.Subject.SubjectID.Valid() {
		return &Error{Code: "identity.access_bundle_identity_invalid"}
	}
	if bundle.ExpiresAt.IsZero() || !bundle.ExpiresAt.After(now) {
		return &Error{Code: "identity.access_bundle_expired"}
	}
	if !uniqueSubjectIDs(bundle.Subject.ReportingSubjectIDs) {
		return &Error{Code: "identity.access_bundle_subject_invalid"}
	}
	for key, values := range bundle.Subject.OrganizationScopes {
		if strings.TrimSpace(key) == "" || !uniqueNonBlank(values) {
			return &Error{Code: "identity.access_bundle_subject_invalid"}
		}
	}
	functionKeys := map[string]struct{}{}
	for _, grant := range bundle.FunctionGrants {
		if !grant.Resource.Valid() || !grant.Action.Valid() || grant.Resource == "*" || grant.Action == "*" || !grant.Effect.Valid() {
			return &Error{Code: "identity.function_grant_invalid"}
		}
		key := string(grant.Resource) + "\x00" + string(grant.Action) + "\x00" + string(grant.Effect)
		if _, duplicate := functionKeys[key]; duplicate {
			return &Error{Code: "identity.function_grant_duplicate"}
		}
		functionKeys[key] = struct{}{}
	}
	dataKeys := map[string]struct{}{}
	for _, policy := range bundle.DataPolicies {
		if strings.TrimSpace(policy.Key) == "" || !policy.Resource.Valid() || policy.Resource == "*" || !policy.Action.Valid() || !policy.Effect.Valid() {
			return &Error{Code: "identity.data_policy_invalid"}
		}
		if _, duplicate := dataKeys[policy.Key]; duplicate {
			return &Error{Code: "identity.data_policy_duplicate"}
		}
		dataKeys[policy.Key] = struct{}{}
		if err := policy.Predicate.Validate(); err != nil {
			return err
		}
	}
	fieldKeys := map[string]struct{}{}
	for _, policy := range bundle.FieldPolicies {
		if !policy.Resource.Valid() || strings.TrimSpace(policy.Field) == "" {
			return &Error{Code: "identity.field_policy_invalid"}
		}
		key := string(policy.Resource) + "\x00" + policy.Field
		if _, duplicate := fieldKeys[key]; duplicate {
			return &Error{Code: "identity.field_policy_duplicate"}
		}
		fieldKeys[key] = struct{}{}
		ruleKeys := map[string]struct{}{}
		priorities := map[int]struct{}{}
		for _, rule := range policy.Rules {
			if strings.TrimSpace(rule.Key) == "" || !rule.Effect.Valid() || !uniqueActions(rule.Actions) {
				return &Error{Code: "identity.field_rule_invalid"}
			}
			if _, duplicate := ruleKeys[rule.Key]; duplicate {
				return &Error{Code: "identity.field_rule_duplicate"}
			}
			if _, duplicate := priorities[rule.Priority]; duplicate {
				return &Error{Code: "identity.field_rule_priority_duplicate"}
			}
			ruleKeys[rule.Key] = struct{}{}
			priorities[rule.Priority] = struct{}{}
			if rule.Predicate != nil {
				if err := rule.Predicate.Validate(); err != nil {
					return err
				}
			}
			if err := rule.validateMaskStrategy(); err != nil {
				return err
			}
		}
	}
	referenceKeys := map[string]struct{}{}
	for _, policy := range bundle.ReferencePolicies {
		if !policy.SourceResource.Valid() || strings.TrimSpace(policy.Reference) == "" || !policy.TargetResource.Valid() || !uniqueNonBlank(policy.DisplayFields) {
			return &Error{Code: "identity.reference_policy_invalid"}
		}
		key := string(policy.SourceResource) + "\x00" + policy.Reference
		if _, duplicate := referenceKeys[key]; duplicate {
			return &Error{Code: "identity.reference_policy_duplicate"}
		}
		referenceKeys[key] = struct{}{}
	}
	exportKeys := map[ResourceType]struct{}{}
	for _, policy := range bundle.ExportPolicies {
		if !policy.Resource.Valid() || policy.Mode != ExportModeDeny && policy.Mode != ExportModeAllowList || !uniqueNonBlank(policy.Fields) {
			return &Error{Code: "identity.export_policy_invalid"}
		}
		if policy.Mode == ExportModeDeny && len(policy.Fields) != 0 {
			return &Error{Code: "identity.export_policy_invalid"}
		}
		if _, duplicate := exportKeys[policy.Resource]; duplicate {
			return &Error{Code: "identity.export_policy_duplicate"}
		}
		exportKeys[policy.Resource] = struct{}{}
	}
	guardrailKeys := map[string]struct{}{}
	for _, guardrail := range bundle.Guardrails {
		if strings.TrimSpace(guardrail.Key) == "" || !guardrail.Effect.Valid() || guardrail.Effect != EffectDeny {
			return &Error{Code: "identity.guardrail_invalid"}
		}
		if guardrail.Resource == "" && (guardrail.Action != "" || strings.TrimSpace(guardrail.Field) != "" || guardrail.Predicate != nil) {
			// An action or record predicate has no unambiguous meaning without a
			// resource type. Reject it instead of letting a catalog adapter drop a
			// deny rule while constraining the bundle.
			return &Error{Code: "identity.guardrail_invalid"}
		}
		if strings.TrimSpace(guardrail.Field) != "" && guardrail.Action == "" {
			return &Error{Code: "identity.guardrail_invalid"}
		}
		if _, duplicate := guardrailKeys[guardrail.Key]; duplicate {
			return &Error{Code: "identity.guardrail_duplicate"}
		}
		guardrailKeys[guardrail.Key] = struct{}{}
		if guardrail.Predicate != nil {
			if err := guardrail.Predicate.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (effect Effect) Valid() bool { return effect == EffectAllow || effect == EffectDeny }

func (action DataAction) Valid() bool {
	return action == DataActionRead || action == DataActionWrite
}

func (effect FieldEffect) Valid() bool {
	switch effect {
	case FieldEffectAllow, FieldEffectDeny, FieldEffectHide, FieldEffectMask:
		return true
	default:
		return false
	}
}

func (rule FieldRule) validateMaskStrategy() error {
	if rule.Effect != FieldEffectMask {
		if rule.MaskStrategy != nil {
			return &Error{Code: "identity.field_rule_mask_invalid"}
		}
		return nil
	}
	if rule.MaskStrategy == nil {
		return &Error{Code: "identity.field_rule_mask_required"}
	}
	switch rule.MaskStrategy.Type {
	case MaskTypePhone, MaskTypeIDNumber, MaskTypeEmail, MaskTypeYearOnly:
		if rule.MaskStrategy.LastN != 0 {
			return &Error{Code: "identity.field_rule_mask_invalid"}
		}
	case MaskTypeLastN:
		if rule.MaskStrategy.LastN < 1 || rule.MaskStrategy.LastN > 32 {
			return &Error{Code: "identity.field_rule_mask_invalid"}
		}
	default:
		return &Error{Code: "identity.field_rule_mask_invalid"}
	}
	return nil
}

func uniqueActions(values []Action) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[Action]struct{}, len(values))
	for _, value := range values {
		if !value.Valid() {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (predicate Predicate) Validate() error {
	branches := 0
	if strings.TrimSpace(predicate.Fact) != "" || predicate.Operator != "" {
		branches++
		if strings.TrimSpace(predicate.Fact) == "" || !predicate.Operator.Valid() {
			return &Error{Code: "identity.policy_predicate_invalid"}
		}
	}
	if len(predicate.All) > 0 {
		branches++
	}
	if len(predicate.Any) > 0 {
		branches++
	}
	if predicate.Not != nil {
		branches++
	}
	if branches != 1 {
		return &Error{Code: "identity.policy_predicate_invalid"}
	}
	if len(predicate.Path) > 0 {
		if len(predicate.Path) > 3 || len(predicate.All) > 0 || len(predicate.Any) > 0 || predicate.Not != nil {
			return &Error{Code: "identity.policy_relation_path_invalid"}
		}
		for _, segment := range predicate.Path {
			if segment.Direction != RelationForward && segment.Direction != RelationReverse || strings.TrimSpace(segment.Reference) == "" || !segment.TargetResource.Valid() {
				return &Error{Code: "identity.policy_relation_path_invalid"}
			}
		}
	}
	for _, child := range append(append([]Predicate(nil), predicate.All...), predicate.Any...) {
		if err := child.Validate(); err != nil {
			return err
		}
	}
	if predicate.Not != nil {
		return predicate.Not.Validate()
	}
	return nil
}

func (operator Operator) Valid() bool {
	switch operator {
	case OperatorEqual, OperatorNotEqual, OperatorIn, OperatorNotIn, OperatorExists, OperatorPrefix, OperatorContains:
		return true
	default:
		return false
	}
}

func (bundle AccessBundle) CanonicalJSON(now time.Time) ([]byte, error) {
	if err := bundle.Validate(now); err != nil {
		return nil, err
	}
	clone := bundle
	clone.Subject.ReportingSubjectIDs = append([]SubjectID(nil), bundle.Subject.ReportingSubjectIDs...)
	sort.Slice(clone.Subject.ReportingSubjectIDs, func(i, j int) bool {
		return clone.Subject.ReportingSubjectIDs[i] < clone.Subject.ReportingSubjectIDs[j]
	})
	if bundle.Subject.OrganizationScopes != nil {
		clone.Subject.OrganizationScopes = make(map[string][]string, len(bundle.Subject.OrganizationScopes))
		for key, values := range bundle.Subject.OrganizationScopes {
			clone.Subject.OrganizationScopes[key] = append([]string(nil), values...)
			sort.Strings(clone.Subject.OrganizationScopes[key])
		}
	}
	clone.FunctionGrants = append([]FunctionGrant(nil), bundle.FunctionGrants...)
	clone.DataPolicies = append([]DataPolicy(nil), bundle.DataPolicies...)
	for index := range clone.DataPolicies {
		clone.DataPolicies[index].Predicate = canonicalPredicate(clone.DataPolicies[index].Predicate)
	}
	clone.FieldPolicies = append([]FieldPolicy(nil), bundle.FieldPolicies...)
	for index := range clone.FieldPolicies {
		clone.FieldPolicies[index] = canonicalFieldPolicy(clone.FieldPolicies[index])
	}
	clone.ReferencePolicies = append([]ReferencePolicy(nil), bundle.ReferencePolicies...)
	for index := range clone.ReferencePolicies {
		clone.ReferencePolicies[index].DisplayFields = append([]string(nil), clone.ReferencePolicies[index].DisplayFields...)
		sort.Strings(clone.ReferencePolicies[index].DisplayFields)
	}
	clone.ExportPolicies = append([]ExportPolicy(nil), bundle.ExportPolicies...)
	for index := range clone.ExportPolicies {
		clone.ExportPolicies[index].Fields = append([]string(nil), clone.ExportPolicies[index].Fields...)
		sort.Strings(clone.ExportPolicies[index].Fields)
	}
	clone.Guardrails = append([]Guardrail(nil), bundle.Guardrails...)
	for index := range clone.Guardrails {
		if clone.Guardrails[index].Predicate != nil {
			predicate := canonicalPredicate(*clone.Guardrails[index].Predicate)
			clone.Guardrails[index].Predicate = &predicate
		}
	}
	sort.Slice(clone.FunctionGrants, func(i, j int) bool {
		left, right := clone.FunctionGrants[i], clone.FunctionGrants[j]
		return fmt.Sprint(left.Resource, "\x00", left.Action, "\x00", left.Effect) < fmt.Sprint(right.Resource, "\x00", right.Action, "\x00", right.Effect)
	})
	sort.Slice(clone.DataPolicies, func(i, j int) bool { return clone.DataPolicies[i].Key < clone.DataPolicies[j].Key })
	sort.Slice(clone.FieldPolicies, func(i, j int) bool {
		return fmt.Sprint(clone.FieldPolicies[i].Resource, "\x00", clone.FieldPolicies[i].Field) < fmt.Sprint(clone.FieldPolicies[j].Resource, "\x00", clone.FieldPolicies[j].Field)
	})
	sort.Slice(clone.ReferencePolicies, func(i, j int) bool {
		return fmt.Sprint(clone.ReferencePolicies[i].SourceResource, "\x00", clone.ReferencePolicies[i].Reference) < fmt.Sprint(clone.ReferencePolicies[j].SourceResource, "\x00", clone.ReferencePolicies[j].Reference)
	})
	sort.Slice(clone.ExportPolicies, func(i, j int) bool { return clone.ExportPolicies[i].Resource < clone.ExportPolicies[j].Resource })
	sort.Slice(clone.Guardrails, func(i, j int) bool { return clone.Guardrails[i].Key < clone.Guardrails[j].Key })
	return json.Marshal(clone)
}

func canonicalPredicate(predicate Predicate) Predicate {
	predicate.Path = append([]RelationSegment(nil), predicate.Path...)
	predicate.All = canonicalPredicateList(predicate.All)
	predicate.Any = canonicalPredicateList(predicate.Any)
	if predicate.Not != nil {
		nested := canonicalPredicate(*predicate.Not)
		predicate.Not = &nested
	}
	switch values := predicate.Value.(type) {
	case []string:
		predicate.Value = append([]string(nil), values...)
		if predicate.Operator == OperatorIn || predicate.Operator == OperatorNotIn {
			sort.Strings(predicate.Value.([]string))
		}
	case []any:
		predicate.Value = append([]any(nil), values...)
		if predicate.Operator == OperatorIn || predicate.Operator == OperatorNotIn {
			sort.Slice(predicate.Value.([]any), func(left, right int) bool {
				leftJSON, _ := json.Marshal(predicate.Value.([]any)[left])
				rightJSON, _ := json.Marshal(predicate.Value.([]any)[right])
				return string(leftJSON) < string(rightJSON)
			})
		}
	}
	return predicate
}

func canonicalFieldPolicy(policy FieldPolicy) FieldPolicy {
	policy.Rules = append([]FieldRule(nil), policy.Rules...)
	for index := range policy.Rules {
		policy.Rules[index].Actions = append([]Action(nil), policy.Rules[index].Actions...)
		sort.Slice(policy.Rules[index].Actions, func(left, right int) bool {
			return policy.Rules[index].Actions[left] < policy.Rules[index].Actions[right]
		})
		if policy.Rules[index].Predicate != nil {
			predicate := canonicalPredicate(*policy.Rules[index].Predicate)
			policy.Rules[index].Predicate = &predicate
		}
		if policy.Rules[index].MaskStrategy != nil {
			strategy := *policy.Rules[index].MaskStrategy
			policy.Rules[index].MaskStrategy = &strategy
		}
	}
	sort.Slice(policy.Rules, func(left, right int) bool {
		if policy.Rules[left].Priority != policy.Rules[right].Priority {
			return policy.Rules[left].Priority > policy.Rules[right].Priority
		}
		return policy.Rules[left].Key < policy.Rules[right].Key
	})
	return policy
}

func canonicalPredicateList(values []Predicate) []Predicate {
	if values == nil {
		return nil
	}
	result := make([]Predicate, len(values))
	for index := range values {
		result[index] = canonicalPredicate(values[index])
	}
	sort.Slice(result, func(left, right int) bool {
		leftJSON, _ := json.Marshal(result[left])
		rightJSON, _ := json.Marshal(result[right])
		return string(leftJSON) < string(rightJSON)
	})
	return result
}

func uniqueSubjectIDs(values []SubjectID) bool {
	seen := make(map[SubjectID]struct{}, len(values))
	for _, value := range values {
		if !value.Valid() {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (bundle AccessBundle) CacheKey(now time.Time) (string, error) {
	if err := bundle.Validate(now); err != nil {
		return "", err
	}
	payload, _ := json.Marshal(struct {
		Workspace WorkspaceID           `json:"workspace"`
		Subject   SubjectID             `json:"subject"`
		Revision  AuthorizationRevision `json:"revision"`
	}{bundle.Subject.WorkspaceID, bundle.Subject.SubjectID, bundle.AuthorizationRevision})
	digest := sha256.Sum256(payload)
	return "identity-access:" + hex.EncodeToString(digest[:]), nil
}

func uniqueNonBlank(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
