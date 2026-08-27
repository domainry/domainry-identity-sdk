package evaluator

import (
	"strings"

	identity "github.com/domainry/domainry-identity-sdk/authorization"
)

// EvaluationContext combines immutable Identity facts with business facts
// resolved for the current request. BusinessClaims are deliberately
// separate from AccessBundle.Subject: selecting a business profile must never
// mutate or counterfeit Identity-issued policy state.
type EvaluationContext struct {
	Subject        identity.Subject
	BusinessClaims map[string]any
}

type missingBusinessClaim struct{}

func IsMissingValue(value any) bool {
	_, missing := value.(missingBusinessClaim)
	return missing
}

// ResolveValue resolves portable policy references. Unknown references fail
// closed instead of being compared as literal strings.
func ResolveValue(value any, evaluation EvaluationContext) (any, error) {
	text, ok := value.(string)
	if !ok {
		return value, nil
	}
	if strings.HasPrefix(text, "$subject.") {
		resolved := resolveIdentitySubjectValue(text, evaluation.Subject)
		if resolvedText, unresolved := resolved.(string); unresolved && resolvedText == text {
			return nil, &identity.Error{Code: "identity.policy_subject_claim_unknown", Message: text}
		}
		return resolved, nil
	}
	if !strings.HasPrefix(text, "$context.") {
		return value, nil
	}
	key := strings.TrimPrefix(text, "$context.")
	key = strings.TrimPrefix(key, "claims.")
	if strings.TrimSpace(key) == "" {
		return nil, &identity.Error{Code: "identity.policy_business_claim_unknown", Message: text}
	}
	resolved, exists := evaluation.BusinessClaims[key]
	if !exists || resolved == nil {
		// Business claims are request-scoped. A user without the selected
		// profile or claim simply does not match the policy; this is a normal
		// authorization denial, not a malformed bundle.
		return missingBusinessClaim{}, nil
	}
	return resolved, nil
}
