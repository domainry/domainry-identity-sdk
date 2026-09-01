package evaluator

import (
	"fmt"
	"strings"
	"time"

	identity "github.com/domainry/domainry-identity-sdk/authorization"
)

type RecordFilter struct {
	Allow []identity.Predicate
	Deny  []identity.Predicate
}

// CompileRecordFilter returns one bounded portable filter. Runtimes translate
// it once per query; they must not call remote authorization per row.
func CompileRecordFilter(bundle identity.AccessBundle, resource identity.ResourceType, action identity.Action, dataAction identity.DataAction, now time.Time) (RecordFilter, error) {
	filter := RecordFilter{Allow: []identity.Predicate{}, Deny: []identity.Predicate{}}
	if err := bundle.Validate(now); err != nil {
		return RecordFilter{}, err
	}
	if !resource.Valid() || !action.Valid() || !dataAction.Valid() {
		return RecordFilter{}, &identity.Error{Code: "identity.access_request_invalid"}
	}
	functionAllowed := false
	for _, grant := range bundle.FunctionGrants {
		if grant.Resource != resource || grant.Action != action {
			continue
		}
		if grant.Effect == identity.EffectDeny {
			return filter, nil
		}
		functionAllowed = true
	}
	if !functionAllowed {
		return filter, nil
	}
	for _, guardrail := range bundle.Guardrails {
		if guardrail.Resource != "" && !resourceMatches(guardrail.Resource, resource) || guardrail.Action != "" && !actionMatches(guardrail.Action, action) {
			continue
		}
		if guardrail.Predicate == nil {
			return RecordFilter{Allow: []identity.Predicate{}, Deny: []identity.Predicate{}}, nil
		}
		filter.Deny = append(filter.Deny, *guardrail.Predicate)
	}
	for _, policy := range bundle.DataPolicies {
		if !resourceMatches(policy.Resource, resource) || policy.Action != dataAction {
			continue
		}
		if err := policy.Predicate.Validate(); err != nil {
			return RecordFilter{}, err
		}
		if policy.Effect == identity.EffectDeny {
			filter.Deny = append(filter.Deny, policy.Predicate)
		} else if policy.Effect == identity.EffectAllow {
			filter.Allow = append(filter.Allow, policy.Predicate)
		} else {
			return RecordFilter{}, &identity.Error{Code: "identity.policy_effect_unsupported"}
		}
	}
	return filter, nil
}

type SQLFilter struct {
	Clause string
	Args   []any
}

type ColumnResolver func(string) (string, bool)

func CompileSQL(filter RecordFilter, subject identity.Subject, resolve ColumnResolver) (SQLFilter, error) {
	return CompileSQLWithContext(filter, EvaluationContext{Subject: subject}, resolve)
}

func CompileSQLWithContext(filter RecordFilter, evaluation EvaluationContext, resolve ColumnResolver) (SQLFilter, error) {
	if resolve == nil {
		return SQLFilter{}, &identity.Error{Code: "identity.policy_column_resolver_required"}
	}
	allow, allowArgs, err := compileGroup(filter.Allow, evaluation, resolve, " OR ")
	if err != nil {
		return SQLFilter{}, err
	}
	deny, denyArgs, err := compileGroup(filter.Deny, evaluation, resolve, " OR ")
	if err != nil {
		return SQLFilter{}, err
	}
	if allow == "" && len(filter.Allow) > 0 {
		return SQLFilter{}, &identity.Error{Code: "identity.policy_translation_failed"}
	}
	// No explicit allow policy means no visible records. Function grants are
	// deliberately not inputs to the SQL compiler and cannot become all rows.
	clause := "0 = 1"
	args := []any{}
	if allow != "" {
		clause = "(" + allow + ")"
		args = append(args, allowArgs...)
	}
	if deny != "" {
		clause += " AND NOT (" + deny + ")"
		args = append(args, denyArgs...)
	}
	return SQLFilter{Clause: clause, Args: args}, nil
}

func compileGroup(values []identity.Predicate, evaluation EvaluationContext, resolve ColumnResolver, separator string) (string, []any, error) {
	clauses := make([]string, 0, len(values))
	args := []any{}
	for _, predicate := range values {
		clause, values, err := compilePredicate(predicate, evaluation, resolve)
		if err != nil {
			return "", nil, err
		}
		clauses = append(clauses, clause)
		args = append(args, values...)
	}
	return strings.Join(clauses, separator), args, nil
}

func compilePredicate(predicate identity.Predicate, evaluation EvaluationContext, resolve ColumnResolver) (string, []any, error) {
	if err := predicate.Validate(); err != nil {
		return "", nil, err
	}
	if len(predicate.Path) > 0 {
		return "", nil, &identity.Error{Code: "identity.policy_relation_resolver_required"}
	}
	if len(predicate.All) > 0 {
		clause, args, err := compileGroup(predicate.All, evaluation, resolve, " AND ")
		return "(" + clause + ")", args, err
	}
	if len(predicate.Any) > 0 {
		clause, args, err := compileGroup(predicate.Any, evaluation, resolve, " OR ")
		return "(" + clause + ")", args, err
	}
	if predicate.Not != nil {
		clause, args, err := compilePredicate(*predicate.Not, evaluation, resolve)
		return "NOT (" + clause + ")", args, err
	}
	column, ok := resolve(predicate.Fact)
	if !ok || strings.TrimSpace(column) == "" {
		return "", nil, &identity.Error{Code: "identity.policy_fact_untranslatable", Message: predicate.Fact}
	}
	expected, err := ResolveValue(predicate.Value, evaluation)
	if err != nil {
		return "", nil, err
	}
	if IsMissingValue(expected) {
		return "0 = 1", nil, nil
	}
	switch predicate.Operator {
	case identity.OperatorEqual:
		return column + " = ?", []any{expected}, nil
	case identity.OperatorNotEqual:
		return column + " <> ?", []any{expected}, nil
	case identity.OperatorPrefix:
		value, ok := expected.(string)
		if !ok {
			return "", nil, &identity.Error{Code: "identity.policy_value_invalid"}
		}
		return column + " LIKE ? ESCAPE '\\'", []any{escapeLike(value) + "%"}, nil
	case identity.OperatorExists:
		want, ok := expected.(bool)
		if !ok {
			return "", nil, &identity.Error{Code: "identity.policy_value_invalid"}
		}
		if want {
			return column + " IS NOT NULL", nil, nil
		}
		return column + " IS NULL", nil, nil
	case identity.OperatorIn, identity.OperatorNotIn:
		values, ok := anySlice(expected)
		if !ok || len(values) == 0 {
			return "", nil, &identity.Error{Code: "identity.policy_value_invalid"}
		}
		marks := strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")
		op := " IN "
		if predicate.Operator == identity.OperatorNotIn {
			op = " NOT IN "
		}
		return column + op + "(" + marks + ")", values, nil
	default:
		return "", nil, &identity.Error{Code: "identity.policy_operator_untranslatable", Message: fmt.Sprint(predicate.Operator)}
	}
}

func anySlice(value any) ([]any, bool) {
	switch typed := value.(type) {
	case []any:
		return append([]any(nil), typed...), true
	case []string:
		out := make([]any, len(typed))
		for index := range typed {
			out[index] = typed[index]
		}
		return out, true
	default:
		return nil, false
	}
}

func escapeLike(value string) string {
	return strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(value)
}
