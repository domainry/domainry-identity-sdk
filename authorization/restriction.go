package authorization

import "strings"

// RestrictAccess intersects an AccessBundle with an application credential's
// explicit resource.action scopes. Denies and guardrails are always retained.
func RestrictAccess(bundle AccessBundle, scopes []string) AccessBundle {
	derived := cloneAccessBundle(bundle)
	allowed := map[string]bool{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			allowed[scope] = true
		}
	}
	allows := func(resource ResourceType, action Action) bool {
		return allowed[string(resource)+"."+string(action)]
	}

	functions := make([]FunctionGrant, 0, len(derived.FunctionGrants))
	for _, grant := range derived.FunctionGrants {
		if grant.Effect == EffectDeny || allows(grant.Resource, grant.Action) {
			functions = append(functions, grant)
		}
	}
	derived.FunctionGrants = functions
	data := make([]DataPolicy, 0, len(derived.DataPolicies))
	for _, policy := range derived.DataPolicies {
		if policy.Effect == EffectDeny || allows(policy.Resource, policy.Action) {
			data = append(data, policy)
		}
	}
	derived.DataPolicies = data
	fields := make([]FieldPolicy, 0, len(derived.FieldPolicies))
	for _, policy := range derived.FieldPolicies {
		policy.Read = policy.Read && allows(policy.Resource, "read")
		policy.Write = policy.Write && (allows(policy.Resource, "create") || allows(policy.Resource, "update"))
		policy.Export = policy.Export && allows(policy.Resource, "export")
		if policy.Read || policy.Write || policy.Export {
			fields = append(fields, policy)
		}
	}
	derived.FieldPolicies = fields
	references := make([]ReferencePolicy, 0, len(derived.ReferencePolicies))
	for _, policy := range derived.ReferencePolicies {
		if allows(policy.SourceResource, "read") {
			references = append(references, policy)
		}
	}
	derived.ReferencePolicies = references
	exports := make([]ExportPolicy, 0, len(derived.ExportPolicies))
	for _, policy := range derived.ExportPolicies {
		if allows(policy.Resource, "export") {
			exports = append(exports, policy)
		}
	}
	derived.ExportPolicies = exports
	return derived
}
