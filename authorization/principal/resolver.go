// Package principal resolves the bounded token, session, and authorization
// snapshot into a Runtime request principal.
package principal

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/domainry/domainry-identity-sdk/authentication"
	identity "github.com/domainry/domainry-identity-sdk/authorization"
)

// Binding is the minimum cohesive SDK surface required to build a Runtime
// request principal. The root identity.Binding satisfies it structurally,
// while this package remains dependent only on business contracts.
type Binding interface {
	Tokens() authentication.TokenVerifier
	Authentication() authentication.Authentication
	Authorization() identity.Authorization
}

type Clock interface {
	Now() time.Time
}

// Resolver verifies bounded JWT claims locally, resolves the richer session
// and AccessBundle once, and caches only until the earliest token, bundle, or
// configured expiry.
type Resolver struct {
	binding Binding
	clock   Clock
	maxTTL  time.Duration
	mu      sync.RWMutex
	entries map[string]resolvedPrincipal
}

type Options struct {
	Clock       Clock
	MaxCacheTTL time.Duration
}

type resolvedPrincipal struct {
	principal identity.Principal
	expiresAt time.Time
}

func NewResolver(binding Binding, options Options) (*Resolver, error) {
	if binding == nil || binding.Tokens() == nil || binding.Authentication() == nil || binding.Authorization() == nil {
		return nil, &identity.Error{Code: "identity.binding_incomplete", Message: "token, authentication, and authorization contracts are required"}
	}
	clock := options.Clock
	if clock == nil {
		clock = systemClock{}
	}
	maxTTL := options.MaxCacheTTL
	if maxTTL <= 0 {
		maxTTL = time.Minute
	}
	return &Resolver{binding: binding, clock: clock, maxTTL: maxTTL, entries: map[string]resolvedPrincipal{}}, nil
}

func (resolver *Resolver) Authenticate(ctx context.Context, accessToken string) (identity.Principal, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return identity.Principal{}, &identity.Error{Code: "auth.token_required"}
	}
	verified, err := resolver.binding.Tokens().Verify(ctx, authentication.VerifyTokenRequest{AccessToken: accessToken})
	if err != nil {
		return identity.Principal{}, err
	}
	now := resolver.clock.Now()
	cacheKey := resolverCacheKey(verified)
	resolver.mu.RLock()
	cached, found := resolver.entries[cacheKey]
	resolver.mu.RUnlock()
	if found && now.Before(cached.expiresAt) {
		return clonePrincipal(cached.principal), nil
	}
	session, err := resolver.binding.Authentication().CurrentSession(ctx, authentication.CurrentSessionRequest{AccessToken: accessToken})
	if err != nil {
		return identity.Principal{}, err
	}
	if session.SubjectID != "" && session.SubjectID != verified.SubjectID || session.WorkspaceID != "" && session.WorkspaceID != verified.WorkspaceID || strings.TrimSpace(session.User.ID) != "" && identity.SubjectID(session.User.ID) != verified.SubjectID {
		return identity.Principal{}, &identity.Error{Code: "identity.session_subject_mismatch"}
	}
	if session.AuthorizationRevision != "" && identity.AuthorizationRevision(session.AuthorizationRevision) != verified.AuthorizationRevision {
		return identity.Principal{}, &identity.Error{Code: "identity.authorization_revision_stale"}
	}
	requestIdentity := identity.RequestIdentity{Principal: identity.Principal{Known: true, WorkspaceID: string(verified.WorkspaceID), UserID: string(verified.SubjectID), AuthorizationRevision: string(verified.AuthorizationRevision)}, AccessToken: accessToken}
	bundle, err := resolver.binding.Authorization().ResolveAccess(ctx, identity.AccessBundleRequest{Identity: requestIdentity})
	if err != nil {
		return identity.Principal{}, err
	}
	if err := bundle.Validate(now); err != nil {
		return identity.Principal{}, err
	}
	if bundle.Subject.SubjectID != verified.SubjectID || bundle.Subject.WorkspaceID != verified.WorkspaceID || bundle.AuthorizationRevision != verified.AuthorizationRevision {
		return identity.Principal{}, &identity.Error{Code: "identity.access_bundle_subject_mismatch"}
	}
	resolved := principalFromResolution(verified, session, bundle)
	expiresAt := now.Add(resolver.maxTTL)
	if tokenExpiry := time.Unix(verified.ExpiresAt, 0); tokenExpiry.Before(expiresAt) {
		expiresAt = tokenExpiry
	}
	if bundle.ExpiresAt.Before(expiresAt) {
		expiresAt = bundle.ExpiresAt
	}
	resolver.mu.Lock()
	resolver.entries[cacheKey] = resolvedPrincipal{principal: clonePrincipal(resolved), expiresAt: expiresAt}
	for key, entry := range resolver.entries {
		if !now.Before(entry.expiresAt) {
			delete(resolver.entries, key)
		}
	}
	resolver.mu.Unlock()
	return resolved, nil
}

func (resolver *Resolver) Invalidate(subject identity.SubjectID, workspace identity.WorkspaceID) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	prefix := string(workspace) + "\x00" + string(subject) + "\x00"
	for key := range resolver.entries {
		if strings.HasPrefix(key, prefix) {
			delete(resolver.entries, key)
		}
	}
}

func resolverCacheKey(token authentication.VerifiedToken) string {
	return string(token.WorkspaceID) + "\x00" + string(token.SubjectID) + "\x00" + string(token.AuthorizationRevision) + "\x00" + token.TokenID
}

func principalFromResolution(token authentication.VerifiedToken, session authentication.SessionView, bundle identity.AccessBundle) identity.Principal {
	roleKey := strings.TrimSpace(session.DefaultRole)
	if roleKey == "" && len(session.Roles) > 0 {
		roleKey = session.Roles[0].Key
	}
	permissions := append([]string(nil), session.Permissions...)
	deniedPermissions := map[string]struct{}{}
	for _, grant := range bundle.FunctionGrants {
		permission := string(grant.Resource) + "." + string(grant.Action)
		if grant.Effect == identity.EffectDeny {
			deniedPermissions[strings.ToLower(permission)] = struct{}{}
			continue
		}
		if grant.Effect == identity.EffectAllow {
			permissions = append(permissions, permission)
		}
	}
	permissions = withoutDeniedPermissions(permissions, deniedPermissions)
	return identity.Principal{
		ContractVersion: identity.PrincipalContextContractVersion, Known: true,
		WorkspaceID: string(token.WorkspaceID), UserID: string(token.SubjectID), RoleKey: roleKey,
		AuthorizationRevision: string(token.AuthorizationRevision),
		OrgID:                 bundle.Subject.OrgID,
		OrgScopeIDs:           cloneStrings(bundle.Subject.OrgScopeIDs),
		ReportingScopeUserIDs: subjectIDsToStrings(bundle.Subject.ReportingScopeUserIDs),
		User:                  session.User, Roles: append([]identity.Role(nil), session.Roles...), Permissions: uniqueSortedStrings(permissions),
		MustChangePassword: session.MustChangePassword,
		AccessBundle:       &bundle,
	}
}

func subjectIDsToStrings(values []identity.SubjectID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func withoutDeniedPermissions(values []string, denied map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, blocked := denied[strings.ToLower(strings.TrimSpace(value))]; !blocked {
			result = append(result, value)
		}
	}
	return result
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func clonePrincipal(value identity.Principal) identity.Principal {
	value.OrgScopeIDs = cloneStrings(value.OrgScopeIDs)
	value.ReportingScopeUserIDs = cloneStrings(value.ReportingScopeUserIDs)
	value.Roles = append([]identity.Role(nil), value.Roles...)
	value.Permissions = cloneStrings(value.Permissions)
	if value.AccessBundle != nil {
		bundle := cloneAccessBundle(*value.AccessBundle)
		value.AccessBundle = &bundle
	}
	return value
}

func cloneAccessBundle(bundle identity.AccessBundle) identity.AccessBundle {
	bundle.Subject.OrgScopeIDs = cloneStrings(bundle.Subject.OrgScopeIDs)
	bundle.Subject.ReportingScopeUserIDs = append([]identity.SubjectID(nil), bundle.Subject.ReportingScopeUserIDs...)
	bundle.FunctionGrants = append([]identity.FunctionGrant(nil), bundle.FunctionGrants...)
	bundle.DataPolicies = append([]identity.DataPolicy(nil), bundle.DataPolicies...)
	for index := range bundle.DataPolicies {
		bundle.DataPolicies[index].Predicate = clonePredicate(bundle.DataPolicies[index].Predicate)
	}
	bundle.FieldPolicies = append([]identity.FieldPolicy(nil), bundle.FieldPolicies...)
	bundle.ReferencePolicies = append([]identity.ReferencePolicy(nil), bundle.ReferencePolicies...)
	for index := range bundle.ReferencePolicies {
		bundle.ReferencePolicies[index].DisplayFields = cloneStrings(bundle.ReferencePolicies[index].DisplayFields)
	}
	bundle.ExportPolicies = append([]identity.ExportPolicy(nil), bundle.ExportPolicies...)
	for index := range bundle.ExportPolicies {
		bundle.ExportPolicies[index].Fields = cloneStrings(bundle.ExportPolicies[index].Fields)
	}
	bundle.Guardrails = append([]identity.Guardrail(nil), bundle.Guardrails...)
	for index := range bundle.Guardrails {
		if bundle.Guardrails[index].Predicate != nil {
			predicate := clonePredicate(*bundle.Guardrails[index].Predicate)
			bundle.Guardrails[index].Predicate = &predicate
		}
	}
	return bundle
}

func clonePredicate(predicate identity.Predicate) identity.Predicate {
	predicate.Value = clonePolicyValue(predicate.Value)
	predicate.All = clonePredicates(predicate.All)
	predicate.Any = clonePredicates(predicate.Any)
	if predicate.Not != nil {
		nested := clonePredicate(*predicate.Not)
		predicate.Not = &nested
	}
	return predicate
}

func clonePredicates(values []identity.Predicate) []identity.Predicate {
	if values == nil {
		return nil
	}
	result := make([]identity.Predicate, len(values))
	for index := range values {
		result[index] = clonePredicate(values[index])
	}
	return result
}

func clonePolicyValue(value any) any {
	switch typed := value.(type) {
	case []any:
		result := make([]any, len(typed))
		for index := range typed {
			result[index] = clonePolicyValue(typed[index])
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, entry := range typed {
			result[key] = clonePolicyValue(entry)
		}
		return result
	case []string:
		return cloneStrings(typed)
	case map[string]string:
		result := make(map[string]string, len(typed))
		for key, entry := range typed {
			result[key] = entry
		}
		return result
	default:
		return value
	}
}

func cloneStrings(values []string) []string { return append([]string(nil), values...) }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

var _ identity.PrincipalAuthenticator = (*Resolver)(nil)
