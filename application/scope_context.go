package application

import (
	"context"

	identity "github.com/domainry/domainry-identity-sdk"
)

type scopeContextKey struct{}

// WithScope carries the application identity established by a Binding or an
// authenticated remote transport. Business callers do not construct this
// scope for individual Identity operations.
func WithScope(ctx context.Context, scope identity.ApplicationScope) context.Context {
	if ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, scopeContextKey{}, scope)
}

// ScopeFromContext returns the application identity established at the SDK
// boundary.
func ScopeFromContext(ctx context.Context) (identity.ApplicationScope, bool) {
	if ctx == nil {
		return identity.ApplicationScope{}, false
	}
	scope, ok := ctx.Value(scopeContextKey{}).(identity.ApplicationScope)
	return scope, ok && scope.WorkspaceID.Valid() && scope.ApplicationKey.Valid()
}
