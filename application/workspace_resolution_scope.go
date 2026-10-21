package application

import (
	"context"
	"sync"

	identity "github.com/domainry/domainry-identity-sdk"
)

type workspaceResolutionScopeKey struct{}
type workspaceResolutionKey struct {
	binding *binding
	input   identity.WorkspaceID
}
type workspaceResolutionScope struct {
	mu     sync.Mutex
	closed bool
	values map[workspaceResolutionKey]identity.WorkspaceID
}

// BeginWorkspaceResolutionScope reuses successful installation/catalog reads
// only inside one synchronous host-owned evaluation. End before executing an
// operation or waiting on external IO. It never changes token/session checks.
func BeginWorkspaceResolutionScope(ctx context.Context) (context.Context, func()) {
	memo := &workspaceResolutionScope{values: map[workspaceResolutionKey]identity.WorkspaceID{}}
	return context.WithValue(ctx, workspaceResolutionScopeKey{}, memo), func() {
		memo.mu.Lock()
		defer memo.mu.Unlock()
		memo.closed, memo.values = true, nil
	}
}

// BeginWorkspaceReadScope also verifies each reused installation at the end of
// a read-only evaluation. No data may be released when finish reports a change.
func BeginWorkspaceReadScope(ctx context.Context) (context.Context, func() error) {
	ctx, _ = BeginWorkspaceResolutionScope(ctx)
	memo := ctx.Value(workspaceResolutionScopeKey{}).(*workspaceResolutionScope)
	return ctx, func() error {
		memo.mu.Lock()
		if memo.closed {
			memo.mu.Unlock()
			return nil
		}
		values := memo.values
		memo.closed, memo.values = true, nil
		memo.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		for key, previous := range values {
			fresh, err := key.binding.resolver.ResolveWorkspace(ctx, key.input)
			if err != nil || !fresh.Valid() || fresh != previous {
				return scopeError(identity.ErrorClassForbidden, "auth.invalid_credentials")
			}
		}
		return ctx.Err()
	}
}

func (value *binding) scopedWorkspaceResolution(ctx context.Context, input identity.WorkspaceID) (identity.WorkspaceID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	memo, _ := ctx.Value(workspaceResolutionScopeKey{}).(*workspaceResolutionScope)
	if memo == nil {
		return value.resolver.ResolveWorkspace(ctx, input)
	}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if memo.closed {
		return value.resolver.ResolveWorkspace(ctx, input)
	}
	key := workspaceResolutionKey{binding: value, input: input}
	if resolved, found := memo.values[key]; found {
		return resolved, nil
	}
	resolved, err := value.resolver.ResolveWorkspace(ctx, input)
	if err == nil && resolved.Valid() && len(memo.values) < 128 {
		memo.values[key] = resolved
	}
	return resolved, err
}
