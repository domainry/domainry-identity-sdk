package application

import (
	"context"
	"errors"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

type countedWorkspaceResolver struct {
	calls  int
	denied bool
}

func (r *countedWorkspaceResolver) ResolveWorkspace(_ context.Context, input identity.WorkspaceID) (identity.WorkspaceID, error) {
	r.calls++
	if r.denied {
		return "", errors.New("workspace unavailable")
	}
	return input, nil
}

func TestWorkspaceResolutionScopeIsBoundedToBindingWorkspaceAndLifetime(t *testing.T) {
	r := &countedWorkspaceResolver{}
	b := &binding{resolver: r}
	ctx, end := BeginWorkspaceResolutionScope(t.Context())
	for i := 0; i < 48; i++ {
		if _, err := b.resolveWorkspace(ctx, "workspace-1"); err != nil {
			t.Fatal(err)
		}
	}
	if r.calls != 1 {
		t.Fatal("repeated installation IO", r.calls)
	}
	if _, err := b.resolveWorkspace(ctx, "workspace-2"); err != nil || r.calls != 2 {
		t.Fatal("cache crossed workspaces", err, r.calls)
	}
	other := &binding{resolver: r}
	if _, err := other.resolveWorkspace(ctx, "workspace-1"); err != nil || r.calls != 3 {
		t.Fatal("cache crossed bindings", err, r.calls)
	}
	end()
	r.denied = true
	for _, check := range []context.Context{ctx, t.Context()} {
		if _, err := b.resolveWorkspace(check, "workspace-1"); err == nil {
			t.Fatal("closed scope hid disabled installation")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := b.scopedWorkspaceResolution(cancelled, "workspace-1"); !errors.Is(err, context.Canceled) {
		t.Fatal("scope hid cancellation", err)
	}
}

func TestWorkspaceReadScopeRejectsInstallationDisabledDuringRead(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		r := &countedWorkspaceResolver{}
		b := &binding{resolver: r}
		ctx, finish := BeginWorkspaceReadScope(t.Context())
		for i := 0; i < 48; i++ {
			if _, err := b.resolveWorkspace(ctx, "workspace-1"); err != nil {
				t.Fatal(err)
			}
		}
		r.denied = revoked
		if err := finish(); (err != nil) != revoked || r.calls != 2 {
			t.Fatal("installation was not freshly checked before release", revoked, r.calls, err)
		}
		_, _ = b.resolveWorkspace(ctx, "workspace-1")
		if r.calls != 3 {
			t.Fatal("read scope survived its finish boundary")
		}
	}
}
