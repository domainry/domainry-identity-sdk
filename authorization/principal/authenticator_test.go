package principal_test

import (
	"context"
	"sync"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
	identityprincipal "github.com/domainry/domainry-identity-sdk/authorization/principal"
)

func TestExternalAuthenticatorUsesInjectedCredentialCache(t *testing.T) {
	binding := newResolverBinding()
	delegate := &countingAuthenticator{principal: externalPrincipal(binding.author.bundle)}
	external := &externalAuthenticatorBinding{resolverBinding: binding, authenticator: delegate}
	cache := identityprincipal.NewMemoryCache()
	first, err := identityprincipal.NewAuthenticator(external, identityprincipal.Options{Clock: binding.clock, MaxCacheTTL: time.Minute, Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	second, err := identityprincipal.NewAuthenticator(external, identityprincipal.Options{Clock: binding.clock, MaxCacheTTL: time.Minute, Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := first.Authenticate(t.Context(), "opaque-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	resolved.AccessBundle.FunctionGrants[0].Action = "delete"
	resolved, err = second.Authenticate(t.Context(), "opaque-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if delegate.CallCount() != 1 {
		t.Fatalf("authoritative authenticator calls=%d want=1", delegate.CallCount())
	}
	if !resolved.HasPermission("orders.read") {
		t.Fatal("shared credential cache lost or exposed a mutable AccessBundle")
	}

	binding.clock.now = binding.clock.now.Add(time.Minute + time.Second)
	if _, err := second.Authenticate(t.Context(), "opaque-secret-token"); err != nil {
		t.Fatal(err)
	}
	if delegate.CallCount() != 2 {
		t.Fatalf("expired credential snapshot calls=%d want=2", delegate.CallCount())
	}
}

func TestExternalAuthenticatorWithoutInjectedCachePreservesDelegate(t *testing.T) {
	binding := newResolverBinding()
	delegate := &countingAuthenticator{principal: externalPrincipal(binding.author.bundle)}
	external := &externalAuthenticatorBinding{resolverBinding: binding, authenticator: delegate}
	authenticator, err := identityprincipal.NewAuthenticator(external, identityprincipal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := authenticator.Authenticate(t.Context(), "opaque-secret-token"); err != nil {
			t.Fatal(err)
		}
	}
	if delegate.CallCount() != 2 {
		t.Fatalf("uninjected cache changed external authenticator calls=%d", delegate.CallCount())
	}
}

func TestExternalAuthenticatorCollapsesConcurrentCacheMisses(t *testing.T) {
	binding := newResolverBinding()
	release := make(chan struct{})
	delegate := &countingAuthenticator{principal: externalPrincipal(binding.author.bundle), release: release}
	external := &externalAuthenticatorBinding{resolverBinding: binding, authenticator: delegate}
	authenticator, err := identityprincipal.NewAuthenticator(external, identityprincipal.Options{Clock: binding.clock, Cache: identityprincipal.NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	const requests = 8
	errors := make(chan error, requests)
	var group sync.WaitGroup
	for range requests {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := authenticator.Authenticate(context.Background(), "same-opaque-token")
			errors <- err
		}()
	}
	for delegate.CallCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if delegate.CallCount() != 1 {
		t.Fatalf("concurrent authoritative calls=%d want=1", delegate.CallCount())
	}
}

type externalAuthenticatorBinding struct {
	*resolverBinding
	authenticator identity.PrincipalAuthenticator
}

func (binding *externalAuthenticatorBinding) PrincipalAuthenticator() identity.PrincipalAuthenticator {
	return binding.authenticator
}

type countingAuthenticator struct {
	mutex     sync.Mutex
	calls     int
	principal identity.Principal
	release   <-chan struct{}
}

func (authenticator *countingAuthenticator) Authenticate(ctx context.Context, _ string) (identity.Principal, error) {
	authenticator.mutex.Lock()
	authenticator.calls++
	authenticator.mutex.Unlock()
	if authenticator.release != nil {
		select {
		case <-ctx.Done():
			return identity.Principal{}, ctx.Err()
		case <-authenticator.release:
		}
	}
	return authenticator.principal, nil
}

func (authenticator *countingAuthenticator) CallCount() int {
	authenticator.mutex.Lock()
	defer authenticator.mutex.Unlock()
	return authenticator.calls
}

func externalPrincipal(bundle identity.AccessBundle) identity.Principal {
	return identity.Principal{
		ContractVersion: identity.PrincipalContextContractVersion,
		Known:           true, WorkspaceID: string(bundle.Subject.WorkspaceID), UserID: string(bundle.Subject.SubjectID),
		AuthorizationRevision: string(bundle.AuthorizationRevision), AccessBundle: &bundle,
	}
}
