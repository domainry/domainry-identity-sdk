package principal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
	identityprincipal "github.com/domainry/domainry-identity-sdk/authorization/principal"
)

func TestResolverDefaultsToFiveMinuteCacheWindow(t *testing.T) {
	binding := newResolverBinding()
	binding.author.bundle.ExpiresAt = binding.clock.now.Add(time.Hour)
	resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Clock: binding.clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Authenticate(t.Context(), "access"); err != nil {
		t.Fatal(err)
	}
	binding.clock.now = binding.clock.now.Add(identityprincipal.DefaultMaxCacheTTL - time.Second)
	if _, err := resolver.Authenticate(t.Context(), "access"); err != nil {
		t.Fatal(err)
	}
	if binding.auth.calls != 1 || binding.author.calls != 1 {
		t.Fatalf("cache expired before five minutes: session=%d bundle=%d", binding.auth.calls, binding.author.calls)
	}
	binding.clock.now = binding.clock.now.Add(2 * time.Second)
	if _, err := resolver.Authenticate(t.Context(), "access"); err != nil {
		t.Fatal(err)
	}
	if binding.auth.calls != 2 || binding.author.calls != 2 {
		t.Fatalf("cache did not expire after five minutes: session=%d bundle=%d", binding.auth.calls, binding.author.calls)
	}
}

func TestResolversCanSharePrincipalCache(t *testing.T) {
	binding := newResolverBinding()
	cache := identityprincipal.NewMemoryCache()
	first, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Clock: binding.clock, Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	second, err := identityprincipal.NewResolver(binding, identityprincipal.Options{Clock: binding.clock, Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Authenticate(t.Context(), "access"); err != nil {
		t.Fatal(err)
	}
	resolved, err := second.Authenticate(t.Context(), "access")
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.HasPermission("orders.read") {
		t.Fatalf("shared cache lost AccessBundle: %#v", resolved)
	}
	if binding.auth.calls != 1 || binding.author.calls != 1 {
		t.Fatalf("shared cache missed: session=%d bundle=%d", binding.auth.calls, binding.author.calls)
	}
}

type unavailableCache struct{ err error }

func (cache unavailableCache) Get(context.Context, identityprincipal.CacheKey, time.Time) (identityprincipal.CacheEntry, bool, error) {
	return identityprincipal.CacheEntry{}, false, cache.err
}
func (cache unavailableCache) Set(context.Context, identityprincipal.CacheKey, identityprincipal.CacheEntry, time.Time) error {
	return cache.err
}
func (cache unavailableCache) Delete(context.Context, identityprincipal.CacheKey) error {
	return cache.err
}
func (cache unavailableCache) Invalidate(context.Context, identity.SubjectID, identity.WorkspaceID) error {
	return cache.err
}

func TestResolverFallsBackToAuthoritativeBindingWhenCacheFails(t *testing.T) {
	binding := newResolverBinding()
	cacheErr := errors.New("cache unavailable")
	reported := 0
	resolver, err := identityprincipal.NewResolver(binding, identityprincipal.Options{
		Clock: binding.clock,
		Cache: unavailableCache{err: cacheErr},
		OnCacheError: func(err error) {
			if !errors.Is(err, cacheErr) {
				t.Fatalf("reported cache error=%v", err)
			}
			reported++
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.Authenticate(t.Context(), "access")
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.HasPermission("orders.read") || binding.auth.calls != 1 || binding.author.calls != 1 || reported != 2 {
		t.Fatalf("principal=%#v session=%d bundle=%d reported=%d", resolved, binding.auth.calls, binding.author.calls, reported)
	}
}
