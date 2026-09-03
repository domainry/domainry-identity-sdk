package principal

import (
	"context"
	"sync"
	"time"

	identity "github.com/domainry/domainry-identity-sdk/authorization"
)

// DefaultMaxCacheTTL bounds how long a resolved session and authorization
// snapshot may be reused without consulting the authoritative Identity binding.
const DefaultMaxCacheTTL = 5 * time.Minute

// CacheKey isolates cached principals by tenant scope, subject, authorization
// revision, and token ID. Access tokens are deliberately never cache keys.
type CacheKey struct {
	WorkspaceID           identity.WorkspaceID
	SubjectID             identity.SubjectID
	AuthorizationRevision identity.AuthorizationRevision
	TokenID               string
}

// CacheEntry is the non-secret, bounded principal snapshot stored by a Cache.
type CacheEntry struct {
	Principal identity.Principal
	ExpiresAt time.Time
}

// Cache is an optional shared storage boundary for resolved principals.
// Implementations are acceleration layers only; Resolver remains responsible
// for validating every returned snapshot before it is authorized.
type Cache interface {
	Get(context.Context, CacheKey, time.Time) (CacheEntry, bool, error)
	Set(context.Context, CacheKey, CacheEntry, time.Time) error
	Delete(context.Context, CacheKey) error
	Invalidate(context.Context, identity.SubjectID, identity.WorkspaceID) error
}

type memoryCache struct {
	mu      sync.RWMutex
	entries map[CacheKey]CacheEntry
}

// NewMemoryCache constructs the default process-local principal cache.
func NewMemoryCache() Cache {
	return &memoryCache{entries: map[CacheKey]CacheEntry{}}
}

func (cache *memoryCache) Get(ctx context.Context, key CacheKey, now time.Time) (CacheEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return CacheEntry{}, false, err
	}
	cache.mu.RLock()
	entry, found := cache.entries[key]
	cache.mu.RUnlock()
	if !found {
		return CacheEntry{}, false, nil
	}
	if !now.Before(entry.ExpiresAt) {
		cache.mu.Lock()
		if current, exists := cache.entries[key]; exists && !now.Before(current.ExpiresAt) {
			delete(cache.entries, key)
		}
		cache.mu.Unlock()
		return CacheEntry{}, false, nil
	}
	entry.Principal = clonePrincipal(entry.Principal)
	return entry, true, nil
}

func (cache *memoryCache) Set(ctx context.Context, key CacheKey, entry CacheEntry, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.entries[key] = CacheEntry{Principal: clonePrincipal(entry.Principal), ExpiresAt: entry.ExpiresAt}
	for candidate, cached := range cache.entries {
		if !now.Before(cached.ExpiresAt) {
			delete(cache.entries, candidate)
		}
	}
	return nil
}

func (cache *memoryCache) Delete(ctx context.Context, key CacheKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cache.mu.Lock()
	delete(cache.entries, key)
	cache.mu.Unlock()
	return nil
}

func (cache *memoryCache) Invalidate(ctx context.Context, subject identity.SubjectID, workspace identity.WorkspaceID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for key := range cache.entries {
		if key.SubjectID == subject && key.WorkspaceID == workspace {
			delete(cache.entries, key)
		}
	}
	return nil
}

func (cache *memoryCache) Close() error {
	cache.mu.Lock()
	clear(cache.entries)
	cache.mu.Unlock()
	return nil
}

var _ Cache = (*memoryCache)(nil)
