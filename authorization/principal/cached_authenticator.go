package principal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	identity "github.com/domainry/domainry-identity-sdk/authorization"
)

type authenticationCall struct {
	done      chan struct{}
	principal identity.Principal
	err       error
}

type cachedAuthenticator struct {
	delegate     identity.PrincipalAuthenticator
	clock        Clock
	maxTTL       time.Duration
	cache        CredentialCache
	onCacheError func(error)

	mutex    sync.Mutex
	inflight map[CredentialCacheKey]*authenticationCall
}

func newCachedAuthenticator(delegate identity.PrincipalAuthenticator, options Options, cache CredentialCache) identity.PrincipalAuthenticator {
	clock := options.Clock
	if clock == nil {
		clock = systemClock{}
	}
	maxTTL := options.MaxCacheTTL
	if maxTTL <= 0 {
		maxTTL = DefaultMaxCacheTTL
	}
	return &cachedAuthenticator{
		delegate: delegate, clock: clock, maxTTL: maxTTL, cache: cache,
		onCacheError: options.OnCacheError, inflight: map[CredentialCacheKey]*authenticationCall{},
	}
}

func (authenticator *cachedAuthenticator) Authenticate(ctx context.Context, credential string) (identity.Principal, error) {
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return authenticator.delegate.Authenticate(ctx, credential)
	}
	key := credentialCacheKey(credential)
	now := authenticator.clock.Now()
	entry, found, err := authenticator.cache.GetCredential(ctx, key, now)
	if err != nil {
		authenticator.handleCacheError(err)
	} else if found {
		if cachedOpaquePrincipalValid(entry, now) {
			return clonePrincipal(entry.Principal), nil
		}
		if err := authenticator.cache.DeleteCredential(ctx, key); err != nil {
			authenticator.handleCacheError(err)
		}
	}

	authenticator.mutex.Lock()
	if call, exists := authenticator.inflight[key]; exists {
		authenticator.mutex.Unlock()
		select {
		case <-ctx.Done():
			return identity.Principal{}, ctx.Err()
		case <-call.done:
			return clonePrincipal(call.principal), call.err
		}
	}
	call := &authenticationCall{done: make(chan struct{})}
	authenticator.inflight[key] = call
	authenticator.mutex.Unlock()

	principal, authenticateErr := authenticator.delegate.Authenticate(ctx, credential)
	if authenticateErr == nil && validOpaquePrincipal(principal, now) {
		expiresAt := now.Add(authenticator.maxTTL)
		if principal.AccessBundle.ExpiresAt.Before(expiresAt) {
			expiresAt = principal.AccessBundle.ExpiresAt
		}
		if expiresAt.After(now) {
			if err := authenticator.cache.SetCredential(ctx, key, CacheEntry{Principal: clonePrincipal(principal), ExpiresAt: expiresAt}, now); err != nil {
				authenticator.handleCacheError(err)
			}
		}
	}

	authenticator.mutex.Lock()
	call.principal = clonePrincipal(principal)
	call.err = authenticateErr
	delete(authenticator.inflight, key)
	close(call.done)
	authenticator.mutex.Unlock()
	return principal, authenticateErr
}

func (authenticator *cachedAuthenticator) handleCacheError(err error) {
	if err != nil && authenticator.onCacheError != nil {
		authenticator.onCacheError(err)
	}
}

func credentialCacheKey(credential string) CredentialCacheKey {
	digest := sha256.Sum256([]byte(credential))
	return CredentialCacheKey(hex.EncodeToString(digest[:]))
}

func cachedOpaquePrincipalValid(entry CacheEntry, now time.Time) bool {
	return now.Before(entry.ExpiresAt) && validOpaquePrincipal(entry.Principal, now)
}

func validOpaquePrincipal(principal identity.Principal, now time.Time) bool {
	if principal.ContractVersion != identity.PrincipalContextContractVersion || !principal.Known || strings.TrimSpace(principal.WorkspaceID) == "" || strings.TrimSpace(principal.UserID) == "" || principal.AccessBundle == nil {
		return false
	}
	bundle := principal.AccessBundle
	if err := bundle.Validate(now); err != nil {
		return false
	}
	return string(bundle.Subject.WorkspaceID) == principal.WorkspaceID &&
		string(bundle.Subject.SubjectID) == principal.UserID &&
		string(bundle.AuthorizationRevision) == principal.AuthorizationRevision
}

var _ identity.PrincipalAuthenticator = (*cachedAuthenticator)(nil)
