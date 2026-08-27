package remote

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

type jwksVerifierConfig struct {
	Issuer   string
	Audience string
	Fetch    func(context.Context, any) error
	CacheTTL time.Duration
	Now      func() time.Time
}

type jwksVerifier struct {
	issuer, audience string
	fetch            func(context.Context, any) error
	cacheTTL         time.Duration
	now              func() time.Time
	mu               sync.RWMutex
	refreshMu        sync.Mutex
	keys             map[string]ed25519.PublicKey
	expiresAt        time.Time
}

func newJWKSVerifier(config jwksVerifierConfig) (*jwksVerifier, error) {
	issuer, audience := strings.TrimSpace(config.Issuer), strings.TrimSpace(config.Audience)
	if issuer == "" || audience == "" || config.Fetch == nil {
		return nil, &identity.Error{Code: "identity.jwks_configuration_invalid"}
	}
	if config.CacheTTL <= 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &jwksVerifier{issuer: issuer, audience: audience, fetch: config.Fetch, cacheTTL: config.CacheTTL, now: config.Now, keys: map[string]ed25519.PublicKey{}}, nil
}

func (verifier *jwksVerifier) Verify(ctx context.Context, request identity.VerifyTokenRequest) (identity.VerifiedToken, error) {
	token := strings.TrimSpace(request.AccessToken)
	if token == "" || request.Issuer != "" && request.Issuer != verifier.issuer || request.Audience != "" && string(request.Audience) != verifier.audience {
		return identity.VerifiedToken{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "identity.token_invalid"}
	}
	header, claims, signingInput, signature, err := decodeJWT(token)
	if err != nil || header.Algorithm != "EdDSA" || header.Type != "JWT" || strings.TrimSpace(header.KeyID) == "" {
		return identity.VerifiedToken{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "identity.token_invalid", Cause: err}
	}
	key, ok := verifier.key(header.KeyID)
	if !ok || verifier.cacheExpired() {
		if err := verifier.refresh(ctx, header.KeyID); err != nil {
			return identity.VerifiedToken{}, err
		}
		key, ok = verifier.key(header.KeyID)
	}
	if !ok || !ed25519.Verify(key, []byte(signingInput), signature) {
		return identity.VerifiedToken{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "identity.token_invalid"}
	}
	if claims.Issuer != verifier.issuer || string(claims.Audience) != verifier.audience || !claims.SubjectID.Valid() || !claims.WorkspaceID.Valid() || !claims.SessionID.Valid() || !claims.AuthorizationRevision.Valid() || strings.TrimSpace(claims.TokenID) == "" {
		return identity.VerifiedToken{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "identity.token_claims_invalid"}
	}
	now := verifier.now().UTC().Unix()
	if claims.ExpiresAt <= now || claims.IssuedAt > now+60 {
		return identity.VerifiedToken{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "identity.token_expired"}
	}
	return claims, nil
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

func decodeJWT(token string) (jwtHeader, identity.VerifiedToken, string, []byte, error) {
	if len(token) > 16<<10 {
		return jwtHeader{}, identity.VerifiedToken{}, "", nil, errors.New("token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtHeader{}, identity.VerifiedToken{}, "", nil, errors.New("token format")
	}
	headerBytes, headerErr := base64.RawURLEncoding.DecodeString(parts[0])
	payloadBytes, payloadErr := base64.RawURLEncoding.DecodeString(parts[1])
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[2])
	if headerErr != nil || payloadErr != nil || signatureErr != nil || len(signature) != ed25519.SignatureSize {
		return jwtHeader{}, identity.VerifiedToken{}, "", nil, errors.New("token encoding")
	}
	var header jwtHeader
	var wire struct {
		Issuer         string                         `json:"iss"`
		Audience       identity.ApplicationKey        `json:"aud"`
		Subject        identity.SubjectID             `json:"sub"`
		Tenant         identity.TenantID              `json:"tenant_id"`
		TenantShort    identity.TenantID              `json:"tid"`
		Workspace      identity.WorkspaceID           `json:"workspace_id"`
		WorkspaceShort identity.WorkspaceID           `json:"wid"`
		Session        identity.SessionID             `json:"sid"`
		Revision       identity.AuthorizationRevision `json:"authz_revision"`
		RevisionShort  identity.AuthorizationRevision `json:"arv"`
		AuthTime       int64                          `json:"auth_time"`
		Methods        []string                       `json:"amr"`
		Assurance      string                         `json:"acr"`
		IssuedAt       int64                          `json:"iat"`
		ExpiresAt      int64                          `json:"exp"`
		TokenID        string                         `json:"jti"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || json.Unmarshal(payloadBytes, &wire) != nil {
		return jwtHeader{}, identity.VerifiedToken{}, "", nil, errors.New("token json")
	}
	if wire.Tenant == "" {
		wire.Tenant = wire.TenantShort
	}
	if wire.Workspace == "" {
		wire.Workspace = wire.WorkspaceShort
	}
	if wire.Revision == "" {
		wire.Revision = wire.RevisionShort
	}
	claims := identity.VerifiedToken{Issuer: wire.Issuer, Audience: wire.Audience, SubjectID: wire.Subject, TenantID: wire.Tenant, WorkspaceID: wire.Workspace, SessionID: wire.Session, AuthorizationRevision: wire.Revision, AuthenticationTime: wire.AuthTime, AuthenticationMethods: wire.Methods, AssuranceLevel: wire.Assurance, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, TokenID: wire.TokenID}
	return header, claims, parts[0] + "." + parts[1], signature, nil
}

type jwksDocument struct {
	Keys []struct {
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Curve     string `json:"crv"`
		X         string `json:"x"`
	} `json:"keys"`
}

func (verifier *jwksVerifier) refresh(ctx context.Context, requiredKeyID string) error {
	verifier.refreshMu.Lock()
	defer verifier.refreshMu.Unlock()
	if _, found := verifier.key(requiredKeyID); found && !verifier.cacheExpired() {
		return nil
	}
	var document jwksDocument
	if err := verifier.fetch(ctx, &document); err != nil {
		return &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.jwks_unavailable", Cause: err}
	}
	keys := map[string]ed25519.PublicKey{}
	for _, item := range document.Keys {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(item.X)
		if item.KeyType != "OKP" || item.Use != "sig" || item.Algorithm != "EdDSA" || item.Curve != "Ed25519" || strings.TrimSpace(item.KeyID) == "" || decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
			return &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.jwks_invalid", Cause: decodeErr}
		}
		if _, duplicate := keys[item.KeyID]; duplicate {
			return &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.jwks_invalid"}
		}
		keys[item.KeyID] = append(ed25519.PublicKey(nil), decoded...)
	}
	if len(keys) == 0 {
		return &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.jwks_empty"}
	}
	verifier.mu.Lock()
	verifier.keys, verifier.expiresAt = keys, verifier.now().Add(verifier.cacheTTL)
	verifier.mu.Unlock()
	return nil
}

func (verifier *jwksVerifier) key(id string) (ed25519.PublicKey, bool) {
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()
	key, ok := verifier.keys[id]
	return key, ok
}
func (verifier *jwksVerifier) cacheExpired() bool {
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()
	return !verifier.expiresAt.After(verifier.now())
}

var _ identity.TokenVerifier = (*jwksVerifier)(nil)
