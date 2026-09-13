package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestRemoteVerifierRequiresWorkspace(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	verifier, err := newJWKSVerifier(jwksVerifierConfig{Issuer: "issuer", Audience: "app", Now: func() time.Time { return now }, Fetch: func(context.Context, any) error { t.Fatal("unexpected JWKS refresh"); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	verifier.keys["key"], verifier.expiresAt = public, now.Add(time.Hour)
	for _, tc := range []struct {
		name, workspace string
		allowed         bool
	}{
		{"current", "workspace-a", true}, {"missing workspace", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]any{"iss": "issuer", "aud": "app", "sub": "user", "workspace_id": tc.workspace, "sid": "session", "authz_revision": "revision", "jti": "token", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"key"}`))
			signed := header + "." + base64.RawURLEncoding.EncodeToString(payload)
			token := signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signed)))
			_, err := verifier.Verify(t.Context(), identity.VerifyTokenRequest{AccessToken: token})
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v error=%v", tc.allowed, err)
			}
		})
	}
}
