package application

import (
	"context"
	"errors"
	"sync"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

type catalogResolver map[identity.WorkspaceID]identity.WorkspaceID

func (catalog catalogResolver) ResolveWorkspace(_ context.Context, ref identity.WorkspaceID) (identity.WorkspaceID, error) {
	if id := catalog[ref]; id != "" {
		return id, nil
	}
	return "", errors.New("not active in installation")
}

type workspaceTestBinding struct {
	*applicationBindingTestBase
	login  identity.Authentication
	tokens identity.TokenVerifier
}

func (b workspaceTestBinding) Authentication() identity.Authentication { return b.login }
func (b workspaceTestBinding) Tokens() identity.TokenVerifier          { return b.tokens }

type workspaceTestAuthentication struct {
	identity.Authentication
	wrongSession bool
	wrongToken   bool
}

func (a workspaceTestAuthentication) LoginWithPassword(_ context.Context, request identity.PasswordLoginRequest) (identity.AuthSession, error) {
	id := request.WorkspaceID
	if a.wrongSession {
		id = "physical-a"
	}
	token := string(id)
	if a.wrongToken {
		token = "physical-a"
	}
	return identity.AuthSession{WorkspaceID: string(id), AccessToken: token}, nil
}

type workspaceTestTokens struct{}

func (workspaceTestTokens) Verify(_ context.Context, request identity.VerifyTokenRequest) (identity.VerifiedToken, error) {
	return identity.VerifiedToken{WorkspaceID: identity.WorkspaceID(request.AccessToken), Audience: "runtime"}, nil
}

func TestTrustedWorkspaceResolverPreservesBindingAndChecksSessionAndToken(t *testing.T) {
	app := identity.ApplicationRef{WorkspaceID: "physical-a", ApplicationKey: "runtime"}
	catalog := catalogResolver{"public-a": "physical-a", "public-b": "physical-b", "physical-a": "physical-a", "physical-b": "physical-b"}
	delegate := workspaceTestBinding{&applicationBindingTestBase{}, workspaceTestAuthentication{}, workspaceTestTokens{}}
	single, err := Bind(delegate, app)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := single.Authentication().LoginWithPassword(t.Context(), identity.PasswordLoginRequest{WorkspaceID: "physical-b"}); err == nil {
		t.Fatal("single binding accepted B")
	}
	if _, err := single.Authentication().LoginWithPassword(t.Context(), identity.PasswordLoginRequest{}); err != nil {
		t.Fatal("single binding lost default", err)
	}
	multi, err := BindWithWorkspaceResolver(delegate, app, catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []identity.WorkspaceID{"", "unknown", "suspended", "foreign"} {
		_, err := multi.Authentication().LoginWithPassword(t.Context(), identity.PasswordLoginRequest{WorkspaceID: ref})
		var failure *identity.Error
		if !errors.As(err, &failure) || failure.Code != "auth.invalid_credentials" {
			t.Fatalf("%q denial=%v", ref, err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			for ref, expected := range catalog {
				session, err := multi.Authentication().LoginWithPassword(t.Context(), identity.PasswordLoginRequest{WorkspaceID: ref})
				if err != nil || session.WorkspaceID != string(expected) {
					t.Errorf("scope %q failed: %v", ref, err)
				}
			}
		})
	}
	wg.Wait()
	for _, auth := range []workspaceTestAuthentication{{wrongSession: true}, {wrongToken: true}} {
		broken, err := BindWithWorkspaceResolver(workspaceTestBinding{&applicationBindingTestBase{}, auth, workspaceTestTokens{}}, app, catalog)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := broken.Authentication().LoginWithPassword(t.Context(), identity.PasswordLoginRequest{WorkspaceID: "public-b"}); err == nil {
			t.Fatal("accepted mismatched outcome")
		}
	}
	if _, err := multi.Authentication().LoginWithPassword(t.Context(), identity.PasswordLoginRequest{WorkspaceID: "public-b", ApplicationKey: "other"}); err == nil {
		t.Fatal("accepted another application")
	}
	if _, err := multi.Tokens().Verify(t.Context(), identity.VerifyTokenRequest{AccessToken: "foreign"}); err == nil {
		t.Fatal("accepted foreign token")
	}
}
