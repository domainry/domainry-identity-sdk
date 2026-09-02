// Package contracttest provides the deployment-parity suite shared by module
// and SaaS Identity bindings.
package contracttest

import (
	"context"
	"testing"
	"time"

	identity "github.com/domainry/domainry-identity-sdk"
)

type Fixture struct {
	Binding        identity.Binding
	TenantID       identity.TenantID
	WorkspaceID    identity.WorkspaceID
	ApplicationKey identity.ApplicationKey
	Login          string
	Password       string
	Resource       identity.ResourceType
	Action         identity.Action
	DataAction     identity.DataAction
	DataAllowed    bool
}

func Run(t *testing.T, fixture Fixture) {
	t.Helper()
	if fixture.Binding == nil {
		t.Fatal("Identity binding is required")
	}
	if fixture.Binding.Authentication() == nil || fixture.Binding.Tokens() == nil || fixture.Binding.Authorization() == nil || fixture.Binding.Principals() == nil || fixture.Binding.Directory() == nil || fixture.Binding.Applications() == nil || fixture.Binding.Permissions() == nil || fixture.Binding.Credentials() == nil {
		t.Fatal("Identity binding does not expose the complete Runtime contract")
	}
	if !fixture.ApplicationKey.Valid() {
		t.Fatal("Identity application key is required")
	}
	descriptor := fixture.Binding.Descriptor()
	if descriptor.ProtocolVersion != identity.CurrentProtocolVersion || descriptor.BundleVersion != identity.CurrentPolicyBundleVersion || descriptor.AuthorizationVersion != identity.AuthorizationContractVersionV1 {
		t.Fatalf("unsupported descriptor: %+v", descriptor)
	}
	if identity.ApplicationKey(descriptor.Audience) != fixture.ApplicationKey || descriptor.Issuer == "" {
		t.Fatalf("binding trust scope does not match fixture application: descriptor=%+v application=%q", descriptor, fixture.ApplicationKey)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	providers, err := fixture.Binding.Authentication().Providers(ctx, identity.ProviderQuery{TenantID: fixture.TenantID, WorkspaceID: fixture.WorkspaceID})
	if err != nil || len(providers) == 0 {
		t.Fatalf("providers=%+v err=%v", providers, err)
	}
	session, err := fixture.Binding.Authentication().LoginWithPassword(ctx, identity.PasswordLoginRequest{TenantID: fixture.TenantID, WorkspaceID: fixture.WorkspaceID, ApplicationKey: fixture.ApplicationKey, Login: fixture.Login, Password: fixture.Password})
	if err != nil || session.AccessToken == "" || session.RefreshToken == "" || session.SessionID == "" {
		t.Fatalf("login session=%+v err=%v", session, err)
	}
	verified, err := fixture.Binding.Tokens().Verify(ctx, identity.VerifyTokenRequest{AccessToken: session.AccessToken, Issuer: descriptor.Issuer, Audience: fixture.ApplicationKey})
	if err != nil || verified.WorkspaceID != fixture.WorkspaceID || verified.SubjectID == "" || verified.Audience != fixture.ApplicationKey {
		t.Fatalf("verified token=%+v err=%v", verified, err)
	}
	if _, err := fixture.Binding.Tokens().Verify(ctx, identity.VerifyTokenRequest{AccessToken: session.AccessToken, Issuer: descriptor.Issuer, Audience: fixture.ApplicationKey + "-other"}); err == nil {
		t.Fatal("token verifier accepted a different application audience")
	}
	view, err := fixture.Binding.Authentication().CurrentSession(ctx, identity.CurrentSessionRequest{AccessToken: session.AccessToken})
	if err != nil || view.WorkspaceID != verified.WorkspaceID || view.SubjectID != verified.SubjectID || view.SessionID != verified.SessionID {
		t.Fatalf("current session=%+v token=%+v err=%v", view, verified, err)
	}
	rotated, err := fixture.Binding.Authentication().RefreshSession(ctx, identity.RefreshRequest{
		TenantID: fixture.TenantID, WorkspaceID: fixture.WorkspaceID, ApplicationKey: fixture.ApplicationKey, SessionID: session.SessionID, RefreshToken: session.RefreshToken,
	})
	if err != nil || rotated.AccessToken == "" || rotated.RefreshToken == "" || rotated.RefreshToken == session.RefreshToken || rotated.SessionID != session.SessionID {
		t.Fatalf("rotated session=%+v err=%v", rotated, err)
	}
	verified, err = fixture.Binding.Tokens().Verify(ctx, identity.VerifyTokenRequest{AccessToken: rotated.AccessToken, Issuer: descriptor.Issuer, Audience: fixture.ApplicationKey})
	if err != nil || verified.WorkspaceID != fixture.WorkspaceID || verified.SubjectID == "" || verified.SessionID != rotated.SessionID || verified.Audience != fixture.ApplicationKey {
		t.Fatalf("rotated token=%+v err=%v", verified, err)
	}
	session = rotated
	principal := identity.Principal{ContractVersion: identity.PrincipalContextContractVersion, Known: true, WorkspaceID: string(verified.WorkspaceID), UserID: string(verified.SubjectID), AuthorizationRevision: string(verified.AuthorizationRevision)}
	requestIdentity := identity.RequestIdentity{Principal: principal, AccessToken: session.AccessToken}
	bundle, err := fixture.Binding.Authorization().ResolveAccess(ctx, identity.AccessBundleRequest{Identity: requestIdentity, ResourceType: fixture.Resource, Action: fixture.Action})
	if err != nil || bundle.AuthorizationRevision != verified.AuthorizationRevision {
		t.Fatalf("bundle=%+v err=%v", bundle, err)
	}
	if !fixture.DataAction.Valid() {
		t.Fatal("contract fixture data action is required")
	}
	decision, err := fixture.Binding.Authorization().Reauthorize(ctx, identity.DecisionRequest{
		Identity: requestIdentity,
		Access:   identity.AccessRequest{ObjectKey: string(fixture.Resource), Action: string(fixture.Action), DataAction: fixture.DataAction, RecordID: "contract-record"},
		Facts:    identity.ResourceFacts{"id": "contract-record"},
	})
	if err != nil || decision.Allowed != fixture.DataAllowed || decision.AuthorizationRevision != string(bundle.AuthorizationRevision) {
		t.Fatalf("reauthorization decision=%+v err=%v", decision, err)
	}
	denied, err := fixture.Binding.Authorization().Reauthorize(ctx, identity.DecisionRequest{
		Identity: requestIdentity,
		Access:   identity.AccessRequest{ObjectKey: string(fixture.Resource), Action: string(fixture.Action), DataAction: fixture.DataAction, RecordID: "contract-record"},
	})
	if err != nil || denied.Allowed {
		t.Fatalf("reauthorization without resource facts must fail closed: decision=%+v err=%v", denied, err)
	}
	application := identity.ApplicationScope{TenantID: fixture.TenantID, WorkspaceID: fixture.WorkspaceID, ApplicationKey: fixture.ApplicationKey}
	user, found, err := fixture.Binding.Directory().FindUser(ctx, identity.UserLookup{Application: application, UserID: verified.SubjectID})
	if err != nil || !found || user.ID != string(verified.SubjectID) {
		t.Fatalf("directory user=%+v found=%v err=%v", user, found, err)
	}
	users, err := fixture.Binding.Directory().ListUsers(ctx, identity.DirectoryQuery{Application: application})
	if err != nil || !containsUser(users, user.ID) {
		t.Fatalf("directory users=%+v err=%v", users, err)
	}
	roles, err := fixture.Binding.Directory().ListRoles(ctx, identity.DirectoryQuery{Application: application})
	if err != nil || len(roles) == 0 {
		t.Fatalf("directory roles=%+v err=%v", roles, err)
	}
	assignments, err := fixture.Binding.Directory().ListUserRoleAssignments(ctx, identity.UserRoleAssignmentQuery{Application: application, UserID: verified.SubjectID})
	if err != nil || len(assignments) == 0 {
		t.Fatalf("directory role assignments=%+v err=%v", assignments, err)
	}
	resolution, err := fixture.Binding.Principals().Resolve(ctx, identity.PrincipalResolutionRequest{Application: application, SubjectID: verified.SubjectID})
	if err != nil || !resolution.Principal.Known || resolution.Principal.UserID != string(verified.SubjectID) || resolution.AccessBundle.Subject.SubjectID != verified.SubjectID || resolution.AccessBundle.AuthorizationRevision != bundle.AuthorizationRevision {
		t.Fatalf("principal resolution=%+v err=%v", resolution, err)
	}
	otherApplication := application
	otherApplication.WorkspaceID += "-other"
	if _, err := fixture.Binding.Directory().ListUsers(ctx, identity.DirectoryQuery{Application: otherApplication}); err == nil {
		t.Fatal("directory accepted a different application workspace")
	}
	if err := fixture.Binding.Authentication().LogoutSession(ctx, identity.LogoutRequest{TenantID: fixture.TenantID, WorkspaceID: fixture.WorkspaceID, ApplicationKey: fixture.ApplicationKey, SessionID: session.SessionID, RefreshToken: session.RefreshToken}); err != nil {
		t.Fatalf("logout: %v", err)
	}
}

func containsUser(values []identity.User, expectedID string) bool {
	for _, value := range values {
		if value.ID == expectedID {
			return true
		}
	}
	return false
}
