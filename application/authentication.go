package application

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type authentication struct{ binding *binding }

func (value authentication) Providers(ctx context.Context, query identity.ProviderQuery) ([]identity.Provider, error) {
	workspaceID, err := value.binding.workspace(query.WorkspaceID)
	if err != nil {
		return nil, err
	}
	query.WorkspaceID = workspaceID
	return value.binding.delegate.Authentication().Providers(ctx, query)
}

func (value authentication) LoginWithPassword(ctx context.Context, request identity.PasswordLoginRequest) (identity.AuthSession, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.AuthSession{}, err
	}
	applicationKey, err := value.binding.applicationKey(request.ApplicationKey)
	if err != nil {
		return identity.AuthSession{}, err
	}
	request.WorkspaceID, request.ApplicationKey = workspaceID, applicationKey
	session, err := value.binding.delegate.Authentication().LoginWithPassword(ctx, request)
	if err == nil {
		err = value.binding.verifySession(ctx, session)
	}
	return session, err
}

func (value authentication) LoginWithPasswordOutcome(ctx context.Context, request identity.PasswordLoginRequest) (identity.AuthenticationOutcome, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	applicationKey, err := value.binding.applicationKey(request.ApplicationKey)
	if err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	request.WorkspaceID, request.ApplicationKey = workspaceID, applicationKey
	if challengeBinding, ok := value.binding.delegate.(identity.ChallengeAuthenticationBinding); ok {
		outcome, err := challengeBinding.ChallengeAuthentication().LoginWithPasswordOutcome(ctx, request)
		if err == nil {
			err = value.binding.verifyAuthenticationOutcome(ctx, outcome)
		}
		return outcome, err
	}
	session, err := value.binding.delegate.Authentication().LoginWithPassword(ctx, request)
	if err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	if err := value.binding.verifySession(ctx, session); err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	return identity.AuthenticationOutcome{Status: identity.AuthenticationStatusAuthenticated, Session: &session}, nil
}

func (value authentication) BeginFederatedLogin(ctx context.Context, request identity.BeginFederatedLoginRequest) (identity.ProviderChallenge, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.ProviderChallenge{}, err
	}
	applicationKey, err := value.binding.applicationKey(request.ApplicationKey)
	if err != nil {
		return identity.ProviderChallenge{}, err
	}
	request.WorkspaceID, request.ApplicationKey = workspaceID, applicationKey
	return value.binding.delegate.Authentication().BeginFederatedLogin(ctx, request)
}

func (value authentication) CompleteFederatedLogin(ctx context.Context, request identity.CompleteFederatedLoginRequest) (identity.FederatedLoginCompletion, error) {
	return value.binding.delegate.Authentication().CompleteFederatedLogin(ctx, request)
}

func (value authentication) ExchangeAuthorizationCode(ctx context.Context, request identity.ExchangeAuthorizationCodeRequest) (identity.AuthSession, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.AuthSession{}, err
	}
	applicationKey, err := value.binding.applicationKey(request.ApplicationKey)
	if err != nil {
		return identity.AuthSession{}, err
	}
	request.WorkspaceID, request.ApplicationKey = workspaceID, applicationKey
	session, err := value.binding.delegate.Authentication().ExchangeAuthorizationCode(ctx, request)
	if err == nil {
		err = value.binding.verifySession(ctx, session)
	}
	return session, err
}

func (value authentication) VerifyOTP(ctx context.Context, request identity.VerifyOTPRequest) (identity.AuthSession, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.AuthSession{}, err
	}
	request.WorkspaceID = workspaceID
	session, err := value.binding.delegate.Authentication().VerifyOTP(ctx, request)
	if err == nil {
		err = value.binding.verifySession(ctx, session)
	}
	return session, err
}

func (value authentication) VerifyOTPOutcome(ctx context.Context, request identity.VerifyOTPRequest) (identity.AuthenticationOutcome, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	request.WorkspaceID = workspaceID
	if challengeBinding, ok := value.binding.delegate.(identity.ChallengeAuthenticationBinding); ok {
		outcome, err := challengeBinding.ChallengeAuthentication().VerifyOTPOutcome(ctx, request)
		if err == nil {
			err = value.binding.verifyAuthenticationOutcome(ctx, outcome)
		}
		return outcome, err
	}
	session, err := value.binding.delegate.Authentication().VerifyOTP(ctx, request)
	if err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	if err := value.binding.verifySession(ctx, session); err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	return identity.AuthenticationOutcome{Status: identity.AuthenticationStatusAuthenticated, Session: &session}, nil
}

func (value authentication) RefreshSession(ctx context.Context, request identity.RefreshRequest) (identity.AuthSession, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.AuthSession{}, err
	}
	applicationKey, err := value.binding.applicationKey(request.ApplicationKey)
	if err != nil {
		return identity.AuthSession{}, err
	}
	request.WorkspaceID, request.ApplicationKey = workspaceID, applicationKey
	session, err := value.binding.delegate.Authentication().RefreshSession(ctx, request)
	if err == nil {
		err = value.binding.verifySession(ctx, session)
	}
	return session, err
}

func (value authentication) LogoutSession(ctx context.Context, request identity.LogoutRequest) error {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return err
	}
	applicationKey, err := value.binding.applicationKey(request.ApplicationKey)
	if err != nil {
		return err
	}
	request.WorkspaceID, request.ApplicationKey = workspaceID, applicationKey
	return value.binding.delegate.Authentication().LogoutSession(ctx, request)
}

func (value authentication) CurrentSession(ctx context.Context, request identity.CurrentSessionRequest) (identity.SessionView, error) {
	verified, err := value.binding.verifyAccessToken(ctx, request.AccessToken)
	if err != nil {
		return identity.SessionView{}, err
	}
	session, err := value.binding.delegate.Authentication().CurrentSession(ctx, request)
	if err != nil {
		return identity.SessionView{}, err
	}
	if session.WorkspaceID != verified.WorkspaceID || session.SubjectID != verified.SubjectID || session.SessionID != verified.SessionID {
		return identity.SessionView{}, scopeError(http.StatusBadGateway, "identity.session_scope_invalid")
	}
	return session, nil
}
