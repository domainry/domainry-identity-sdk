package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type authentication struct{ client *client }

func (adapter authentication) Providers(ctx context.Context, query identity.ProviderQuery) ([]identity.Provider, error) {
	if err := adapter.requireWorkspace(query.WorkspaceID); err != nil {
		return nil, err
	}
	var providers []identity.Provider
	if err := adapter.client.doJSON(ctx, http.MethodGet, "/auth/providers", "", nil, &providers); err != nil {
		return nil, err
	}
	return providers, nil
}

func (adapter authentication) LoginWithPassword(ctx context.Context, request identity.PasswordLoginRequest) (identity.AuthSession, error) {
	outcome, err := adapter.LoginWithPasswordOutcome(ctx, request)
	return authenticatedSession(outcome, err)
}

func (adapter authentication) LoginWithPasswordOutcome(ctx context.Context, request identity.PasswordLoginRequest) (identity.AuthenticationOutcome, error) {
	if err := adapter.requireWorkspace(request.WorkspaceID); err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	applicationKey, err := adapter.client.resolveApplication(string(request.ApplicationKey))
	if err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	request.ApplicationKey, request.Login = identity.ApplicationKey(applicationKey), strings.TrimSpace(request.Login)
	if request.Login == "" || request.Password == "" {
		return identity.AuthenticationOutcome{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "auth.login_request_invalid"}
	}
	var raw json.RawMessage
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/auth/login", "", request, &raw); err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	return decodeAuthenticationOutcome(raw)
}

func (adapter authentication) BeginFederatedLogin(ctx context.Context, request identity.BeginFederatedLoginRequest) (identity.ProviderChallenge, error) {
	if err := adapter.requireWorkspace(request.WorkspaceID); err != nil {
		return identity.ProviderChallenge{}, err
	}
	request.Provider = strings.TrimSpace(request.Provider)
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	applicationKey, err := adapter.client.resolveApplication(string(request.ApplicationKey))
	if err != nil {
		return identity.ProviderChallenge{}, err
	}
	request.ApplicationKey = identity.ApplicationKey(applicationKey)
	if request.Provider == "" {
		return identity.ProviderChallenge{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "auth.provider_request_invalid"}
	}
	var challenge identity.ProviderChallenge
	endpoint := "/auth/providers/" + url.PathEscape(request.Provider) + "/start"
	if err := adapter.client.doJSON(ctx, http.MethodPost, endpoint, "", request, &challenge); err != nil {
		return identity.ProviderChallenge{}, err
	}
	return challenge, nil
}

func (adapter authentication) CompleteFederatedLogin(ctx context.Context, request identity.CompleteFederatedLoginRequest) (identity.FederatedLoginCompletion, error) {
	request.Provider = strings.TrimSpace(request.Provider)
	if request.Provider == "" || len(request.Values) == 0 {
		return identity.FederatedLoginCompletion{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "auth.provider_callback_request_invalid"}
	}
	values := url.Values{}
	for key, value := range request.Values {
		if key = strings.TrimSpace(key); key != "" {
			values.Set(key, value)
		}
	}
	return adapter.client.completeFederatedLogin(ctx, request.Provider, values)
}

func (adapter authentication) ExchangeAuthorizationCode(ctx context.Context, request identity.ExchangeAuthorizationCodeRequest) (identity.AuthSession, error) {
	if err := adapter.requireWorkspace(request.WorkspaceID); err != nil {
		return identity.AuthSession{}, err
	}
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	applicationKey, err := adapter.client.resolveApplication(string(request.ApplicationKey))
	if err != nil {
		return identity.AuthSession{}, err
	}
	request.ApplicationKey = identity.ApplicationKey(applicationKey)
	var session identity.AuthSession
	err = adapter.client.doJSON(ctx, http.MethodPost, "/auth/code/exchange", "", request, &session)
	return session, err
}

func (adapter authentication) VerifyOTP(ctx context.Context, request identity.VerifyOTPRequest) (identity.AuthSession, error) {
	outcome, err := adapter.VerifyOTPOutcome(ctx, request)
	return authenticatedSession(outcome, err)
}

func (adapter authentication) VerifyOTPOutcome(ctx context.Context, request identity.VerifyOTPRequest) (identity.AuthenticationOutcome, error) {
	if err := adapter.requireWorkspace(request.WorkspaceID); err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	request.Provider, request.State, request.Code = strings.TrimSpace(request.Provider), strings.TrimSpace(request.State), strings.TrimSpace(request.Code)
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	if request.Provider == "" || request.State == "" || request.Code == "" {
		return identity.AuthenticationOutcome{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "auth.provider_verify_request_invalid"}
	}
	var raw json.RawMessage
	endpoint := "/auth/providers/" + url.PathEscape(request.Provider) + "/verify"
	if err := adapter.client.doJSON(ctx, http.MethodPost, endpoint, "", request, &raw); err != nil {
		return identity.AuthenticationOutcome{}, err
	}
	return decodeAuthenticationOutcome(raw)
}

func decodeAuthenticationOutcome(raw []byte) (identity.AuthenticationOutcome, error) {
	var outcome identity.AuthenticationOutcome
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return identity.AuthenticationOutcome{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.authentication_response_invalid", Cause: err}
	}
	if outcome.Status == identity.AuthenticationStatusAuthenticated && outcome.Session != nil && strings.TrimSpace(outcome.Session.AccessToken) != "" {
		return outcome, nil
	}
	if outcome.Status == identity.AuthenticationStatusChallengeRequired && outcome.Challenge != nil && strings.TrimSpace(outcome.Challenge.State) != "" {
		return outcome, nil
	}
	// Protocol-v2 servers returned a bare AuthSession. Accept it during rolling
	// upgrades while always exposing the protocol-v3 outcome to new callers.
	var session identity.AuthSession
	if err := json.Unmarshal(raw, &session); err == nil && strings.TrimSpace(session.AccessToken) != "" {
		return identity.AuthenticationOutcome{Status: identity.AuthenticationStatusAuthenticated, Session: &session}, nil
	}
	return identity.AuthenticationOutcome{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.authentication_response_invalid"}
}

func authenticatedSession(outcome identity.AuthenticationOutcome, err error) (identity.AuthSession, error) {
	if err != nil {
		return identity.AuthSession{}, err
	}
	if outcome.Status == identity.AuthenticationStatusAuthenticated && outcome.Session != nil {
		return *outcome.Session, nil
	}
	if outcome.Status == identity.AuthenticationStatusChallengeRequired && outcome.Challenge != nil {
		return identity.AuthSession{}, &identity.Error{StatusCode: http.StatusConflict, Code: "auth.challenge_required", Params: map[string]string{"provider": outcome.Challenge.Provider, "state": outcome.Challenge.State}}
	}
	return identity.AuthSession{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.authentication_response_invalid"}
}

func (adapter authentication) RefreshSession(ctx context.Context, request identity.RefreshRequest) (identity.AuthSession, error) {
	if err := adapter.requireWorkspace(request.WorkspaceID); err != nil {
		return identity.AuthSession{}, err
	}
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	applicationKey, err := adapter.client.resolveApplication(string(request.ApplicationKey))
	if err != nil {
		return identity.AuthSession{}, err
	}
	request.ApplicationKey = identity.ApplicationKey(applicationKey)
	payload := map[string]string{"workspace_id": string(request.WorkspaceID), "application_key": applicationKey, "refresh_token": strings.TrimSpace(request.RefreshToken)}
	var session identity.AuthSession
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/auth/refresh", "", payload, &session); err != nil {
		return identity.AuthSession{}, err
	}
	return session, nil
}

func (adapter authentication) LogoutSession(ctx context.Context, request identity.LogoutRequest) error {
	if err := adapter.requireWorkspace(request.WorkspaceID); err != nil {
		return err
	}
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	applicationKey, err := adapter.client.resolveApplication(string(request.ApplicationKey))
	if err != nil {
		return err
	}
	return adapter.client.doJSON(ctx, http.MethodPost, "/auth/logout", "", map[string]string{"workspace_id": string(request.WorkspaceID), "application_key": applicationKey, "refresh_token": strings.TrimSpace(request.RefreshToken)}, nil)
}

func (adapter authentication) CurrentSession(ctx context.Context, request identity.CurrentSessionRequest) (identity.SessionView, error) {
	if strings.TrimSpace(request.AccessToken) == "" {
		return identity.SessionView{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "auth.token_required"}
	}
	var session identity.SessionView
	if err := adapter.client.doJSON(ctx, http.MethodGet, "/auth/session", request.AccessToken, nil, &session); err != nil {
		return identity.SessionView{}, err
	}
	if !session.WorkspaceID.Valid() || !session.SubjectID.Valid() || !session.SessionID.Valid() || !session.AuthorizationRevision.Valid() || strings.TrimSpace(session.User.ID) == "" {
		return identity.SessionView{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.session_response_invalid"}
	}
	return session, nil
}

func (adapter authentication) requireWorkspace(workspaceID identity.WorkspaceID) error {
	resolved := strings.TrimSpace(string(workspaceID))
	if resolved == "" {
		resolved = adapter.client.resolveWorkspace("")
	}
	if resolved == "" || adapter.client.workspaceID != "" && resolved != adapter.client.workspaceID {
		return &identity.Error{StatusCode: http.StatusForbidden, Code: "auth.workspace_mismatch"}
	}
	return nil
}
