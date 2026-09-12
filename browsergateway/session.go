package browsergateway

import (
	"errors"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

func (gateway *Gateway) Login(w http.ResponseWriter, r *http.Request) {
	var browserRequest browserPasswordLoginRequest
	if !gateway.decodeJSON(w, r, &browserRequest) {
		return
	}
	workspaceID, ok := gateway.passwordLoginWorkspaceID(w, r, browserRequest.WorkspaceID, browserRequest.Login)
	if !ok {
		return
	}
	request := identity.PasswordLoginRequest{
		WorkspaceID: workspaceID, ApplicationKey: gateway.config.ApplicationKey,
		Login: browserRequest.Login, Password: browserRequest.Password,
	}
	if challengeBinding, ok := gateway.binding.(identity.ChallengeAuthenticationBinding); ok {
		outcome, err := challengeBinding.ChallengeAuthentication().LoginWithPasswordOutcome(r.Context(), request)
		if err != nil {
			gateway.writeError(w, err)
			return
		}
		gateway.writeBrowserAuthenticationOutcome(w, outcome)
		return
	}
	session, err := gateway.binding.Authentication().LoginWithPassword(r.Context(), request)
	if err != nil {
		gateway.writeError(w, err)
		return
	}
	gateway.writeBrowserSession(w, session)
}

func (gateway *Gateway) writeBrowserAuthenticationOutcome(w http.ResponseWriter, outcome identity.AuthenticationOutcome) {
	if outcome.Status == identity.AuthenticationStatusChallengeRequired && outcome.Challenge != nil {
		gateway.writeJSON(w, http.StatusOK, browserAuthenticationOutcome{Status: outcome.Status, Challenge: outcome.Challenge})
		return
	}
	if outcome.Status == identity.AuthenticationStatusAuthenticated && outcome.Session != nil {
		gateway.writeBrowserSession(w, *outcome.Session)
		return
	}
	gateway.writeCode(w, http.StatusBadGateway, "identity.authentication_response_invalid")
}

func (gateway *Gateway) Refresh(w http.ResponseWriter, r *http.Request) {
	var scope browserRequestScope
	if !gateway.decodeJSON(w, r, &scope) {
		return
	}
	refreshToken, ok := gateway.refreshToken(r)
	if !ok {
		gateway.writeCode(w, http.StatusUnauthorized, "auth.refresh_token_required")
		return
	}
	workspaceID, ok := gateway.refreshSessionWorkspaceID(w, r, scope.WorkspaceID, refreshToken)
	if !ok {
		return
	}
	session, err := gateway.binding.Authentication().RefreshSession(r.Context(), identity.RefreshRequest{
		WorkspaceID: workspaceID, ApplicationKey: gateway.config.ApplicationKey, RefreshToken: refreshToken,
	})
	if err != nil {
		if invalidRefreshCredential(err) {
			gateway.clearRefreshCookie(w)
		}
		gateway.writeError(w, err)
		return
	}
	gateway.writeBrowserSession(w, session)
}

func (gateway *Gateway) Logout(w http.ResponseWriter, r *http.Request) {
	var scope browserRequestScope
	if !gateway.decodeJSON(w, r, &scope) {
		return
	}
	refreshToken, hasRefreshToken := gateway.refreshToken(r)
	var logoutErr error
	if hasRefreshToken {
		workspaceID, ok := gateway.refreshSessionWorkspaceID(w, r, scope.WorkspaceID, refreshToken)
		if !ok {
			return
		}
		logoutErr = gateway.binding.Authentication().LogoutSession(r.Context(), identity.LogoutRequest{
			WorkspaceID: workspaceID, ApplicationKey: gateway.config.ApplicationKey, RefreshToken: refreshToken,
		})
	}
	gateway.clearRefreshCookie(w)
	if logoutErr != nil {
		gateway.writeError(w, logoutErr)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (gateway *Gateway) Session(w http.ResponseWriter, r *http.Request) {
	if gateway.rejectNonWorkspaceBoundary(w, r) {
		return
	}
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		gateway.writeCode(w, http.StatusUnauthorized, "auth.token_required")
		return
	}
	session, err := gateway.binding.Authentication().CurrentSession(r.Context(), identity.CurrentSessionRequest{AccessToken: token})
	if err != nil {
		gateway.writeError(w, err)
		return
	}
	if gateway.hasExplicitWorkspace(r, "") {
		workspaceID, ok := gateway.workspaceID(w, r, "")
		if !ok {
			return
		}
		if session.WorkspaceID != workspaceID {
			gateway.writeCode(w, http.StatusBadRequest, "identity.workspace_scope_mismatch")
			return
		}
	}
	gateway.writeJSON(w, http.StatusOK, newBrowserSessionView(session))
}

func (gateway *Gateway) writeBrowserSession(w http.ResponseWriter, session identity.AuthSession) {
	refreshToken := strings.TrimSpace(session.RefreshToken)
	if refreshToken == "" {
		// A successful session mutation must rotate or issue the browser refresh
		// credential. Keeping a previous cookie would combine a new access token
		// with stale session state and can make logout/revocation unpredictable.
		gateway.clearRefreshCookie(w)
		gateway.writeCode(w, http.StatusBadGateway, "identity.refresh_credential_missing")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: gateway.config.Cookie.Name, Value: refreshToken, Domain: gateway.config.Cookie.Domain,
		Path: gateway.config.Cookie.Path, HttpOnly: true, Secure: gateway.config.Cookie.Secure,
		SameSite: gateway.config.Cookie.SameSite, MaxAge: int(gateway.config.Cookie.MaxAge.Seconds()),
	})
	gateway.writeJSON(w, http.StatusOK, newBrowserSession(session))
}

func (gateway *Gateway) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: gateway.config.Cookie.Name, Value: "", Domain: gateway.config.Cookie.Domain,
		Path: gateway.config.Cookie.Path, HttpOnly: true, Secure: gateway.config.Cookie.Secure,
		SameSite: gateway.config.Cookie.SameSite, MaxAge: -1,
	})
}

func (gateway *Gateway) refreshToken(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(gateway.config.Cookie.Name)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", false
	}
	return strings.TrimSpace(cookie.Value), true
}

func invalidRefreshCredential(err error) bool {
	var sdkError *identity.Error
	if !errors.As(err, &sdkError) {
		return false
	}
	return sdkError.StatusCode == http.StatusBadRequest || sdkError.StatusCode == http.StatusUnauthorized || sdkError.StatusCode == http.StatusForbidden
}
