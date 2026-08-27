package browsergateway

import (
	"errors"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

func (gateway *Gateway) Login(w http.ResponseWriter, r *http.Request) {
	var request identity.PasswordLoginRequest
	if !gateway.decodeJSON(w, r, &request) {
		return
	}
	workspaceID, ok := gateway.workspaceID(w, r, request.WorkspaceID)
	if !ok {
		return
	}
	request.WorkspaceID = workspaceID
	request.ApplicationKey = gateway.config.ApplicationKey
	session, err := gateway.binding.Authentication().LoginWithPassword(r.Context(), request)
	if err != nil {
		gateway.writeError(w, err)
		return
	}
	gateway.writeBrowserSession(w, session)
}

func (gateway *Gateway) Refresh(w http.ResponseWriter, r *http.Request) {
	var scope browserRequestScope
	if !gateway.decodeJSON(w, r, &scope) {
		return
	}
	workspaceID, ok := gateway.workspaceID(w, r, scope.WorkspaceID)
	if !ok {
		return
	}
	refreshToken, ok := gateway.refreshToken(r)
	if !ok {
		gateway.writeCode(w, http.StatusUnauthorized, "auth.refresh_token_required")
		return
	}
	session, err := gateway.binding.Authentication().RefreshSession(r.Context(), identity.RefreshRequest{
		TenantID: scope.TenantID, WorkspaceID: workspaceID, ApplicationKey: gateway.config.ApplicationKey, RefreshToken: refreshToken,
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
	workspaceID, ok := gateway.workspaceID(w, r, scope.WorkspaceID)
	if !ok {
		return
	}
	refreshToken, _ := gateway.refreshToken(r)
	var logoutErr error
	if refreshToken != "" {
		logoutErr = gateway.binding.Authentication().LogoutSession(r.Context(), identity.LogoutRequest{
			TenantID: scope.TenantID, WorkspaceID: workspaceID, ApplicationKey: gateway.config.ApplicationKey, RefreshToken: refreshToken,
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
	gateway.writeJSON(w, http.StatusOK, session)
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
	session.RefreshToken = ""
	gateway.writeJSON(w, http.StatusOK, session)
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
