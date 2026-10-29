package browsergateway

import (
	"net/http"
	"net/url"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

func (gateway *Gateway) AuthorizeBrowserApplication(w http.ResponseWriter, r *http.Request) {
	refreshToken, ok := gateway.refreshToken(r)
	if !ok {
		gateway.writeCode(w, r, http.StatusUnauthorized, "auth.refresh_token_required")
		return
	}
	target := identity.ApplicationKey(strings.TrimSpace(r.URL.Query().Get("client_id")))
	returnURL := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	codeChallenge := strings.TrimSpace(r.URL.Query().Get("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(r.URL.Query().Get("code_challenge_method"))
	if !target.Valid() || !validReturnURL(returnURL) || state == "" || codeChallenge == "" || codeChallengeMethod != "S256" {
		gateway.writeCode(w, r, http.StatusBadRequest, "auth.authorization_code_request_invalid")
		return
	}
	authority, ok := gateway.binding.(identity.BrowserSingleSignOn)
	if !ok {
		gateway.writeCode(w, r, http.StatusNotImplemented, "identity.browser_sso_unavailable")
		return
	}
	result, err := authority.AuthorizeBrowserApplication(r.Context(), identity.BrowserAuthorizationRequest{
		SourceApplicationKey: gateway.config.ApplicationKey,
		TargetApplicationKey: target,
		RefreshToken:         refreshToken,
		ReturnURL:            returnURL,
		State:                state,
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
	})
	if err != nil {
		if invalidRefreshCredential(err) {
			gateway.clearRefreshCookie(w)
		}
		gateway.writeError(w, r, err)
		return
	}
	redirect, valid := validatedReturnURL(result.ReturnURL)
	if !valid {
		gateway.writeCode(w, r, http.StatusBadGateway, "identity.redirect_url_invalid")
		return
	}
	query := redirect.Query()
	query.Set("code", result.AuthorizationCode)
	query.Set("state", result.State)
	redirect.RawQuery = query.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func (gateway *Gateway) Providers(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := gateway.workspaceID(w, r, "")
	if !ok {
		return
	}
	providers, err := gateway.binding.Authentication().Providers(r.Context(), identity.ProviderQuery{WorkspaceID: workspaceID})
	if err != nil {
		gateway.writeError(w, r, err)
		return
	}
	gateway.writeJSON(w, http.StatusOK, providers)
}

func (gateway *Gateway) StartProvider(w http.ResponseWriter, r *http.Request) {
	var request browserProviderStartRequest
	if r.Method == http.MethodPost && !gateway.decodeJSON(w, r, &request) {
		return
	}
	workspaceID, ok := gateway.workspaceID(w, r, request.WorkspaceID)
	if !ok {
		return
	}
	if request.ReturnURL == "" {
		request.ReturnURL = strings.TrimSpace(r.URL.Query().Get("return_url"))
	}
	if request.ReturnURL != "" && !validReturnURL(request.ReturnURL) {
		gateway.writeCode(w, r, http.StatusBadRequest, "identity.redirect_url_invalid")
		return
	}
	challenge, err := gateway.binding.Authentication().BeginFederatedLogin(r.Context(), identity.BeginFederatedLoginRequest{
		WorkspaceID: workspaceID, ApplicationKey: gateway.config.ApplicationKey,
		Provider: r.PathValue("provider"), ReturnURL: request.ReturnURL, Phone: request.Phone,
	})
	if err != nil {
		gateway.writeError(w, r, err)
		return
	}
	gateway.writeJSON(w, http.StatusOK, challenge)
}

func (gateway *Gateway) ProviderCallback(w http.ResponseWriter, r *http.Request) {
	if gateway.rejectNonWorkspaceBoundary(w, r) {
		return
	}
	values := map[string]string{}
	for key, entries := range r.URL.Query() {
		if len(entries) > 0 {
			values[key] = entries[0]
		}
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			gateway.writeCode(w, r, http.StatusBadRequest, "auth.provider_callback_invalid")
			return
		}
		if _, present := r.PostForm["tenant_id"]; present {
			gateway.writeCode(w, r, http.StatusBadRequest, "identity.workspace_scope_only")
			return
		}
		for key, entries := range r.PostForm {
			if len(entries) > 0 {
				values[key] = entries[0]
			}
		}
	}
	completion, err := gateway.binding.Authentication().CompleteFederatedLogin(r.Context(), identity.CompleteFederatedLoginRequest{
		Provider: r.PathValue("provider"), Values: values,
	})
	if err != nil {
		gateway.writeError(w, r, err)
		return
	}
	if !validReturnURL(completion.ReturnURL) {
		gateway.writeCode(w, r, http.StatusBadGateway, "identity.provider_redirect_invalid")
		return
	}
	redirect, err := url.Parse(completion.ReturnURL)
	if err != nil || !redirect.IsAbs() {
		gateway.writeCode(w, r, http.StatusBadGateway, "identity.provider_redirect_invalid")
		return
	}
	query := redirect.Query()
	query.Set("code", completion.AuthorizationCode)
	if strings.TrimSpace(completion.State) != "" {
		query.Set("state", completion.State)
	}
	redirect.RawQuery = query.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}

func (gateway *Gateway) VerifyProvider(w http.ResponseWriter, r *http.Request) {
	var browserRequest browserVerifyOTPRequest
	if !gateway.decodeJSON(w, r, &browserRequest) {
		return
	}
	workspaceID, ok := gateway.workspaceID(w, r, browserRequest.WorkspaceID)
	if !ok {
		return
	}
	request := identity.VerifyOTPRequest{WorkspaceID: workspaceID, Provider: r.PathValue("provider"), State: browserRequest.State, Code: browserRequest.Code}
	if challengeBinding, ok := gateway.binding.(identity.ChallengeAuthenticationBinding); ok {
		outcome, err := challengeBinding.ChallengeAuthentication().VerifyOTPOutcome(r.Context(), request)
		if err != nil {
			gateway.writeError(w, r, err)
			return
		}
		gateway.writeBrowserAuthenticationOutcome(w, r, workspaceID, outcome)
		return
	}
	session, err := gateway.binding.Authentication().VerifyOTP(r.Context(), request)
	if err != nil {
		gateway.writeError(w, r, err)
		return
	}
	gateway.writeBrowserSession(w, r, session)
}

func (gateway *Gateway) ExchangeAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	var browserRequest browserAuthorizationCodeExchangeRequest
	if !gateway.decodeJSON(w, r, &browserRequest) {
		return
	}
	workspaceID, ok := gateway.workspaceID(w, r, browserRequest.WorkspaceID)
	if !ok {
		return
	}
	if !validReturnURL(browserRequest.ReturnURL) {
		gateway.writeCode(w, r, http.StatusBadRequest, "identity.redirect_url_invalid")
		return
	}
	request := identity.ExchangeAuthorizationCodeRequest{
		WorkspaceID: workspaceID, Code: browserRequest.Code,
		ApplicationKey: gateway.config.ApplicationKey, ReturnURL: browserRequest.ReturnURL, CodeVerifier: browserRequest.CodeVerifier,
	}
	session, err := gateway.binding.Authentication().ExchangeAuthorizationCode(r.Context(), request)
	if err != nil {
		gateway.writeError(w, r, err)
		return
	}
	gateway.writeBrowserSession(w, r, session)
}

func validatedReturnURL(raw string) (*url.URL, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return parsed, err == nil && parsed.IsAbs() && (parsed.Scheme == "https" || parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))
}

func validReturnURL(raw string) bool {
	_, valid := validatedReturnURL(raw)
	return valid
}
