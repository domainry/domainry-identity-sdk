package browsergateway

import (
	"net/http"
	"net/url"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

func (gateway *Gateway) Providers(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := gateway.workspaceID(w, r, "")
	if !ok {
		return
	}
	providers, err := gateway.binding.Authentication().Providers(r.Context(), identity.ProviderQuery{WorkspaceID: workspaceID})
	if err != nil {
		gateway.writeError(w, err)
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
		gateway.writeCode(w, http.StatusBadRequest, "identity.redirect_url_invalid")
		return
	}
	challenge, err := gateway.binding.Authentication().BeginFederatedLogin(r.Context(), identity.BeginFederatedLoginRequest{
		WorkspaceID: workspaceID, ApplicationKey: gateway.config.ApplicationKey,
		Provider: r.PathValue("provider"), ReturnURL: request.ReturnURL, Phone: request.Phone,
	})
	if err != nil {
		gateway.writeError(w, err)
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
			gateway.writeCode(w, http.StatusBadRequest, "auth.provider_callback_invalid")
			return
		}
		if _, present := r.PostForm["tenant_id"]; present {
			gateway.writeCode(w, http.StatusBadRequest, "identity.workspace_scope_only")
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
		gateway.writeError(w, err)
		return
	}
	if !validReturnURL(completion.ReturnURL) {
		gateway.writeCode(w, http.StatusBadGateway, "identity.provider_redirect_invalid")
		return
	}
	redirect, err := url.Parse(completion.ReturnURL)
	if err != nil || !redirect.IsAbs() {
		gateway.writeCode(w, http.StatusBadGateway, "identity.provider_redirect_invalid")
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
			gateway.writeError(w, err)
			return
		}
		gateway.writeBrowserAuthenticationOutcome(w, outcome)
		return
	}
	session, err := gateway.binding.Authentication().VerifyOTP(r.Context(), request)
	if err != nil {
		gateway.writeError(w, err)
		return
	}
	gateway.writeBrowserSession(w, session)
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
		gateway.writeCode(w, http.StatusBadRequest, "identity.redirect_url_invalid")
		return
	}
	request := identity.ExchangeAuthorizationCodeRequest{
		WorkspaceID: workspaceID, Code: browserRequest.Code,
		ApplicationKey: gateway.config.ApplicationKey, ReturnURL: browserRequest.ReturnURL,
	}
	session, err := gateway.binding.Authentication().ExchangeAuthorizationCode(r.Context(), request)
	if err != nil {
		gateway.writeError(w, err)
		return
	}
	gateway.writeBrowserSession(w, session)
}

func validatedReturnURL(raw string) (*url.URL, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return parsed, err == nil && parsed.IsAbs() && (parsed.Scheme == "https" || parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))
}

func validReturnURL(raw string) bool {
	_, valid := validatedReturnURL(raw)
	return valid
}
