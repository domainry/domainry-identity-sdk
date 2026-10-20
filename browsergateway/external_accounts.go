package browsergateway

import (
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

func (gateway *Gateway) externalAccountManager(w http.ResponseWriter, r *http.Request) (identity.ExternalAccountManager, identity.WorkspaceID, bool) {
	binding, ok := gateway.binding.(identity.ExternalAccountBinding)
	if !ok || binding.ExternalAccounts() == nil {
		gateway.writeError(w, r, &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "auth.external_account_link_unavailable"})
		return nil, "", false
	}
	workspaceID, ok := gateway.workspaceID(w, r, "")
	if !ok {
		return nil, "", false
	}
	return binding.ExternalAccounts(), workspaceID, true
}

func (gateway *Gateway) ExternalAccounts(w http.ResponseWriter, r *http.Request) {
	manager, workspaceID, ok := gateway.externalAccountManager(w, r)
	if !ok {
		return
	}
	accounts, err := manager.ListExternalAccounts(r.Context(), identity.ListExternalAccountsRequest{
		WorkspaceID: workspaceID,
		AccessToken: bearerToken(r.Header.Get("Authorization")),
	})
	if err != nil {
		gateway.writeError(w, r, err)
		return
	}
	gateway.writeJSON(w, http.StatusOK, accounts)
}

func (gateway *Gateway) StartExternalAccountLink(w http.ResponseWriter, r *http.Request) {
	var browserRequest browserExternalAccountLinkRequest
	if !gateway.decodeJSON(w, r, &browserRequest) {
		return
	}
	if !validReturnURL(browserRequest.ReturnURL) {
		gateway.writeCode(w, r, http.StatusBadRequest, "identity.redirect_url_invalid")
		return
	}
	manager, workspaceID, ok := gateway.externalAccountManager(w, r)
	if !ok {
		return
	}
	challenge, err := manager.StartExternalAccountLink(r.Context(), identity.StartExternalAccountLinkRequest{
		WorkspaceID: workspaceID, ApplicationKey: gateway.config.ApplicationKey,
		AccessToken: bearerToken(r.Header.Get("Authorization")),
		Provider:    r.PathValue("provider"), ReturnURL: browserRequest.ReturnURL,
	})
	if err != nil {
		gateway.writeError(w, r, err)
		return
	}
	gateway.writeJSON(w, http.StatusOK, challenge)
}

func (gateway *Gateway) UnbindExternalAccount(w http.ResponseWriter, r *http.Request) {
	manager, workspaceID, ok := gateway.externalAccountManager(w, r)
	if !ok {
		return
	}
	err := manager.UnbindExternalAccount(r.Context(), identity.UnbindExternalAccountRequest{
		WorkspaceID: workspaceID,
		AccessToken: bearerToken(r.Header.Get("Authorization")),
		Provider:    strings.TrimSpace(r.PathValue("provider")), AccountID: strings.TrimSpace(r.PathValue("accountID")),
	})
	if err != nil {
		gateway.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
