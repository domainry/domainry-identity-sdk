package browsergateway

import (
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

func (gateway *Gateway) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var request identity.ChangePasswordRequest
	if !gateway.decodeJSON(w, r, &request) {
		return
	}
	request.AccessToken = bearerToken(r.Header.Get("Authorization"))
	request.IdempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	session, err := gateway.binding.Credentials().ChangePassword(r.Context(), request)
	if err != nil {
		gateway.writeError(w, err)
		return
	}
	gateway.writeBrowserSession(w, session)
}

func (gateway *Gateway) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var request identity.ResetPasswordRequest
	if !gateway.decodeJSON(w, r, &request) {
		return
	}
	workspaceID, ok := gateway.workspaceID(w, r, request.WorkspaceID)
	if !ok {
		return
	}
	request.WorkspaceID = workspaceID
	request.AccessToken = bearerToken(r.Header.Get("Authorization"))
	request.IdempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if err := gateway.binding.Credentials().ResetPassword(r.Context(), request); err != nil {
		gateway.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (gateway *Gateway) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	var request identity.RevokeSessionsRequest
	if !gateway.decodeJSON(w, r, &request) {
		return
	}
	workspaceID, ok := gateway.workspaceID(w, r, request.WorkspaceID)
	if !ok {
		return
	}
	request.WorkspaceID = workspaceID
	request.AccessToken = bearerToken(r.Header.Get("Authorization"))
	request.IdempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if err := gateway.binding.Credentials().RevokeSessions(r.Context(), request); err != nil {
		gateway.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
