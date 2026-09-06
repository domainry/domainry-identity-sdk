package browsergateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

// Browser response types are deliberately separate from the deployment-neutral
// authentication contracts. The latter retain TenantID for compatibility with
// older non-browser adapters; the browser boundary is Workspace-only and never
// serializes either a tenant selector or a refresh credential.
type browserAuthenticationOutcome struct {
	Status    identity.AuthenticationStatus `json:"status"`
	Challenge *identity.ProviderChallenge   `json:"challenge,omitempty"`
}

type browserSession struct {
	SessionID             identity.SessionID `json:"session_id,omitempty"`
	WorkspaceID           string             `json:"workspace_id"`
	AccessToken           string             `json:"access_token"`
	TokenType             string             `json:"token_type"`
	ExpiresAt             string             `json:"expires_at"`
	User                  identity.User      `json:"user"`
	Roles                 []identity.Role    `json:"roles"`
	DefaultRole           string             `json:"default_role"`
	Permissions           []string           `json:"permissions"`
	MustChangePassword    bool               `json:"must_change_password"`
	AuthenticationTime    int64              `json:"auth_time,omitempty"`
	AuthenticationMethods []string           `json:"amr,omitempty"`
	AssuranceLevel        string             `json:"acr,omitempty"`
}

type browserSessionView struct {
	SessionID             identity.SessionID             `json:"session_id,omitempty"`
	WorkspaceID           identity.WorkspaceID           `json:"workspace_id"`
	SubjectID             identity.SubjectID             `json:"subject_id"`
	AuthorizationRevision identity.AuthorizationRevision `json:"authorization_revision,omitempty"`
	User                  identity.User                  `json:"user"`
	Roles                 []identity.Role                `json:"roles"`
	DefaultRole           string                         `json:"default_role,omitempty"`
	Permissions           []string                       `json:"permissions,omitempty"`
	MustChangePassword    bool                           `json:"must_change_password"`
}

func newBrowserSession(session identity.AuthSession) browserSession {
	return browserSession{
		SessionID:             session.SessionID,
		WorkspaceID:           session.WorkspaceID,
		AccessToken:           session.AccessToken,
		TokenType:             session.TokenType,
		ExpiresAt:             session.ExpiresAt,
		User:                  session.User,
		Roles:                 session.Roles,
		DefaultRole:           session.DefaultRole,
		Permissions:           session.Permissions,
		MustChangePassword:    session.MustChangePassword,
		AuthenticationTime:    session.AuthenticationTime,
		AuthenticationMethods: session.AuthenticationMethods,
		AssuranceLevel:        session.AssuranceLevel,
	}
}

func newBrowserSessionView(session identity.SessionView) browserSessionView {
	return browserSessionView{
		SessionID:             session.SessionID,
		WorkspaceID:           session.WorkspaceID,
		SubjectID:             session.SubjectID,
		AuthorizationRevision: session.AuthorizationRevision,
		User:                  session.User,
		Roles:                 session.Roles,
		DefaultRole:           session.DefaultRole,
		Permissions:           session.Permissions,
		MustChangePassword:    session.MustChangePassword,
	}
}

func (gateway *Gateway) writeError(w http.ResponseWriter, err error) {
	status, code, message, requestID := http.StatusInternalServerError, "identity.request_failed", "", ""
	params := map[string]string(nil)
	var sdkError *identity.Error
	if errors.As(err, &sdkError) {
		if sdkError.StatusCode >= 400 && sdkError.StatusCode <= 599 {
			status = sdkError.StatusCode
		}
		if strings.TrimSpace(sdkError.Code) != "" {
			code = sdkError.Code
		}
		message, requestID, params = sdkError.Message, sdkError.RequestID, sdkError.Params
	}
	payload := map[string]any{"code": code, "error": map[string]any{"code": code}}
	if message != "" {
		payload["message"] = message
	}
	if requestID != "" {
		payload["request_id"] = requestID
	}
	if len(params) > 0 {
		payload["params"] = params
		payload["error"].(map[string]any)["params"] = params
	}
	gateway.writeJSON(w, status, payload)
}

func (gateway *Gateway) writeCode(w http.ResponseWriter, status int, code string) {
	gateway.writeJSON(w, status, map[string]any{"code": code, "error": map[string]string{"code": code}})
}

func (gateway *Gateway) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}
