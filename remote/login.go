package remote

import (
	"context"
	"net/http"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func (c *Client) Login(ctx context.Context, request identitysdk.LoginRequest) (identitysdk.AuthSession, error) {
	request.WorkspaceID = c.resolveWorkspace(request.WorkspaceID)
	request.Login = strings.TrimSpace(request.Login)
	if request.WorkspaceID == "" || request.Login == "" || request.Password == "" {
		return identitysdk.AuthSession{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "auth.login_request_invalid"}
	}
	var session identitysdk.AuthSession
	if err := c.doJSON(ctx, http.MethodPost, "/auth/login", "", request, &session); err != nil {
		return identitysdk.AuthSession{}, err
	}
	return session, nil
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (identitysdk.AuthSession, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if c.resolveWorkspace("") == "" || refreshToken == "" {
		return identitysdk.AuthSession{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "auth.refresh_request_invalid"}
	}
	payload := map[string]string{"workspace_id": c.resolveWorkspace(""), "refresh_token": refreshToken}
	var session identitysdk.AuthSession
	if err := c.doJSON(ctx, http.MethodPost, "/auth/refresh", "", payload, &session); err != nil {
		return identitysdk.AuthSession{}, err
	}
	return session, nil
}

func (c *Client) Logout(ctx context.Context, refreshToken string) error {
	refreshToken = strings.TrimSpace(refreshToken)
	if c.resolveWorkspace("") == "" || refreshToken == "" {
		return &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "auth.logout_request_invalid"}
	}
	payload := map[string]string{"workspace_id": c.resolveWorkspace(""), "refresh_token": refreshToken}
	return c.doJSON(ctx, http.MethodPost, "/auth/logout", "", payload, nil)
}

func (c *Client) resolveWorkspace(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	if c == nil {
		return ""
	}
	return c.workspaceID
}
