package remote

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type credentialClient struct{ client *client }

func (adapter credentialClient) ChangePassword(ctx context.Context, request identity.ChangePasswordRequest) (identity.AuthSession, error) {
	payload := map[string]string{"current_password": request.CurrentPassword, "new_password": request.NewPassword}
	var session identity.AuthSession
	err := adapter.client.doJSONWithHeaders(ctx, http.MethodPost, "/auth/change-password", request.AccessToken, payload, &session, idempotencyHeaders(request.IdempotencyKey))
	return session, err
}

func (adapter credentialClient) ResetPassword(ctx context.Context, request identity.ResetPasswordRequest) error {
	payload := map[string]any{"user_id": string(request.SubjectID), "new_password": request.NewPassword, "must_change_password": request.MustChangePassword}
	return adapter.client.doJSONWithHeaders(ctx, http.MethodPost, "/auth/reset-password", request.AccessToken, payload, nil, idempotencyHeaders(request.IdempotencyKey))
}

func (adapter credentialClient) RevokeSessions(ctx context.Context, request identity.RevokeSessionsRequest) error {
	return adapter.client.doJSONWithHeaders(ctx, http.MethodPost, "/auth/sessions/revoke-others", request.AccessToken, map[string]string{"user_id": string(request.SubjectID)}, nil, idempotencyHeaders(request.IdempotencyKey))
}

func idempotencyHeaders(key string) http.Header {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	return http.Header{"Idempotency-Key": []string{key}}
}
