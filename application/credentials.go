package application

import (
	"context"

	identity "github.com/domainry/domainry-identity-sdk"
)

type credentials struct{ binding *binding }

func (value credentials) ChangePassword(ctx context.Context, request identity.ChangePasswordRequest) (identity.AuthSession, error) {
	if _, err := value.binding.verifyAccessToken(ctx, request.AccessToken); err != nil {
		return identity.AuthSession{}, err
	}
	session, err := value.binding.delegate.Credentials().ChangePassword(ctx, request)
	if err == nil {
		err = value.binding.verifySession(ctx, session)
	}
	return session, err
}

func (value credentials) ResetPassword(ctx context.Context, request identity.ResetPasswordRequest) error {
	if _, err := value.binding.verifyAccessToken(ctx, request.AccessToken); err != nil {
		return err
	}
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return err
	}
	request.WorkspaceID = workspaceID
	return value.binding.delegate.Credentials().ResetPassword(ctx, request)
}

func (value credentials) RevokeSessions(ctx context.Context, request identity.RevokeSessionsRequest) error {
	if _, err := value.binding.verifyAccessToken(ctx, request.AccessToken); err != nil {
		return err
	}
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return err
	}
	request.WorkspaceID = workspaceID
	return value.binding.delegate.Credentials().RevokeSessions(ctx, request)
}
