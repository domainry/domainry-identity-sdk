package application

import (
	"context"

	identity "github.com/domainry/domainry-identity-sdk"
)

type externalAccounts struct {
	binding  *binding
	delegate identity.ExternalAccountManager
}

func (value externalAccounts) ListExternalAccounts(ctx context.Context, request identity.ListExternalAccountsRequest) ([]identity.ExternalAccount, error) {
	workspaceID, err := value.workspaceForAccessToken(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return nil, err
	}
	request.WorkspaceID = workspaceID
	return value.delegate.ListExternalAccounts(ctx, request)
}

func (value externalAccounts) StartExternalAccountLink(ctx context.Context, request identity.StartExternalAccountLinkRequest) (identity.ProviderChallenge, error) {
	workspaceID, err := value.workspaceForAccessToken(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return identity.ProviderChallenge{}, err
	}
	applicationKey, err := value.binding.applicationKey(request.ApplicationKey)
	if err != nil {
		return identity.ProviderChallenge{}, err
	}
	request.WorkspaceID, request.ApplicationKey = workspaceID, applicationKey
	return value.delegate.StartExternalAccountLink(ctx, request)
}

func (value externalAccounts) UnbindExternalAccount(ctx context.Context, request identity.UnbindExternalAccountRequest) error {
	workspaceID, err := value.workspaceForAccessToken(ctx, request.WorkspaceID, request.AccessToken)
	if err != nil {
		return err
	}
	request.WorkspaceID = workspaceID
	return value.delegate.UnbindExternalAccount(ctx, request)
}

func (value externalAccounts) workspaceForAccessToken(ctx context.Context, requested identity.WorkspaceID, accessToken string) (identity.WorkspaceID, error) {
	workspaceID, err := value.binding.workspace(ctx, requested)
	if err != nil {
		return "", err
	}
	verified, err := value.binding.verifyAccessToken(ctx, accessToken)
	if err != nil {
		return "", err
	}
	if verified.WorkspaceID != workspaceID {
		return "", scopeError(identity.ErrorClassForbidden, "auth.workspace_mismatch")
	}
	return workspaceID, nil
}

var _ identity.ExternalAccountManager = externalAccounts{}
