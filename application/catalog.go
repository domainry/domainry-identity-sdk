package application

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type catalog struct{ binding *binding }

func (value catalog) Validate(ctx context.Context, input identity.AuthorizationCatalog) error {
	if err := value.validateApplication(input.Application); err != nil {
		return err
	}
	return value.binding.delegate.Catalog().Validate(ctx, input)
}

func (value catalog) Publish(ctx context.Context, input identity.AuthorizationCatalog) (identity.CatalogReceipt, error) {
	if err := value.validateApplication(input.Application); err != nil {
		return identity.CatalogReceipt{}, err
	}
	return value.binding.delegate.Catalog().Publish(ctx, input)
}

func (value catalog) CurrentRevision(ctx context.Context, input identity.ApplicationRef) (identity.CatalogReceipt, error) {
	if err := value.validateApplication(input); err != nil {
		return identity.CatalogReceipt{}, err
	}
	return value.binding.delegate.Catalog().CurrentRevision(ctx, input)
}

func (value catalog) validateApplication(input identity.ApplicationRef) error {
	workspaceID, err := value.binding.workspace(input.WorkspaceID)
	if err != nil {
		return err
	}
	applicationKey, err := value.binding.applicationKey(input.ApplicationKey)
	if err != nil {
		return err
	}
	if workspaceID != value.binding.application.WorkspaceID || applicationKey != value.binding.application.ApplicationKey {
		return scopeError(http.StatusForbidden, "identity.application_scope_mismatch")
	}
	return nil
}
