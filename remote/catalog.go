package remote

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type catalogClient struct{ client *client }

func (adapter catalogClient) Validate(_ context.Context, catalog identity.AuthorizationCatalog) error {
	if err := catalog.ValidateContract(); err != nil {
		return err
	}
	return adapter.validateApplication(catalog.Application)
}

func (adapter catalogClient) Publish(ctx context.Context, catalog identity.AuthorizationCatalog) (identity.CatalogReceipt, error) {
	if err := catalog.ValidateContract(); err != nil {
		return identity.CatalogReceipt{}, err
	}
	if err := adapter.validateApplication(catalog.Application); err != nil {
		return identity.CatalogReceipt{}, err
	}
	var receipt identity.CatalogReceipt
	err := adapter.client.doJSON(ctx, http.MethodPut, "/identity/catalog", adapter.client.serviceAccessToken, catalog, &receipt)
	return receipt, err
}

func (adapter catalogClient) CurrentRevision(ctx context.Context, application identity.ApplicationRef) (identity.CatalogReceipt, error) {
	if err := adapter.validateApplication(application); err != nil {
		return identity.CatalogReceipt{}, err
	}
	application.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(application.WorkspaceID)))
	if !application.TenantID.Valid() {
		application.TenantID = identity.TenantID(application.WorkspaceID)
	}
	applicationKey, err := adapter.client.resolveApplication(string(application.ApplicationKey))
	if err != nil {
		return identity.CatalogReceipt{}, err
	}
	application.ApplicationKey = identity.ApplicationKey(applicationKey)
	var receipt identity.CatalogReceipt
	err = adapter.client.doJSON(ctx, http.MethodPost, "/identity/catalog/revision", adapter.client.serviceAccessToken, application, &receipt)
	return receipt, err
}

func (adapter catalogClient) validateApplication(application identity.ApplicationRef) error {
	if err := (authentication{client: adapter.client}).requireWorkspace(application.WorkspaceID); err != nil {
		return err
	}
	_, err := adapter.client.resolveApplication(string(application.ApplicationKey))
	return err
}
