package remote

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type applicationRegistry struct{ client *client }

func (adapter applicationRegistry) Register(ctx context.Context, request identity.ApplicationRegistration) (identity.ApplicationRegistrationReceipt, error) {
	if err := request.ValidateContract(); err != nil {
		return identity.ApplicationRegistrationReceipt{}, err
	}
	var receipt identity.ApplicationRegistrationReceipt
	err := adapter.client.doJSON(ctx, http.MethodPut, "/identity/applications/current", adapter.client.serviceAccessToken, request, &receipt)
	return receipt, err
}

type permissionRegistry struct{ client *client }

func (adapter permissionRegistry) Reconcile(ctx context.Context, request identity.PermissionReconcileRequest) (identity.PermissionReconcileReceipt, error) {
	if err := request.ValidateContract(); err != nil {
		return identity.PermissionReconcileReceipt{}, err
	}
	var receipt identity.PermissionReconcileReceipt
	err := adapter.client.doJSON(ctx, http.MethodPut, "/identity/permissions/reconcile", adapter.client.serviceAccessToken, request, &receipt)
	return receipt, err
}

func (adapter permissionRegistry) CurrentSourceSnapshot(ctx context.Context, request identity.PermissionSourceSnapshotRequest) (identity.PermissionSourceSnapshot, error) {
	if err := request.ValidateContract(); err != nil {
		return identity.PermissionSourceSnapshot{}, err
	}
	var snapshot identity.PermissionSourceSnapshot
	err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/permissions/source-snapshot", adapter.client.serviceAccessToken, request, &snapshot)
	return snapshot, err
}
