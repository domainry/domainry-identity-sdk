package application

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type applications struct{ binding *binding }

func (value applications) Register(ctx context.Context, input identity.ApplicationRegistration) (identity.ApplicationRegistrationReceipt, error) {
	application, err := value.binding.scopedApplication(input.Application)
	if err != nil {
		return identity.ApplicationRegistrationReceipt{}, err
	}
	input.Application = application
	return value.binding.delegate.Applications().Register(ctx, input)
}

type permissions struct{ binding *binding }

func (value permissions) Reconcile(ctx context.Context, input identity.PermissionReconcileRequest) (identity.PermissionReconcileReceipt, error) {
	application, err := value.binding.scopedApplication(input.Application)
	if err != nil {
		return identity.PermissionReconcileReceipt{}, err
	}
	input.Application = application
	return value.binding.delegate.Permissions().Reconcile(ctx, input)
}

func (value permissions) CurrentSourceSnapshot(ctx context.Context, input identity.PermissionSourceSnapshotRequest) (identity.PermissionSourceSnapshot, error) {
	application, err := value.binding.scopedApplication(input.Application)
	if err != nil {
		return identity.PermissionSourceSnapshot{}, err
	}
	input.Application = application
	reader, ok := value.binding.delegate.Permissions().(identity.PermissionSnapshotReader)
	if !ok {
		return identity.PermissionSourceSnapshot{}, &identity.Error{Code: "identity.permission_snapshot_reader_unavailable"}
	}
	return reader.CurrentSourceSnapshot(ctx, input)
}

func (value *binding) scopedApplication(input identity.ApplicationRef) (identity.ApplicationRef, error) {
	workspaceID, err := value.workspace(input.WorkspaceID)
	if err != nil {
		return identity.ApplicationRef{}, err
	}
	applicationKey, err := value.applicationKey(input.ApplicationKey)
	if err != nil {
		return identity.ApplicationRef{}, err
	}
	input.WorkspaceID, input.ApplicationKey = workspaceID, applicationKey
	if input.TenantID == "" {
		input.TenantID = value.application.TenantID
	} else if value.application.TenantID != "" && input.TenantID != value.application.TenantID {
		return identity.ApplicationRef{}, scopeError(http.StatusForbidden, "identity.tenant_mismatch")
	}
	return input, nil
}
