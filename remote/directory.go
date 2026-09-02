package remote

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type directoryClient struct{ client *client }

func (adapter directoryClient) FindUser(ctx context.Context, request identity.UserLookup) (identity.User, bool, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return identity.User{}, false, err
	}
	if !request.UserID.Valid() {
		return identity.User{}, false, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.user_id_invalid"}
	}
	var response struct {
		User  identity.User `json:"user"`
		Found bool          `json:"found"`
	}
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/runtime/directory/user", adapter.client.serviceAccessToken, request, &response); err != nil {
		return identity.User{}, false, err
	}
	return response.User, response.Found, nil
}

func (adapter directoryClient) FindOrganizationUnit(ctx context.Context, request identity.OrganizationUnitLookup) (identity.OrganizationUnit, bool, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return identity.OrganizationUnit{}, false, err
	}
	request.OrgID = strings.TrimSpace(request.OrgID)
	if request.OrgID == "" {
		return identity.OrganizationUnit{}, false, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.org_id_invalid"}
	}
	var response struct {
		OrganizationUnit identity.OrganizationUnit `json:"organization_unit"`
		Found            bool                      `json:"found"`
	}
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/runtime/directory/organization-unit", adapter.client.serviceAccessToken, request, &response); err != nil {
		return identity.OrganizationUnit{}, false, err
	}
	return response.OrganizationUnit, response.Found, nil
}

func (adapter directoryClient) ListUsers(ctx context.Context, request identity.DirectoryQuery) ([]identity.User, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return nil, err
	}
	var values []identity.User
	err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/runtime/directory/users", adapter.client.serviceAccessToken, request, &values)
	return values, err
}

func (adapter directoryClient) ListRoles(ctx context.Context, request identity.DirectoryQuery) ([]identity.Role, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return nil, err
	}
	var values []identity.Role
	err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/runtime/directory/roles", adapter.client.serviceAccessToken, request, &values)
	return values, err
}

func (adapter directoryClient) ListUserRoleAssignments(ctx context.Context, request identity.UserRoleAssignmentQuery) ([]identity.UserRoleAssignment, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return nil, err
	}
	var values []identity.UserRoleAssignment
	err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/runtime/directory/role-assignments", adapter.client.serviceAccessToken, request, &values)
	return values, err
}

func (adapter directoryClient) normalizeScope(scope *identity.ApplicationScope) error {
	if adapter.client == nil || strings.TrimSpace(adapter.client.serviceAccessToken) == "" {
		return &identity.Error{StatusCode: http.StatusServiceUnavailable, Code: "identity.service_credential_required"}
	}
	workspaceID := identity.WorkspaceID(adapter.client.resolveWorkspace(string(scope.WorkspaceID)))
	if err := (authentication{client: adapter.client}).requireWorkspace(workspaceID); err != nil {
		return err
	}
	applicationKey, err := adapter.client.resolveApplication(string(scope.ApplicationKey))
	if err != nil {
		return err
	}
	scope.WorkspaceID = workspaceID
	if !scope.TenantID.Valid() {
		scope.TenantID = identity.TenantID(workspaceID)
	}
	scope.ApplicationKey = identity.ApplicationKey(applicationKey)
	return nil
}

var _ identity.Directory = directoryClient{}
