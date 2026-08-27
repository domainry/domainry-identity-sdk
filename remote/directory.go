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

func (adapter directoryClient) FindDepartment(ctx context.Context, request identity.DepartmentLookup) (identity.Department, bool, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return identity.Department{}, false, err
	}
	request.DepartmentID = strings.TrimSpace(request.DepartmentID)
	if request.DepartmentID == "" {
		return identity.Department{}, false, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.department_id_invalid"}
	}
	var response struct {
		Department identity.Department `json:"department"`
		Found      bool                `json:"found"`
	}
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/runtime/directory/department", adapter.client.serviceAccessToken, request, &response); err != nil {
		return identity.Department{}, false, err
	}
	return response.Department, response.Found, nil
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

func (adapter directoryClient) ListWorkforce(ctx context.Context, request identity.DirectoryQuery) ([]identity.WorkforceEntry, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return nil, err
	}
	var values []identity.WorkforceEntry
	err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/runtime/directory/workforce", adapter.client.serviceAccessToken, request, &values)
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
