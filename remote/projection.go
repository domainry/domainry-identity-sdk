package remote

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type projectionClient struct{ client *client }

func (adapter projectionClient) FindUser(ctx context.Context, request identity.UserLookup) (identity.User, bool, error) {
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
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/users/lookup", adapter.client.serviceAccessToken, request, &response); err != nil {
		return identity.User{}, false, err
	}
	return response.User, response.Found, nil
}

func (adapter projectionClient) FindOrganizationUnit(ctx context.Context, request identity.OrganizationUnitLookup) (identity.OrganizationUnit, bool, error) {
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
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/organization-units/lookup", adapter.client.serviceAccessToken, request, &response); err != nil {
		return identity.OrganizationUnit{}, false, err
	}
	return response.OrganizationUnit, response.Found, nil
}

func (adapter projectionClient) ListUsers(ctx context.Context, request identity.ProjectionQuery) ([]identity.User, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return nil, err
	}
	var values []identity.User
	err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/users/query", adapter.client.serviceAccessToken, request, &values)
	return values, err
}

func (adapter projectionClient) ListRoles(ctx context.Context, request identity.ProjectionQuery) ([]identity.Role, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return nil, err
	}
	var values []identity.Role
	err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/roles/query", adapter.client.serviceAccessToken, request, &values)
	return values, err
}

func (adapter projectionClient) ListUserRoleAssignments(ctx context.Context, request identity.UserRoleAssignmentQuery) ([]identity.UserRoleAssignment, error) {
	if err := adapter.normalizeScope(&request.Application); err != nil {
		return nil, err
	}
	var values []identity.UserRoleAssignment
	err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/user-role-assignments/query", adapter.client.serviceAccessToken, request, &values)
	return values, err
}

func (adapter projectionClient) normalizeScope(scope *identity.ApplicationScope) error {
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

var _ identity.Projection = projectionClient{}
