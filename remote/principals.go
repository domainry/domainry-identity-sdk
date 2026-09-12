package remote

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type principalResolver struct{ client *client }

func (adapter principalResolver) Resolve(ctx context.Context, request identity.PrincipalResolutionRequest) (identity.PrincipalResolution, error) {
	if err := (projectionClient{client: adapter.client}).requireCredential(); err != nil {
		return identity.PrincipalResolution{}, err
	}
	request.RoleKey = strings.TrimSpace(request.RoleKey)
	if request.Workload != nil {
		request.Workload.WorkflowKey = strings.TrimSpace(request.Workload.WorkflowKey)
		request.Workload.DefinitionVersionID = strings.TrimSpace(request.Workload.DefinitionVersionID)
		request.Workload.ReleaseID = strings.TrimSpace(request.Workload.ReleaseID)
		request.Workload.ReleaseDigest = strings.TrimSpace(request.Workload.ReleaseDigest)
	}
	if !request.SubjectID.Valid() {
		return identity.PrincipalResolution{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.subject_id_invalid"}
	}
	var resolution identity.PrincipalResolution
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/principal/resolve", adapter.client.serviceAccessToken, request, &resolution); err != nil {
		return identity.PrincipalResolution{}, err
	}
	workspaceID := identity.WorkspaceID(adapter.client.resolveWorkspace(""))
	if resolution.Principal.WorkspaceID != string(workspaceID) || resolution.Principal.UserID != string(request.SubjectID) ||
		resolution.AccessBundle.Subject.WorkspaceID != workspaceID || resolution.AccessBundle.Subject.SubjectID != request.SubjectID {
		return identity.PrincipalResolution{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.principal_response_invalid"}
	}
	resolution.Principal.AccessBundle = &resolution.AccessBundle
	return resolution, nil
}

var _ identity.PrincipalResolver = principalResolver{}
