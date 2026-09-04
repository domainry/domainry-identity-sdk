package remote

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type principalResolver struct{ client *client }

func (adapter principalResolver) Resolve(ctx context.Context, request identity.PrincipalResolutionRequest) (identity.PrincipalResolution, error) {
	if err := (projectionClient{client: adapter.client}).normalizeScope(&request.Application); err != nil {
		return identity.PrincipalResolution{}, err
	}
	request.RoleKey = strings.TrimSpace(request.RoleKey)
	if !request.SubjectID.Valid() {
		return identity.PrincipalResolution{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.subject_id_invalid"}
	}
	var resolution identity.PrincipalResolution
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/principal/resolve", adapter.client.serviceAccessToken, request, &resolution); err != nil {
		return identity.PrincipalResolution{}, err
	}
	if resolution.Principal.WorkspaceID != string(request.Application.WorkspaceID) || resolution.Principal.UserID != string(request.SubjectID) ||
		resolution.AccessBundle.Subject.WorkspaceID != request.Application.WorkspaceID || resolution.AccessBundle.Subject.SubjectID != request.SubjectID {
		return identity.PrincipalResolution{}, &identity.Error{StatusCode: http.StatusBadGateway, Code: "identity.principal_response_invalid"}
	}
	resolution.Principal.AccessBundle = &resolution.AccessBundle
	return resolution, nil
}

var _ identity.PrincipalResolver = principalResolver{}
