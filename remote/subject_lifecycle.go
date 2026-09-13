package remote

import (
	"context"
	"encoding/json"
	identity "github.com/domainry/domainry-identity-sdk"
	"net/http"
	"strings"
)

func (value *binding) SystemSubjects() identity.SystemSubjects { return systemSubjects{value.client} }

type systemSubjects struct{ client *client }

func (value systemSubjects) invoke(ctx context.Context, operation string, request identity.SubjectErasureRequest) (json.RawMessage, error) {
	if err := (projectionClient{client: value.client}).requireCredential(); err != nil {
		return nil, err
	}
	if request.WorkspaceID != value.client.workspaceID || !identity.WorkspaceID(request.WorkspaceID).Valid() {
		return nil, &identity.Error{StatusCode: http.StatusForbidden, Code: "auth.workspace_mismatch"}
	}
	if strings.TrimSpace(request.SubjectID) == "" {
		return nil, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.subject_id_invalid"}
	}
	if operation == "erase" && strings.TrimSpace(request.RequestID) == "" {
		return nil, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.subject_request_id_required"}
	}
	var output json.RawMessage
	err := value.client.doJSON(ctx, http.MethodPost, "/identity/system/subjects/"+operation, value.client.serviceAccessToken, request, &output)
	return output, err
}
func (value systemSubjects) PreviewSubject(ctx context.Context, workspaceID, subjectID string) (json.RawMessage, error) {
	return value.invoke(ctx, "preview", identity.SubjectErasureRequest{WorkspaceID: workspaceID, SubjectID: subjectID})
}
func (value systemSubjects) ExportSubject(ctx context.Context, workspaceID, subjectID string) (json.RawMessage, error) {
	return value.invoke(ctx, "export", identity.SubjectErasureRequest{WorkspaceID: workspaceID, SubjectID: subjectID})
}
func (value systemSubjects) EraseSubjectForRequest(ctx context.Context, request identity.SubjectErasureRequest) (json.RawMessage, error) {
	return value.invoke(ctx, "erase", request)
}
