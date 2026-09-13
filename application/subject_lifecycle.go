package application

import (
	"context"
	"encoding/json"
	"github.com/domainry/domainry-foundation/requestcontext"
	identity "github.com/domainry/domainry-identity-sdk"
	"net/http"
)

func (value *binding) SystemSubjects() identity.SystemSubjects { return systemSubjects{value} }
func (value *applicationServiceBinding) SystemSubjects() identity.SystemSubjects {
	return value.binding.SystemSubjects()
}
func (value *applicationServiceVerificationBinding) SystemSubjects() identity.SystemSubjects {
	return value.binding.SystemSubjects()
}

type systemSubjects struct{ binding *binding }

func (value systemSubjects) delegate(ctx context.Context, workspaceID string) (identity.SystemSubjects, error) {
	if !identity.WorkspaceID(workspaceID).Valid() {
		return nil, scopeError(http.StatusBadRequest, "identity.workspace_id_invalid")
	}
	if _, err := value.binding.workspace(ctx, identity.WorkspaceID(workspaceID)); err != nil {
		return nil, err
	}
	capability, ok := value.binding.delegate.(identity.SystemSubjectBinding)
	if !ok || capability.SystemSubjects() == nil {
		return nil, scopeError(http.StatusNotImplemented, "identity.subject_lifecycle_unavailable")
	}
	return capability.SystemSubjects(), nil
}
func (value systemSubjects) PreviewSubject(ctx context.Context, workspaceID, subjectID string) (json.RawMessage, error) {
	delegate, err := value.delegate(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	return delegate.PreviewSubject(requestcontext.WithWorkspaceID(ctx, workspaceID), workspaceID, subjectID)
}
func (value systemSubjects) ExportSubject(ctx context.Context, workspaceID, subjectID string) (json.RawMessage, error) {
	delegate, err := value.delegate(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	return delegate.ExportSubject(requestcontext.WithWorkspaceID(ctx, workspaceID), workspaceID, subjectID)
}
func (value systemSubjects) EraseSubjectForRequest(ctx context.Context, request identity.SubjectErasureRequest) (json.RawMessage, error) {
	delegate, err := value.delegate(ctx, request.WorkspaceID)
	if err != nil {
		return nil, err
	}
	return delegate.EraseSubjectForRequest(requestcontext.WithWorkspaceID(ctx, request.WorkspaceID), request)
}
