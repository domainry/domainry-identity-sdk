package identity

import (
	"context"
	"encoding/json"
)

// SystemSubjects is a trusted host capability. It is never available through
// end-user bearer authentication or the browser gateway.
type SystemSubjects interface {
	PreviewSubject(context.Context, string, string) (json.RawMessage, error)
	ExportSubject(context.Context, string, string) (json.RawMessage, error)
	EraseSubjectForRequest(context.Context, SubjectErasureRequest) (json.RawMessage, error)
}

type SubjectErasureRequest struct {
	WorkspaceID string          `json:"workspace_id"`
	SubjectID   string          `json:"subject_id"`
	RequestID   string          `json:"request_id"`
	LegalHolds  json.RawMessage `json:"legal_holds,omitempty"`
}

type SystemSubjectBinding interface{ SystemSubjects() SystemSubjects }
