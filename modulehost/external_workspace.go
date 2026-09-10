package modulehost

import "context"

type ExternalWorkspaceCreate struct {
	WorkspaceID          string
	Name                 string
	UserID               string
	ApplicationBootstrap map[string]any
}

// ExternalWorkspaceHost is a trusted, transaction-bound host capability. It is
// never exposed as a browser API. The host owns _workspaces and application
// bootstrap data; the module owns external identities and personal ownership.
// Transaction callbacks contain only database effects and may be retried.
type ExternalWorkspaceHost interface {
	RunExternalWorkspaceTransaction(context.Context, func(context.Context, Transaction) error) error
	CreateExternalWorkspace(context.Context, ExternalWorkspaceCreate, Transaction) error
	InitializeExternalWorkspaceApplication(context.Context, ExternalWorkspaceCreate, Transaction) error
	ExternalWorkspaceActive(context.Context, string) (bool, error)
}
