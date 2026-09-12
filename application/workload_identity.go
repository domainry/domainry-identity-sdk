package application

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type workflowWorkloads struct{ binding *binding }

func (value workflowWorkloads) delegate() (identity.WorkflowWorkloadIdentity, error) {
	capability, ok := value.binding.delegate.(identity.WorkflowWorkloadIdentityBinding)
	if !ok || capability.WorkflowWorkloads() == nil {
		return nil, scopeError(http.StatusNotImplemented, "identity.workflow_workload_unavailable")
	}
	return capability.WorkflowWorkloads(), nil
}

func (value workflowWorkloads) ApplyWorkflowWorkloadBindings(ctx context.Context, request identity.ApplyWorkflowWorkloadBindingsRequest) (identity.ApplyWorkflowWorkloadBindingsResult, error) {
	application, err := value.binding.applicationScope(ctx, request.Application)
	if err != nil {
		return identity.ApplyWorkflowWorkloadBindingsResult{}, err
	}
	request.Application = application
	capability, err := value.delegate()
	if err != nil {
		return identity.ApplyWorkflowWorkloadBindingsResult{}, err
	}
	return capability.ApplyWorkflowWorkloadBindings(ctx, request)
}

func (value workflowWorkloads) GetWorkflowWorkloadBinding(ctx context.Context, request identity.GetWorkflowWorkloadBindingRequest) (identity.WorkflowWorkloadBinding, error) {
	application, err := value.binding.applicationScope(ctx, request.Application)
	if err != nil {
		return identity.WorkflowWorkloadBinding{}, err
	}
	request.Application = application
	capability, err := value.delegate()
	if err != nil {
		return identity.WorkflowWorkloadBinding{}, err
	}
	return capability.GetWorkflowWorkloadBinding(ctx, request)
}

var _ identity.WorkflowWorkloadIdentity = workflowWorkloads{}
var _ identity.WorkflowWorkloadIdentityBinding = (*binding)(nil)
