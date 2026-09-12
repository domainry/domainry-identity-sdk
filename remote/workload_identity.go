package remote

import (
	"context"
	"net/http"

	identity "github.com/domainry/domainry-identity-sdk"
)

type workflowWorkloads struct{ client *client }

func (adapter workflowWorkloads) ApplyWorkflowWorkloadBindings(ctx context.Context, request identity.ApplyWorkflowWorkloadBindingsRequest) (identity.ApplyWorkflowWorkloadBindingsResult, error) {
	if err := (projectionClient{client: adapter.client}).normalizeScope(&request.Application); err != nil {
		return identity.ApplyWorkflowWorkloadBindingsResult{}, err
	}
	if err := request.Validate(); err != nil {
		return identity.ApplyWorkflowWorkloadBindingsResult{}, err
	}
	var result identity.ApplyWorkflowWorkloadBindingsResult
	if err := adapter.client.doJSON(ctx, http.MethodPut, "/identity/workflow-workloads", adapter.client.serviceAccessToken, request, &result); err != nil {
		return identity.ApplyWorkflowWorkloadBindingsResult{}, err
	}
	return result, nil
}

func (adapter workflowWorkloads) GetWorkflowWorkloadBinding(ctx context.Context, request identity.GetWorkflowWorkloadBindingRequest) (identity.WorkflowWorkloadBinding, error) {
	if err := (projectionClient{client: adapter.client}).normalizeScope(&request.Application); err != nil {
		return identity.WorkflowWorkloadBinding{}, err
	}
	if err := request.Validate(); err != nil {
		return identity.WorkflowWorkloadBinding{}, err
	}
	var result identity.WorkflowWorkloadBinding
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/workflow-workloads/resolve", adapter.client.serviceAccessToken, request, &result); err != nil {
		return identity.WorkflowWorkloadBinding{}, err
	}
	return result, nil
}

var _ identity.WorkflowWorkloadIdentity = workflowWorkloads{}
