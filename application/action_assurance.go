package application

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type actionAssurance struct{ binding *binding }

func (value actionAssurance) delegate() (identity.ActionAssurance, error) {
	binding, ok := value.binding.delegate.(identity.ActionAssuranceBinding)
	if !ok || binding.ActionAssurance() == nil {
		return nil, scopeError(http.StatusNotImplemented, "identity.action_assurance_unavailable")
	}
	return binding.ActionAssurance(), nil
}

func (value actionAssurance) BeginActionAssurance(ctx context.Context, request identity.BeginActionAssuranceRequest) (identity.ProviderChallenge, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.ProviderChallenge{}, err
	}
	request.WorkspaceID = workspaceID
	delegate, err := value.delegate()
	if err != nil {
		return identity.ProviderChallenge{}, err
	}
	return delegate.BeginActionAssurance(ctx, request)
}

func (value actionAssurance) VerifyActionAssurance(ctx context.Context, request identity.VerifyActionAssuranceRequest) (identity.ActionAssuranceReceipt, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.ActionAssuranceReceipt{}, err
	}
	request.WorkspaceID = workspaceID
	delegate, err := value.delegate()
	if err != nil {
		return identity.ActionAssuranceReceipt{}, err
	}
	receipt, err := delegate.VerifyActionAssurance(ctx, request)
	if err == nil {
		err = value.validateReceipt(receipt, workspaceID, "")
	}
	return receipt, err
}

func (value actionAssurance) ValidateActionAssuranceReceipt(ctx context.Context, request identity.ValidateActionAssuranceReceiptRequest) (identity.ActionAssuranceReceipt, error) {
	workspaceID, err := value.binding.workspace(request.WorkspaceID)
	if err != nil {
		return identity.ActionAssuranceReceipt{}, err
	}
	request.WorkspaceID = workspaceID
	delegate, err := value.delegate()
	if err != nil {
		return identity.ActionAssuranceReceipt{}, err
	}
	receipt, err := delegate.ValidateActionAssuranceReceipt(ctx, request)
	if err == nil {
		err = value.validateReceipt(receipt, workspaceID, request.SubjectID)
	}
	return receipt, err
}

func (value actionAssurance) validateReceipt(receipt identity.ActionAssuranceReceipt, workspaceID identity.WorkspaceID, subjectID identity.SubjectID) error {
	if strings.TrimSpace(receipt.Token) == "" || receipt.WorkspaceID != workspaceID || !receipt.SubjectID.Valid() || subjectID != "" && receipt.SubjectID != subjectID || len(receipt.Methods) == 0 || strings.TrimSpace(receipt.ExpiresAt) == "" {
		return scopeError(http.StatusBadGateway, "identity.action_assurance_receipt_invalid")
	}
	return nil
}

var _ identity.ActionAssurance = actionAssurance{}
