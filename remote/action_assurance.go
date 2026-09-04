package remote

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type actionAssurance struct{ client *client }

func (adapter actionAssurance) BeginActionAssurance(ctx context.Context, request identity.BeginActionAssuranceRequest) (identity.ProviderChallenge, error) {
	if err := (authentication{client: adapter.client}).requireWorkspace(request.WorkspaceID); err != nil {
		return identity.ProviderChallenge{}, err
	}
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	if strings.TrimSpace(request.AccessToken) == "" {
		return identity.ProviderChallenge{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "auth.token_required"}
	}
	var challenge identity.ProviderChallenge
	err := adapter.client.doJSON(ctx, http.MethodPost, "/auth/action-assurance/challenges", request.AccessToken, request, &challenge)
	return challenge, err
}

func (adapter actionAssurance) VerifyActionAssurance(ctx context.Context, request identity.VerifyActionAssuranceRequest) (identity.ActionAssuranceReceipt, error) {
	if err := (authentication{client: adapter.client}).requireWorkspace(request.WorkspaceID); err != nil {
		return identity.ActionAssuranceReceipt{}, err
	}
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	request.Provider, request.State, request.Code = strings.TrimSpace(request.Provider), strings.TrimSpace(request.State), strings.TrimSpace(request.Code)
	if strings.TrimSpace(request.AccessToken) == "" || request.Provider == "" || request.State == "" || request.Code == "" {
		return identity.ActionAssuranceReceipt{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "auth.action_assurance_verify_request_invalid"}
	}
	var receipt identity.ActionAssuranceReceipt
	err := adapter.client.doJSON(ctx, http.MethodPost, "/auth/action-assurance/challenges/verify", request.AccessToken, request, &receipt)
	return receipt, err
}

func (adapter actionAssurance) ValidateActionAssuranceReceipt(ctx context.Context, request identity.ValidateActionAssuranceReceiptRequest) (identity.ActionAssuranceReceipt, error) {
	if err := (authentication{client: adapter.client}).requireWorkspace(request.WorkspaceID); err != nil {
		return identity.ActionAssuranceReceipt{}, err
	}
	request.WorkspaceID = identity.WorkspaceID(adapter.client.resolveWorkspace(string(request.WorkspaceID)))
	if strings.TrimSpace(request.AccessToken) == "" || strings.TrimSpace(request.Token) == "" || !request.SubjectID.Valid() {
		return identity.ActionAssuranceReceipt{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "auth.action_assurance_receipt_request_invalid"}
	}
	var receipt identity.ActionAssuranceReceipt
	err := adapter.client.doJSON(ctx, http.MethodPost, "/auth/action-assurance/receipts/validate", request.AccessToken, request, &receipt)
	return receipt, err
}

var _ identity.ActionAssurance = actionAssurance{}
