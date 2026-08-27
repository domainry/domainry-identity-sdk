package remote

import (
	"context"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type authorization struct{ client *client }

func (adapter authorization) ResolveAccess(ctx context.Context, request identity.AccessBundleRequest) (identity.AccessBundle, error) {
	if !request.Identity.Principal.Known || strings.TrimSpace(request.Identity.AccessToken) == "" {
		return identity.AccessBundle{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "auth.token_required"}
	}
	payload := map[string]string{"resource_type": string(request.ResourceType), "action": string(request.Action)}
	var bundle identity.AccessBundle
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/access-bundle", request.Identity.AccessToken, payload, &bundle); err != nil {
		return identity.AccessBundle{}, err
	}
	if err := bundle.Validate(adapter.client.now()); err != nil {
		return identity.AccessBundle{}, err
	}
	return bundle, nil
}

func (adapter authorization) Reauthorize(ctx context.Context, request identity.DecisionRequest) (identity.AccessDecision, error) {
	if !request.Identity.Principal.Known || strings.TrimSpace(request.Identity.AccessToken) == "" {
		return identity.AccessDecision{}, &identity.Error{StatusCode: http.StatusUnauthorized, Code: "auth.token_required"}
	}
	request.Access.ObjectKey = strings.TrimSpace(request.Access.ObjectKey)
	request.Access.Action = strings.TrimSpace(request.Access.Action)
	request.Access.FieldKey = strings.TrimSpace(request.Access.FieldKey)
	request.Access.RecordID = strings.TrimSpace(request.Access.RecordID)
	if request.Access.ObjectKey == "" || request.Access.Action == "" {
		return identity.AccessDecision{}, &identity.Error{StatusCode: http.StatusBadRequest, Code: "identity.access_request_invalid"}
	}
	payload := struct {
		Access identity.AccessRequest `json:"access"`
		Facts  identity.ResourceFacts `json:"facts,omitempty"`
	}{Access: request.Access, Facts: request.Facts}
	var decision identity.AccessDecision
	if err := adapter.client.doJSON(ctx, http.MethodPost, "/identity/reauthorize", request.Identity.AccessToken, payload, &decision); err != nil {
		return identity.AccessDecision{}, err
	}
	return decision, nil
}
