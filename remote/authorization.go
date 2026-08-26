package remote

import (
	"context"
	"net/http"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func (c *Client) Authorize(ctx context.Context, identity identitysdk.RequestIdentity, request identitysdk.AccessRequest) (identitysdk.AccessDecision, error) {
	if !identity.Principal.Known || strings.TrimSpace(identity.Principal.UserID) == "" || strings.TrimSpace(identity.AccessToken) == "" {
		return identitysdk.AccessDecision{}, &identitysdk.Error{StatusCode: http.StatusUnauthorized, Code: "auth.token_required"}
	}
	request.ObjectKey = strings.TrimSpace(request.ObjectKey)
	request.Action = strings.TrimSpace(request.Action)
	request.FieldKey = strings.TrimSpace(request.FieldKey)
	request.RecordID = strings.TrimSpace(request.RecordID)
	if request.ObjectKey == "" || request.Action == "" {
		return identitysdk.AccessDecision{}, &identitysdk.Error{StatusCode: http.StatusBadRequest, Code: "identity.access_request_invalid"}
	}
	payload := struct {
		UserID    string `json:"user_id"`
		ObjectKey string `json:"object_key"`
		Action    string `json:"action"`
		FieldKey  string `json:"field_key,omitempty"`
		RecordID  string `json:"record_id,omitempty"`
	}{
		UserID: identity.Principal.UserID, ObjectKey: request.ObjectKey, Action: request.Action,
		FieldKey: request.FieldKey, RecordID: request.RecordID,
	}
	var decision identitysdk.AccessDecision
	if err := c.doJSON(ctx, http.MethodPost, "/identity/access/explain", identity.AccessToken, payload, &decision); err != nil {
		return identitysdk.AccessDecision{}, err
	}
	return decision, nil
}
