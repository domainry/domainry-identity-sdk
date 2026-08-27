package browsergateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type browserRequestScope struct {
	TenantID    identity.TenantID    `json:"tenant_id,omitempty"`
	WorkspaceID identity.WorkspaceID `json:"workspace_id,omitempty"`
}

func (gateway *Gateway) workspaceID(w http.ResponseWriter, r *http.Request, body identity.WorkspaceID) (identity.WorkspaceID, bool) {
	values := []string{strings.TrimSpace(r.Header.Get("X-Workspace-ID")), strings.TrimSpace(r.URL.Query().Get("workspace_id")), strings.TrimSpace(string(body))}
	resolved := ""
	for _, value := range values {
		if value == "" {
			continue
		}
		if resolved != "" && resolved != value {
			gateway.writeCode(w, http.StatusBadRequest, "identity.workspace_scope_mismatch")
			return "", false
		}
		resolved = value
	}
	if resolved == "" {
		resolved = string(gateway.config.DefaultWorkspaceID)
	}
	workspaceID := identity.WorkspaceID(resolved)
	if !workspaceID.Valid() {
		gateway.writeCode(w, http.StatusBadRequest, "backend.workspace_scope_required")
		return "", false
	}
	return workspaceID, true
}

func (gateway *Gateway) decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, gateway.config.MaxRequestBodySize))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		gateway.writeCode(w, http.StatusBadRequest, "backend.invalid_json")
		return false
	}
	if err := decoder.Decode(&struct{}{}); errors.Is(err, io.EOF) {
		return true
	}
	gateway.writeCode(w, http.StatusBadRequest, "backend.invalid_json")
	return false
}

func bearerToken(value string) string {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
