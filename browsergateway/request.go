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
	WorkspaceID identity.WorkspaceID `json:"workspace_id,omitempty"`
}

type browserPasswordLoginRequest struct {
	WorkspaceID    identity.WorkspaceID    `json:"workspace_id,omitempty"`
	ApplicationKey identity.ApplicationKey `json:"application_key,omitempty"`
	Login          string                  `json:"login"`
	Password       string                  `json:"password"`
}

type browserProviderStartRequest struct {
	WorkspaceID    identity.WorkspaceID    `json:"workspace_id,omitempty"`
	ApplicationKey identity.ApplicationKey `json:"application_key,omitempty"`
	ReturnURL      string                  `json:"return_url,omitempty"`
	Phone          string                  `json:"phone,omitempty"`
}

type browserVerifyOTPRequest struct {
	WorkspaceID identity.WorkspaceID `json:"workspace_id,omitempty"`
	State       string               `json:"state"`
	Code        string               `json:"code"`
}

type browserAuthorizationCodeExchangeRequest struct {
	WorkspaceID    identity.WorkspaceID    `json:"workspace_id,omitempty"`
	ApplicationKey identity.ApplicationKey `json:"application_key,omitempty"`
	Code           string                  `json:"code"`
	ReturnURL      string                  `json:"return_url"`
}

func (gateway *Gateway) workspaceID(w http.ResponseWriter, r *http.Request, body identity.WorkspaceID) (identity.WorkspaceID, bool) {
	if gateway.rejectNonWorkspaceBoundary(w, r) {
		return "", false
	}
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
	if resolved == "" && gateway.config.RequireExplicitWorkspace {
		gateway.writeCode(w, http.StatusForbidden, "auth.invalid_credentials")
		return "", false
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
	if gateway.rejectNonWorkspaceBoundary(w, r) {
		return false
	}
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

// rejectNonWorkspaceBoundary prevents legacy tenant selectors from being
// silently ignored in headers or query parameters. JSON tenant_id is rejected
// separately by DisallowUnknownFields on the browser-specific DTOs.
func (gateway *Gateway) rejectNonWorkspaceBoundary(w http.ResponseWriter, r *http.Request) bool {
	_, tenantQueryPresent := r.URL.Query()["tenant_id"]
	tenantHeaderPresent := false
	for name := range r.Header {
		if strings.EqualFold(name, "X-Tenant-ID") {
			tenantHeaderPresent = true
			break
		}
	}
	if tenantQueryPresent || tenantHeaderPresent {
		gateway.writeCode(w, http.StatusBadRequest, "identity.workspace_scope_only")
		return true
	}
	return false
}

func bearerToken(value string) string {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
