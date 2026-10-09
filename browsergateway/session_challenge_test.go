package browsergateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestBrowserChallengeReturnsResolvedWorkspaceForVerification(t *testing.T) {
	response := httptest.NewRecorder()
	gateway := &Gateway{}
	gateway.writeBrowserAuthenticationOutcome(response, "workspace-resolved", identity.AuthenticationOutcome{
		Status: identity.AuthenticationStatusChallengeRequired,
		Challenge: &identity.ProviderChallenge{
			Provider: "domainry_totp", State: "state-1", Type: "otp", Purpose: "login_mfa", ExpiresAt: "2026-09-28T10:00:00Z",
		},
	})

	var body struct {
		Status      identity.AuthenticationStatus `json:"status"`
		WorkspaceID identity.WorkspaceID          `json:"workspace_id"`
		Challenge   *identity.ProviderChallenge   `json:"challenge"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || body.Status != identity.AuthenticationStatusChallengeRequired || body.WorkspaceID != "workspace-resolved" || body.Challenge == nil || body.Challenge.State != "state-1" {
		t.Fatalf("status=%d body=%#v", response.Code, body)
	}
}
