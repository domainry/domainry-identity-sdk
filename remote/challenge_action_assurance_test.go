package remote

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestChallengeAwareAuthenticationReturnsChallengeWithoutInventingSession(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"challenge_required","challenge":{"provider":"sms","state":"state-a","type":"otp","purpose":"login_mfa","status":"active","masked_destination":"+86 138****0000","retry_at":"2026-09-04T00:00:30Z","expires_at":"2026-09-04T00:05:00Z"}}`))
	}))
	authentication := authentication{client: client}
	request := identity.PasswordLoginRequest{WorkspaceID: "workspace-a", Login: "user@example.test", Password: "password"}
	outcome, err := authentication.LoginWithPasswordOutcome(t.Context(), request)
	if err != nil || outcome.Status != identity.AuthenticationStatusChallengeRequired || outcome.Challenge == nil || outcome.Challenge.Purpose != "login_mfa" || outcome.Challenge.MaskedDestination == "" {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	if outcome.Session != nil {
		t.Fatal("challenge outcome contained a session")
	}
	_, err = authentication.LoginWithPassword(t.Context(), request)
	var identityError *identity.Error
	if !errors.As(err, &identityError) || identityError.Code != "auth.challenge_required" || identityError.Params["state"] != "state-a" {
		t.Fatalf("legacy login error=%#v", err)
	}
}

func TestRemoteActionAssuranceKeepsBearerOutOfJSONAndUsesItForEveryProofStep(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token-a" {
			t.Fatalf("%s authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if _, leaked := payload["access_token"]; leaked {
			t.Fatalf("%s serialized bearer token: %#v", r.URL.Path, payload)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/action-assurance/challenges":
			_, _ = w.Write([]byte(`{"provider":"sms","state":"state-a","purpose":"action_assurance","status":"active","expires_at":"2026-09-04T00:05:00Z"}`))
		case "/auth/action-assurance/challenges/verify":
			_, _ = w.Write([]byte(`{"token":"signed-receipt","workspace_id":"workspace-a","subject_id":"user-a","methods":["otp"],"expires_at":"2026-09-04T00:02:00Z"}`))
		case "/auth/action-assurance/receipts/validate":
			_, _ = w.Write([]byte(`{"token":"signed-receipt","workspace_id":"workspace-a","subject_id":"user-a","methods":["otp"],"expires_at":"2026-09-04T00:02:00Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	assurance := actionAssurance{client: client}
	challenge, err := assurance.BeginActionAssurance(t.Context(), identity.BeginActionAssuranceRequest{
		WorkspaceID: "workspace-a", AccessToken: "access-token-a",
	})
	if err != nil || challenge.State != "state-a" {
		t.Fatalf("challenge=%#v err=%v", challenge, err)
	}
	receipt, err := assurance.VerifyActionAssurance(t.Context(), identity.VerifyActionAssuranceRequest{
		WorkspaceID: "workspace-a", AccessToken: "access-token-a", Provider: "sms", State: challenge.State, Code: "123456",
	})
	if err != nil || receipt.Token != "signed-receipt" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	validated, err := assurance.ValidateActionAssuranceReceipt(t.Context(), identity.ValidateActionAssuranceReceiptRequest{
		WorkspaceID: "workspace-a", SubjectID: "user-a", Token: receipt.Token, AccessToken: "access-token-a",
	})
	if err != nil || validated.SubjectID != "user-a" {
		t.Fatalf("validated=%#v err=%v", validated, err)
	}
}
