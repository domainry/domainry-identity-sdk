package modulehost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkspaceProvisioningPasswordNeverEntersSerializedContract(t *testing.T) {
	raw, err := json.Marshal(WorkspaceIdentityProvisionRequest{
		WorkspaceID: "workspace-primary", AdminLoginID: "admin@example.test", AdminName: "Admin", InitialPassword: "Secret1!Bootstrap",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Secret1!Bootstrap") || strings.Contains(string(raw), "initial_password") {
		t.Fatalf("bootstrap password escaped in serialized request: %s", raw)
	}
}

func TestWorkspaceIdentityBootstrapIsNonHTTPAndCredentialNeverSerializes(t *testing.T) {
	requestJSON, err := json.Marshal(WorkspaceIdentityBootstrapRequest{
		ContractVersion: WorkspaceIdentityBootstrapContractVersion,
		ContractHash:    WorkspaceIdentityBootstrapContractHash,
		InvocationID:    "invocation", WorkspaceID: "workspace", CompanyID: "company",
		CompanyCode: "COMPANY", CompanyName: "Company", FirstStoreID: "store",
		FirstStoreCode: "STORE", FirstStoreName: "Store", InitialAdminUserID: "user",
		InitialAdminLoginID: "admin@example.test", InitialAdminName: "Admin", InitialAdminPassword: "domainry!123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(requestJSON) != "{}" {
		t.Fatalf("trusted bootstrap command became serializable: %s", requestJSON)
	}
	credentialJSON, err := json.Marshal(WorkspaceIdentityBootstrapOneTimeCredential{
		LoginID: "admin@example.test", InitialPassword: "NeverPersist1!", MustChangePassword: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(credentialJSON) != "{}" || strings.Contains(string(credentialJSON), "NeverPersist1!") {
		t.Fatalf("one-time credential became serializable: %s", credentialJSON)
	}
	completionJSON, err := json.Marshal(WorkspaceIdentityBootstrapCompletion{
		WorkspaceID: "workspace", ReceiptID: "receipt", Outcome: WorkspaceIdentityBootstrapTransactionRolledBack,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(completionJSON) != "{}" {
		t.Fatalf("trusted transaction completion became serializable: %s", completionJSON)
	}
}

func TestWorkspaceIdentityBootstrapContractConstantsArePinned(t *testing.T) {
	if WorkspaceIdentityBootstrapContractVersion != "domainry-workspace-identity-bootstrap-v4" {
		t.Fatalf("version=%q", WorkspaceIdentityBootstrapContractVersion)
	}
	if WorkspaceIdentityBootstrapContractHash != "a45006763a7f31393506426c8dd57d55a0dd2036426f0e43cd8ece49bcdd7c82" {
		t.Fatalf("hash=%q", WorkspaceIdentityBootstrapContractHash)
	}
	digest := sha256.Sum256([]byte(WorkspaceIdentityBootstrapContractCanonical))
	if actual := hex.EncodeToString(digest[:]); actual != WorkspaceIdentityBootstrapContractHash {
		t.Fatalf("canonical contract hash=%q", actual)
	}
}
