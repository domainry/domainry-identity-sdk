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

func TestWorkspaceIdentityBootstrapV2IsNonHTTPAndCredentialNeverSerializes(t *testing.T) {
	requestJSON, err := json.Marshal(WorkspaceIdentityBootstrapV2Request{
		ContractVersion: CurrentWorkspaceIdentityBootstrapContractVersion,
		ContractHash:    CurrentWorkspaceIdentityBootstrapContractHash,
		InvocationID:    "invocation", WorkspaceID: "workspace", CompanyID: "company",
		CompanyCode: "COMPANY", CompanyName: "Company", FirstStoreID: "store",
		FirstStoreCode: "STORE", FirstStoreName: "Store", InitialAdminUserID: "user",
		InitialAdminLoginID: "admin@example.test", InitialAdminName: "Admin",
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

func TestWorkspaceIdentityBootstrapV2ContractConstantsArePinned(t *testing.T) {
	if CurrentWorkspaceIdentityBootstrapContractVersion != "domainry-workspace-identity-bootstrap-v2" {
		t.Fatalf("version=%q", CurrentWorkspaceIdentityBootstrapContractVersion)
	}
	if CurrentWorkspaceIdentityBootstrapContractHash != "5011287354029d67c64e1f9dedf3767234c9af8d7ec7e29886a9b4b419ccc9c8" {
		t.Fatalf("hash=%q", CurrentWorkspaceIdentityBootstrapContractHash)
	}
	digest := sha256.Sum256([]byte(WorkspaceIdentityBootstrapContractCanonicalV2))
	if actual := hex.EncodeToString(digest[:]); actual != CurrentWorkspaceIdentityBootstrapContractHash {
		t.Fatalf("canonical contract hash=%q", actual)
	}
}
