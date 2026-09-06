package modulehost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestInstallationAdministratorBootstrapContractHashAndTransportExclusion(t *testing.T) {
	digest := sha256.Sum256([]byte(InstallationAdministratorBootstrapContractCanonicalV1))
	if got := hex.EncodeToString(digest[:]); got != InstallationAdministratorBootstrapContractHashV1 {
		t.Fatalf("contract hash=%q", got)
	}
	encoded, err := json.Marshal(InstallationAdministratorBootstrapRequest{
		ContractVersion: CurrentInstallationAdministratorBootstrapContractVersion,
		ContractHash:    CurrentInstallationAdministratorBootstrapContractHash,
		InvocationID:    "bootstrap-admin", WorkspaceID: "workspace-secret",
		LoginID: "installation@example.test", Name: "Installation Admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "{}" {
		t.Fatalf("embedded request leaked onto JSON transport: %s", encoded)
	}
}
