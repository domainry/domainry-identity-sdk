package management

import "testing"

func TestContractVersionIsStable(t *testing.T) {
	if ContractVersion != "domainry-identity-management-surface-v1" {
		t.Fatalf("contract version=%q", ContractVersion)
	}
}
