package httpapi

import "testing"

func TestHTTPContractConstantsAreStable(t *testing.T) {
	if ContractVersion != "domainry-module-http-adapter-v1" {
		t.Fatalf("contract version=%q", ContractVersion)
	}
	if ExposurePublic != "public" || ExposureManagement != "management" {
		t.Fatalf("exposures=%q/%q", ExposurePublic, ExposureManagement)
	}
}
