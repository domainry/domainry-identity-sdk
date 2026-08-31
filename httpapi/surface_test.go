package httpapi

import "testing"

func TestHTTPContractConstantsAreStable(t *testing.T) {
	if ContractVersion != "domainry-module-http-surface-v1" {
		t.Fatalf("contract version=%q", ContractVersion)
	}
	if ExposurePublic != "public" || ExposureTenantAdmin != "tenant_admin" {
		t.Fatalf("exposures=%q/%q", ExposurePublic, ExposureTenantAdmin)
	}
}
