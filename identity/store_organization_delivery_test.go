package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStoreOrganizationDeliveryContractCarriesNoCallerAuthorityOrTenant(t *testing.T) {
	request := StoreOrganizationDeliveryRequest{
		ContractVersion: StoreOrganizationDeliveryContractVersionV1,
		AccessToken:     "secret-bearer",
		IdempotencyKey:  "store-create-1",
		Organization: StoreOrganizationMutation{
			Operation: StoreOrganizationCreate, OrganizationID: "store-1", Code: "S1", Name: "Store One", ParentOrganizationID: "company", ExpectedVersion: 0,
		},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-bearer", "workspace", "tenant", "actor", "role", "node_type"} {
		if strings.Contains(strings.ToLower(string(payload)), forbidden) {
			t.Fatalf("serialized StoreOrganization authority %q: %s", forbidden, payload)
		}
	}
	if !StoreOrganizationCreate.Valid() || !StoreOrganizationRename.Valid() || !StoreOrganizationDisable.Valid() || StoreOrganizationOperation("other").Valid() {
		t.Fatal("StoreOrganization operation validation contract changed")
	}
}

func TestStoreOrganizationListContractIsBoundedAndSerializable(t *testing.T) {
	request := StoreOrganizationListRequest{
		ContractVersion: StoreOrganizationDeliveryContractVersionV1,
		AccessToken:     "secret-bearer",
		PageSize:        StoreOrganizationMaxPageSize,
		Cursor:          "opaque-cursor",
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(payload)
	if strings.Contains(serialized, "secret-bearer") || !strings.Contains(serialized, `"page_size":100`) || !strings.Contains(serialized, `"cursor":"opaque-cursor"`) {
		t.Fatalf("serialized StoreOrganization list request=%s", payload)
	}
	if StoreOrganizationDefaultPageSize <= 0 || StoreOrganizationMaxPageSize < StoreOrganizationDefaultPageSize {
		t.Fatalf("invalid page bounds default=%d max=%d", StoreOrganizationDefaultPageSize, StoreOrganizationMaxPageSize)
	}
}
