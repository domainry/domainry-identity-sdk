package identity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestWorkspaceIdentityUsageContractCarriesNoWorkspaceSelectionOrPII(t *testing.T) {
	request := WorkspaceIdentityUsageRequest{
		ContractVersion: CurrentWorkspaceIdentityUsageContractVersion,
		ContractHash:    CurrentWorkspaceIdentityUsageContractHash,
		AccessToken:     "installation-secret",
		PageSize:        WorkspaceIdentityUsageMaxPageSize,
		Cursor:          "opaque-cursor",
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	serialized := strings.ToLower(string(payload))
	for _, forbidden := range []string{"installation-secret", "workspace_id", "workspace_ids", "tenant", "email", "name", "phone", "user"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("serialized usage request contains %q: %s", forbidden, payload)
		}
	}
	if !strings.Contains(serialized, `"contract_hash":"`+CurrentWorkspaceIdentityUsageContractHash+`"`) || !strings.Contains(serialized, `"page_size":100`) || !strings.Contains(serialized, `"cursor":"opaque-cursor"`) {
		t.Fatalf("serialized usage request lost bounded paging: %s", payload)
	}
	requestType := reflect.TypeOf(request)
	for index := 0; index < requestType.NumField(); index++ {
		name := strings.ToLower(requestType.Field(index).Name)
		if strings.Contains(name, "workspace") || strings.Contains(name, "tenant") {
			t.Fatalf("caller request exposes boundary selection field %q", requestType.Field(index).Name)
		}
	}
}

func TestWorkspaceIdentityUsageExactResolveKeepsPhysicalWorkspaceIDOffJSON(t *testing.T) {
	payload, err := json.Marshal(WorkspaceIdentityUsageResolveRequest{
		ContractVersion: CurrentWorkspaceIdentityUsageContractVersion,
		ContractHash:    CurrentWorkspaceIdentityUsageContractHash,
		AccessToken:     "installation-secret",
		WorkspaceCode:   "night-tokyo",
	})
	if err != nil {
		t.Fatal(err)
	}
	serialized := strings.ToLower(string(payload))
	for _, forbidden := range []string{"installation-secret", "night-tokyo", "workspace_code", "workspace_id", "tenant"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("serialized exact usage request contains %q: %s", forbidden, payload)
		}
	}
}

func TestWorkspaceIdentityUsageProjectionContainsOnlyCounts(t *testing.T) {
	payload, err := json.Marshal(WorkspaceIdentityUsagePage{Items: []WorkspaceIdentityUsage{{
		WorkspaceID: "workspace-1",
		Accounts: WorkspaceIdentityAccountCounts{
			ActiveHumanAccounts: 2, ActiveHumanAccountsWithActiveRole: 1,
			DisabledHumanAccounts: 1, ServiceAccounts: 3, AutomationAccounts: 4,
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	serialized := strings.ToLower(string(payload))
	for _, forbidden := range []string{"email", "phone", "display_name", "login", "worker", "profile", "billable", "tenant"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("usage projection contains %q: %s", forbidden, payload)
		}
	}
	if !strings.Contains(serialized, `"active_human_accounts_with_active_role":1`) {
		t.Fatalf("usage projection lost distinct active-human role fact: %s", payload)
	}
	if WorkspaceIdentityUsageDefaultPageSize <= 0 || WorkspaceIdentityUsageMaxPageSize < WorkspaceIdentityUsageDefaultPageSize {
		t.Fatalf("invalid usage page bounds default=%d max=%d", WorkspaceIdentityUsageDefaultPageSize, WorkspaceIdentityUsageMaxPageSize)
	}
}

func TestWorkspaceIdentityUsageContractV2HashMatchesCanonicalDescriptor(t *testing.T) {
	actual := fmt.Sprintf("%x", sha256.Sum256([]byte(workspaceIdentityUsageCanonicalContractV2)))
	if actual != WorkspaceIdentityUsageContractHashV2 {
		t.Fatalf("Workspace Identity usage contract hash=%q want=%q", WorkspaceIdentityUsageContractHashV2, actual)
	}
}

func TestWorkspaceIdentityUsageContractV3HashMatchesCanonicalDescriptor(t *testing.T) {
	actual := fmt.Sprintf("%x", sha256.Sum256([]byte(workspaceIdentityUsageCanonicalContractV3)))
	if actual != WorkspaceIdentityUsageContractHashV3 {
		t.Fatalf("Workspace Identity usage v3 contract hash=%q want=%q", WorkspaceIdentityUsageContractHashV3, actual)
	}
}
