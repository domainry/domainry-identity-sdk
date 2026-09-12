package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeprecatedProjectionApplicationScopeIsNeverSerialized(t *testing.T) {
	scope := ApplicationScope{TenantID: "tenant", WorkspaceID: "workspace", ApplicationKey: "application"}
	values := []any{
		ProjectionQuery{Application: scope},
		UserLookup{Application: scope, UserID: "user"},
		OrganizationUnitLookup{Application: scope, OrgID: "org"},
		DisplayNameQuery{Application: scope, UserIDs: []string{"user"}},
		UserRoleAssignmentQuery{Application: scope, UserID: "user"},
	}
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "tenant") || strings.Contains(string(raw), "workspace") || strings.Contains(string(raw), "application") {
			t.Fatalf("deprecated application scope leaked into request JSON: %s", raw)
		}
	}
}
