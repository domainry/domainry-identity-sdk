package contracttest_test

import (
	"encoding/json"
	"strings"
	"testing"

	identity "github.com/domainry/domainry-identity-sdk"
)

func TestPublicIdentityScopesSerializeOnlyWorkspace(t *testing.T) {
	for _, value := range []any{
		identity.ApplicationRef{WorkspaceID: "workspace-a", ApplicationKey: "app"},
		identity.ApplicationScope{WorkspaceID: "workspace-a", ApplicationKey: "app"},
		identity.AuthSession{WorkspaceID: "workspace-a"},
		identity.VerifiedToken{WorkspaceID: "workspace-a"},
		identity.Subject{WorkspaceID: "workspace-a"},
		identity.PasswordLoginRequest{WorkspaceID: "workspace-a"},
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "tenant") || !strings.Contains(string(raw), `"workspace_id":"workspace-a"`) {
			t.Fatalf("scope JSON=%s", raw)
		}
	}
}
