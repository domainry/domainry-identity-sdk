package authorization

import (
	"encoding/json"
	"strings"
	"testing"

	identitymodel "github.com/domainry/domainry-identity-sdk/identity"
)

func TestDeprecatedPrincipalApplicationScopeIsNeverSerialized(t *testing.T) {
	raw, err := json.Marshal(PrincipalResolutionRequest{
		Application: identitymodel.ApplicationScope{TenantID: "tenant", WorkspaceID: "workspace", ApplicationKey: "application"},
		SubjectID:   "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "tenant") || strings.Contains(string(raw), "workspace") || strings.Contains(string(raw), "application") {
		t.Fatalf("deprecated application scope leaked into request JSON: %s", raw)
	}
}
