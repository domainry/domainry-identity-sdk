package modulehost

import (
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
