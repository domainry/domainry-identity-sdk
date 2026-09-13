package identity

import "testing"

func TestWorkspaceBoundaryRejectsHistoricalDefaultPlaceholder(t *testing.T) {
	for _, value := range []string{"default", " DEFAULT ", "Default"} {
		if WorkspaceID(value).Valid() {
			t.Fatalf("workspace placeholder %q is valid", value)
		}
	}
	if !WorkspaceID("workspace-primary").Valid() {
		t.Fatal("explicit initialized workspace boundary are invalid")
	}
}
