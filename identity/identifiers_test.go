package identity

import "testing"

func TestTenantBoundariesRejectHistoricalDefaultPlaceholder(t *testing.T) {
	for _, value := range []string{"default", " DEFAULT ", "Default"} {
		if TenantID(value).Valid() {
			t.Fatalf("tenant placeholder %q is valid", value)
		}
		if WorkspaceID(value).Valid() {
			t.Fatalf("workspace placeholder %q is valid", value)
		}
	}
	if !TenantID("tenant-primary").Valid() || !WorkspaceID("workspace-primary").Valid() {
		t.Fatal("explicit initialized tenant boundaries are invalid")
	}
}
