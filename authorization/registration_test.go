package authorization

import (
	"strings"
	"testing"
)

func testPermissionDefinition(resourceKey, operationKey, label, category, sourceKind string) PermissionDefinition {
	key := resourceKey + "." + operationKey
	return PermissionDefinition{
		PermissionKey: key, ModuleKey: "test", GroupKey: resourceKey,
		ResourceKey: resourceKey, OperationKey: operationKey, Label: label, Category: category, SourceKind: sourceKind,
		GrantMode: "direct", ScopeKind: "none", DefaultLocale: "en",
		I18n: PermissionLocalizedText{"en": {
			ModuleLabel: "Test", GroupLabel: category, ResourceLabel: category, OperationLabel: operationKey, Label: label,
		}},
	}
}

func TestApplicationRegistrationAndPermissionSnapshotValidation(t *testing.T) {
	registration := ApplicationRegistration{
		Application:  ApplicationRef{WorkspaceID: "workspace", ApplicationKey: "runtime"},
		RedirectURLs: []string{"https://runtime.example/auth/callback", "http://localhost:3100/auth/callback", "https://runtime.example/auth/callback"},
	}
	if err := registration.ValidateContract(); err != nil {
		t.Fatal(err)
	}
	if got := registration.CanonicalRedirectURLs(); got[0] != "http://localhost:3100/auth/callback" || got[1] != "https://runtime.example/auth/callback" {
		t.Fatalf("canonical redirects=%v", got)
	}
	request := PermissionReconcileRequest{
		SourceOwner: "application:runtime",
		Definitions: []PermissionDefinition{testPermissionDefinition("customer", "read", "Read customers", "Customer", "object_default")},
	}
	request.SnapshotHash, _ = PermissionSnapshotHash(request.SourceOwner, request.Definitions)
	if err := request.ValidateContract(); err != nil {
		t.Fatal(err)
	}
	receipt := PermissionReconcileReceipt{
		SourceOwner:          request.SourceOwner,
		PreviousSnapshotHash: request.PreviousSnapshotHash, SnapshotHash: request.SnapshotHash,
		DefinitionCount: len(request.Definitions), Inserted: len(request.Definitions),
	}
	if err := receipt.ValidateFor(request); err != nil {
		t.Fatal(err)
	}
	idempotent := receipt
	idempotent.PreviousSnapshotHash = request.SnapshotHash
	idempotent.Inserted = 0
	idempotent.Unchanged = len(request.Definitions)
	if err := idempotent.ValidateFor(request); err != nil {
		t.Fatalf("idempotent receipt rejected: %v", err)
	}
	wrongOwner := receipt
	wrongOwner.SourceOwner = "module:other"
	if err := wrongOwner.ValidateFor(request); err == nil {
		t.Fatal("receipt for another owner was accepted")
	} else if sdkError, ok := err.(*Error); !ok || sdkError.Code != "identity.permission_reconcile_receipt_invalid" {
		t.Fatalf("invalid receipt error=%#v", err)
	}
	reordered := PermissionReconcileRequest{SourceOwner: request.SourceOwner, Definitions: []PermissionDefinition{
		testPermissionDefinition("customer", "update", "Update customers", "Customer", "object_default"),
		request.Definitions[0],
	}}
	firstHash, err := PermissionSnapshotHash(reordered.SourceOwner, reordered.Definitions)
	if err != nil {
		t.Fatal(err)
	}
	reordered.Definitions[0], reordered.Definitions[1] = reordered.Definitions[1], reordered.Definitions[0]
	secondHash, err := PermissionSnapshotHash(reordered.SourceOwner, reordered.Definitions)
	if err != nil || firstHash != secondHash {
		t.Fatalf("order-dependent permission snapshot hash: first=%q second=%q err=%v", firstHash, secondHash, err)
	}
	invalidHash := request
	invalidHash.SnapshotHash = strings.Repeat("0", 64)
	if err := invalidHash.ValidateContract(); err == nil {
		t.Fatal("mismatched permission snapshot hash was accepted")
	}
	mismatched := request
	mismatched.Definitions = append([]PermissionDefinition(nil), request.Definitions...)
	mismatched.Definitions[0].PermissionKey = "customer.write"
	if err := mismatched.ValidateContract(); err == nil {
		t.Fatal("permission key different from resource.action was accepted")
	}
	invalidOwner := request
	invalidOwner.SourceOwner = "Application Owner"
	if err := invalidOwner.ValidateContract(); err == nil {
		t.Fatal("non-canonical source owner accepted")
	} else if sdkError, ok := err.(*Error); !ok || sdkError.Code != "identity.permission_source_owner_invalid" {
		t.Fatalf("invalid source owner error=%#v", err)
	}
	invalidPrevious := request
	invalidPrevious.PreviousSnapshotHash = "not-a-sha256"
	if err := invalidPrevious.ValidateContract(); err == nil {
		t.Fatal("invalid previous permission snapshot hash was accepted")
	} else if sdkError, ok := err.(*Error); !ok || sdkError.Code != "identity.permission_previous_snapshot_hash_invalid" {
		t.Fatalf("invalid previous snapshot error=%#v", err)
	}
	request.Definitions = append(request.Definitions, request.Definitions[0])
	if err := request.ValidateContract(); err == nil {
		t.Fatal("duplicate permission definition accepted")
	}
}

func TestPermissionSourceSnapshotValidation(t *testing.T) {
	request := PermissionSourceSnapshotRequest{
		SourceOwner: "module:notification",
	}
	definitions := []PermissionDefinition{testPermissionDefinition("notification.templates", "list", "List templates", "Notification", "module_http")}
	hash, err := PermissionSnapshotHash(request.SourceOwner, definitions)
	if err != nil {
		t.Fatal(err)
	}
	valid := PermissionSourceSnapshot{SourceOwner: request.SourceOwner, SnapshotHash: hash, Definitions: definitions}
	if err := valid.ValidateFor(request); err != nil {
		t.Fatal(err)
	}
	valid.SnapshotHash, valid.Definitions = "", nil
	if err := valid.ValidateFor(request); err != nil {
		t.Fatalf("fresh source snapshot rejected: %v", err)
	}
	invalid := valid
	invalid.SourceOwner = "module:other"
	if err := invalid.ValidateFor(request); err == nil {
		t.Fatal("mismatched source snapshot was accepted")
	}
}
