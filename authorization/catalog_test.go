package authorization

import (
	"bytes"
	"testing"
)

func TestAuthorizationCatalogCanonicalJSONIsOrderIndependent(t *testing.T) {
	first := AuthorizationCatalog{
		ContractVersion: CatalogVersionV1,
		Application: ApplicationRef{
			WorkspaceID: "workspace-1", ApplicationKey: "runtime-app",
			RedirectURLs: []string{"https://runtime.example/auth/callback", "http://localhost:3100/auth/callback"},
		},
		Resources: []ResourceDefinition{
			{Key: "customer", Fields: []string{"name", "id"}, SupportedFacts: []string{"owner_id", "id"}},
			{Key: "order", Fields: []string{"customer_id", "id"}, References: []ReferenceDefinition{{Key: "customer_id", TargetResource: "customer"}}},
		},
		Actions: []ActionDefinition{{Resource: "order", Action: "read"}, {Resource: "customer", Action: "read"}},
	}
	second := AuthorizationCatalog{
		ContractVersion: CatalogVersionV1,
		Application: ApplicationRef{
			WorkspaceID: "workspace-1", ApplicationKey: "runtime-app",
			RedirectURLs: []string{"http://localhost:3100/auth/callback", "https://runtime.example/auth/callback"},
		},
		Resources: []ResourceDefinition{
			{Key: "order", Fields: []string{"id", "customer_id"}, References: []ReferenceDefinition{{Key: "customer_id", TargetResource: "customer"}}},
			{Key: "customer", Fields: []string{"id", "name"}, SupportedFacts: []string{"id", "owner_id"}},
		},
		Actions: []ActionDefinition{{Resource: "customer", Action: "read"}, {Resource: "order", Action: "read"}},
	}
	firstJSON, err := first.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := second.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("canonical catalogs differ:\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestAuthorizationCatalogRejectsInvalidReferenceAndScope(t *testing.T) {
	base := AuthorizationCatalog{
		ContractVersion: CatalogVersionV1,
		Application:     ApplicationRef{WorkspaceID: "workspace-1", ApplicationKey: "runtime-app"},
		Resources:       []ResourceDefinition{{Key: "order", Fields: []string{"id"}}},
		Actions:         []ActionDefinition{{Resource: "order", Action: "read"}},
	}
	missingWorkspace := base
	missingWorkspace.Application.WorkspaceID = ""
	if err := missingWorkspace.ValidateContract(); err == nil {
		t.Fatal("catalog without workspace scope accepted")
	}
	unknownTarget := base
	unknownTarget.Resources[0].References = []ReferenceDefinition{{Key: "id", TargetResource: "customer"}}
	if err := unknownTarget.ValidateContract(); err == nil {
		t.Fatal("catalog reference to an undeclared target accepted")
	}
}
