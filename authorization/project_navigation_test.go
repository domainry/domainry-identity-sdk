package authorization

import (
	"reflect"
	"testing"
)

func TestProjectNavigationCatalogCanonicalizesFileTemplate(t *testing.T) {
	input := ProjectNavigationCatalog{
		ContractVersion: ProjectNavigationContractVersion,
		Menus: []ProjectMenuDefinition{
			{Key: " orders ", Label: map[string]string{"zh-CN": " 订单 ", "en": " Orders "}, ParentKey: " sales ", Route: " /orders ", SortOrder: 20},
			{Key: "sales", Label: map[string]string{"en": "Sales"}, SortOrder: 10},
		},
		RoleMenuSets: []ProjectRoleMenuSet{{RoleKey: " sales_agent ", MenuKeys: []string{"orders", "orders"}}},
	}
	normalized, err := NormalizeProjectNavigationCatalog(input)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{normalized.Menus[0].Key, normalized.Menus[1].Key}; !reflect.DeepEqual(got, []string{"sales", "orders"}) {
		t.Fatalf("menu order=%v", got)
	}
	if normalized.Menus[1].Label["zh-CN"] != "订单" || normalized.Menus[1].Route != "/orders" || normalized.Menus[1].ParentKey != "sales" {
		t.Fatalf("normalized menu=%#v", normalized.Menus[1])
	}
	if got := normalized.RoleMenuSets[0]; got.RoleKey != "sales_agent" || !reflect.DeepEqual(got.MenuKeys, []string{"orders"}) {
		t.Fatalf("role menu set=%#v", got)
	}
	first, err := ProjectNavigationCatalogSHA256(input)
	if err != nil {
		t.Fatal(err)
	}
	reordered := ProjectNavigationCatalog{
		ContractVersion: ProjectNavigationContractVersion,
		Menus:           []ProjectMenuDefinition{input.Menus[1], input.Menus[0]},
		RoleMenuSets:    input.RoleMenuSets,
	}
	second, err := ProjectNavigationCatalogSHA256(reordered)
	if err != nil || first != second {
		t.Fatalf("digest first=%q second=%q err=%v", first, second, err)
	}
}

func TestProjectNavigationCatalogRejectsInvalidReferencesAndCycles(t *testing.T) {
	base := ProjectNavigationCatalog{ContractVersion: ProjectNavigationContractVersion, Menus: []ProjectMenuDefinition{{Key: "root", Label: map[string]string{"en": "Root"}}}}
	for name, mutate := range map[string]func(*ProjectNavigationCatalog){
		"version":        func(value *ProjectNavigationCatalog) { value.ContractVersion = "other" },
		"missing label":  func(value *ProjectNavigationCatalog) { value.Menus[0].Label = nil },
		"unknown parent": func(value *ProjectNavigationCatalog) { value.Menus[0].ParentKey = "missing" },
		"cycle": func(value *ProjectNavigationCatalog) {
			value.Menus = []ProjectMenuDefinition{{Key: "a", Label: map[string]string{"en": "A"}, ParentKey: "b"}, {Key: "b", Label: map[string]string{"en": "B"}, ParentKey: "a"}}
		},
		"unknown menu": func(value *ProjectNavigationCatalog) {
			value.RoleMenuSets = []ProjectRoleMenuSet{{RoleKey: "admin", MenuKeys: []string{"missing"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Menus = append([]ProjectMenuDefinition(nil), base.Menus...)
			mutate(&candidate)
			if _, err := NormalizeProjectNavigationCatalog(candidate); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}
