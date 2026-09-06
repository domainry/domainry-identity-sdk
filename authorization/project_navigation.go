package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const ProjectNavigationContractVersion = "domainry-project-navigation-v1"

var projectNavigationKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)

// ProjectMenuDefinition is one source-owned product navigation entry. The
// frontend compiler owns route, presentation and hierarchy. Identity only
// materializes a Workspace-local copy during trusted Workspace bootstrap.
type ProjectMenuDefinition struct {
	Key         string            `json:"key"`
	Label       map[string]string `json:"label"`
	Description string            `json:"description,omitempty"`
	Route       string            `json:"route,omitempty"`
	Icon        string            `json:"icon,omitempty"`
	ParentKey   string            `json:"parent_key,omitempty"`
	SortOrder   int               `json:"sort_order"`
}

// ProjectRoleMenuSet is the only authored navigation policy: one published
// role key references menu keys already proven by the frontend compiler.
type ProjectRoleMenuSet struct {
	RoleKey  string   `json:"role_key"`
	MenuKeys []string `json:"menu_keys"`
}

// ProjectNavigationCatalog is a versioned file contract. It deliberately has
// no tenant/workspace or client/surface dimension; Workspace bootstrap injects
// the tenant scope and frontend routing remains frontend-owned.
type ProjectNavigationCatalog struct {
	ContractVersion string                  `json:"contract_version"`
	Menus           []ProjectMenuDefinition `json:"menus"`
	RoleMenuSets    []ProjectRoleMenuSet    `json:"role_menu_sets,omitempty"`
}

// NormalizeProjectNavigationCatalog validates and canonicalizes the trusted
// file contract without executing frontend code.
func NormalizeProjectNavigationCatalog(input ProjectNavigationCatalog) (ProjectNavigationCatalog, error) {
	input.ContractVersion = strings.TrimSpace(input.ContractVersion)
	if input.ContractVersion != ProjectNavigationContractVersion {
		return ProjectNavigationCatalog{}, fmt.Errorf("project navigation contract version is unsupported")
	}
	menus := append([]ProjectMenuDefinition(nil), input.Menus...)
	seenMenus := make(map[string]bool, len(menus))
	for index := range menus {
		menu := &menus[index]
		menu.Key = strings.TrimSpace(menu.Key)
		menu.Description = strings.TrimSpace(menu.Description)
		menu.Route = strings.TrimSpace(menu.Route)
		menu.Icon = strings.TrimSpace(menu.Icon)
		menu.ParentKey = strings.TrimSpace(menu.ParentKey)
		if !projectNavigationKeyPattern.MatchString(menu.Key) || seenMenus[menu.Key] {
			return ProjectNavigationCatalog{}, fmt.Errorf("project navigation menu key %q is invalid or duplicated", menu.Key)
		}
		seenMenus[menu.Key] = true
		labels := make(map[string]string, len(menu.Label))
		for locale, value := range menu.Label {
			locale, value = strings.TrimSpace(locale), strings.TrimSpace(value)
			if locale != "" && value != "" {
				labels[locale] = value
			}
		}
		if len(labels) == 0 {
			return ProjectNavigationCatalog{}, fmt.Errorf("project navigation menu %q has no label", menu.Key)
		}
		menu.Label = labels
	}
	for _, menu := range menus {
		if menu.ParentKey != "" && (!seenMenus[menu.ParentKey] || menu.ParentKey == menu.Key) {
			return ProjectNavigationCatalog{}, fmt.Errorf("project navigation menu %q has invalid parent %q", menu.Key, menu.ParentKey)
		}
	}
	parents := make(map[string]string, len(menus))
	for _, menu := range menus {
		parents[menu.Key] = menu.ParentKey
	}
	for _, menu := range menus {
		visited := map[string]bool{}
		for key := menu.Key; key != ""; key = parents[key] {
			if visited[key] {
				return ProjectNavigationCatalog{}, fmt.Errorf("project navigation menu %q has a parent cycle", menu.Key)
			}
			visited[key] = true
		}
	}
	sort.Slice(menus, func(left, right int) bool {
		if menus[left].SortOrder == menus[right].SortOrder {
			return menus[left].Key < menus[right].Key
		}
		return menus[left].SortOrder < menus[right].SortOrder
	})
	sets := append([]ProjectRoleMenuSet(nil), input.RoleMenuSets...)
	seenRoles := make(map[string]bool, len(sets))
	for index := range sets {
		set := &sets[index]
		set.RoleKey = strings.TrimSpace(set.RoleKey)
		if !projectNavigationKeyPattern.MatchString(set.RoleKey) || seenRoles[set.RoleKey] {
			return ProjectNavigationCatalog{}, fmt.Errorf("project navigation role key %q is invalid or duplicated", set.RoleKey)
		}
		seenRoles[set.RoleKey] = true
		seen := map[string]bool{}
		keys := make([]string, 0, len(set.MenuKeys))
		for _, raw := range set.MenuKeys {
			key := strings.TrimSpace(raw)
			if !seenMenus[key] {
				return ProjectNavigationCatalog{}, fmt.Errorf("project navigation role %q references unknown menu %q", set.RoleKey, key)
			}
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		set.MenuKeys = keys
	}
	sort.Slice(sets, func(left, right int) bool { return sets[left].RoleKey < sets[right].RoleKey })
	return ProjectNavigationCatalog{ContractVersion: ProjectNavigationContractVersion, Menus: menus, RoleMenuSets: sets}, nil
}

// ProjectNavigationCatalogSHA256 is the shared digest used by Runtime and
// Identity bootstrap receipts to prove which file template was materialized.
func ProjectNavigationCatalogSHA256(input ProjectNavigationCatalog) (string, error) {
	normalized, err := NormalizeProjectNavigationCatalog(input)
	if err != nil {
		return "", err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("encode project navigation catalog: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
