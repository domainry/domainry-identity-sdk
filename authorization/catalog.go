package authorization

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

type ApplicationRef struct {
	TenantID       TenantID       `json:"tenant_id,omitempty"`
	WorkspaceID    WorkspaceID    `json:"workspace_id,omitempty"`
	ApplicationKey ApplicationKey `json:"application_key"`
	RedirectURLs   []string       `json:"redirect_urls,omitempty"`
}

type AuthorizationCatalog struct {
	ContractVersion string               `json:"contract_version"`
	Application     ApplicationRef       `json:"application"`
	Resources       []ResourceDefinition `json:"resources"`
	Actions         []ActionDefinition   `json:"actions"`
}

type ResourceDefinition struct {
	Key            ResourceType          `json:"key"`
	Fields         []string              `json:"fields,omitempty"`
	References     []ReferenceDefinition `json:"references,omitempty"`
	SupportedFacts []string              `json:"supported_facts,omitempty"`
}

type ReferenceDefinition struct {
	Key            string       `json:"key"`
	TargetResource ResourceType `json:"target_resource"`
}

type ActionDefinition struct {
	Resource ResourceType `json:"resource"`
	Action   Action       `json:"action"`
	Risk     string       `json:"risk,omitempty"`
}

type CatalogReceipt struct {
	Revision    CatalogRevision `json:"revision"`
	SHA256      string          `json:"sha256"`
	PublishedAt string          `json:"published_at"`
}

type CatalogClient interface {
	Validate(context.Context, AuthorizationCatalog) error
	Publish(context.Context, AuthorizationCatalog) (CatalogReceipt, error)
	CurrentRevision(context.Context, ApplicationRef) (CatalogReceipt, error)
}

func (catalog AuthorizationCatalog) ValidateContract() error {
	if catalog.ContractVersion != CatalogVersionV1 || !catalog.Application.WorkspaceID.Valid() || !catalog.Application.ApplicationKey.Valid() {
		return &Error{Code: "identity.catalog_invalid"}
	}
	redirects := map[string]struct{}{}
	for _, raw := range catalog.Application.RedirectURLs {
		value := strings.TrimSpace(raw)
		parsed, err := url.Parse(value)
		if err != nil || !parsed.IsAbs() || parsed.Fragment != "" || parsed.User != nil || parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")) {
			return &Error{Code: "identity.catalog_redirect_url_invalid"}
		}
		if _, duplicate := redirects[value]; duplicate {
			return &Error{Code: "identity.catalog_redirect_url_duplicate"}
		}
		redirects[value] = struct{}{}
	}
	resources := map[ResourceType]ResourceDefinition{}
	for _, resource := range catalog.Resources {
		if !resource.Key.Valid() || !uniqueNonBlank(resource.Fields) || !uniqueNonBlank(resource.SupportedFacts) {
			return &Error{Code: "identity.catalog_resource_invalid"}
		}
		if _, exists := resources[resource.Key]; exists {
			return &Error{Code: "identity.catalog_resource_duplicate"}
		}
		references := map[string]struct{}{}
		for _, reference := range resource.References {
			key := strings.TrimSpace(reference.Key)
			if key == "" || !reference.TargetResource.Valid() || !containsString(resource.Fields, key) {
				return &Error{Code: "identity.catalog_reference_invalid"}
			}
			if _, duplicate := references[key]; duplicate {
				return &Error{Code: "identity.catalog_reference_duplicate"}
			}
			references[key] = struct{}{}
		}
		resources[resource.Key] = resource
	}
	for _, resource := range catalog.Resources {
		for _, reference := range resource.References {
			if _, exists := resources[reference.TargetResource]; !exists {
				return &Error{Code: "identity.catalog_reference_target_unknown"}
			}
		}
	}
	seenActions := map[string]bool{}
	for _, action := range catalog.Actions {
		if _, exists := resources[action.Resource]; !exists || !action.Action.Valid() {
			return &Error{Code: "identity.catalog_action_invalid"}
		}
		key := string(action.Resource) + "\x00" + string(action.Action)
		if seenActions[key] {
			return &Error{Code: "identity.catalog_action_duplicate"}
		}
		seenActions[key] = true
	}
	return nil
}

// CanonicalJSON returns the stable catalog representation used for revision
// hashing. Equivalent declarations produce the same bytes regardless of input
// ordering.
func (catalog AuthorizationCatalog) CanonicalJSON() ([]byte, error) {
	if err := catalog.ValidateContract(); err != nil {
		return nil, err
	}
	clone := catalog
	clone.Application.RedirectURLs = append([]string(nil), catalog.Application.RedirectURLs...)
	sort.Strings(clone.Application.RedirectURLs)
	clone.Resources = append([]ResourceDefinition(nil), catalog.Resources...)
	for index := range clone.Resources {
		clone.Resources[index].Fields = append([]string(nil), clone.Resources[index].Fields...)
		clone.Resources[index].SupportedFacts = append([]string(nil), clone.Resources[index].SupportedFacts...)
		clone.Resources[index].References = append([]ReferenceDefinition(nil), clone.Resources[index].References...)
		sort.Strings(clone.Resources[index].Fields)
		sort.Strings(clone.Resources[index].SupportedFacts)
		sort.Slice(clone.Resources[index].References, func(left, right int) bool {
			return clone.Resources[index].References[left].Key < clone.Resources[index].References[right].Key
		})
	}
	sort.Slice(clone.Resources, func(left, right int) bool { return clone.Resources[left].Key < clone.Resources[right].Key })
	clone.Actions = append([]ActionDefinition(nil), catalog.Actions...)
	sort.Slice(clone.Actions, func(left, right int) bool {
		leftKey := string(clone.Actions[left].Resource) + "\x00" + string(clone.Actions[left].Action)
		rightKey := string(clone.Actions[right].Resource) + "\x00" + string(clone.Actions[right].Action)
		return leftKey < rightKey
	})
	return json.Marshal(clone)
}

func uniqueNonBlank(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == expected {
			return true
		}
	}
	return false
}
