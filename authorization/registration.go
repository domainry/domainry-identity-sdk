package authorization

import (
	"context"
	"net/url"
	"sort"
	"strings"
)

const AuthorizationContractVersionV1 = "domainry-identity-authorization-v1"

type ApplicationRef struct {
	TenantID       TenantID       `json:"tenant_id,omitempty"`
	WorkspaceID    WorkspaceID    `json:"workspace_id,omitempty"`
	ApplicationKey ApplicationKey `json:"application_key"`
}

type ApplicationRegistration struct {
	Application  ApplicationRef `json:"application"`
	RedirectURLs []string       `json:"redirect_urls"`
}

type ApplicationRegistrationReceipt struct {
	Application  ApplicationRef `json:"application"`
	RedirectURLs []string       `json:"redirect_urls"`
	Status       string         `json:"status"`
	UpdatedAt    string         `json:"updated_at"`
}

type ApplicationRegistry interface {
	Register(context.Context, ApplicationRegistration) (ApplicationRegistrationReceipt, error)
}

func (registration ApplicationRegistration) ValidateContract() error {
	if !registration.Application.WorkspaceID.Valid() || !registration.Application.ApplicationKey.Valid() {
		return &Error{Code: "identity.application_registration_invalid"}
	}
	for _, raw := range registration.RedirectURLs {
		value := strings.TrimSpace(raw)
		parsed, err := url.Parse(value)
		if err != nil || !parsed.IsAbs() || parsed.Fragment != "" || parsed.User != nil || parsed.Host == "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
			return &Error{Code: "identity.application_redirect_url_invalid"}
		}
	}
	return nil
}

func (registration ApplicationRegistration) CanonicalRedirectURLs() []string {
	result := append([]string(nil), registration.RedirectURLs...)
	for index := range result {
		result[index] = strings.TrimSpace(result[index])
	}
	sort.Strings(result)
	return compactStrings(result)
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
