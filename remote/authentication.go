package remote

import (
	"context"
	"net/http"
	"sort"
	"strings"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type authenticationProfile struct {
	User               identitysdk.User   `json:"user"`
	Roles              []identitysdk.Role `json:"roles"`
	DefaultRole        string             `json:"default_role"`
	Permissions        []string           `json:"permissions"`
	MustChangePassword bool               `json:"must_change_password"`
}

func (c *Client) Authenticate(ctx context.Context, accessToken string) (identitysdk.Principal, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return identitysdk.Principal{}, &identitysdk.Error{StatusCode: http.StatusUnauthorized, Code: "auth.token_required"}
	}
	var profile authenticationProfile
	if err := c.doJSON(ctx, http.MethodGet, "/auth/me", accessToken, nil, &profile); err != nil {
		return identitysdk.Principal{}, err
	}
	var principal identitysdk.Principal
	if err := c.doJSON(ctx, http.MethodGet, "/identity/principal-context", accessToken, nil, &principal); err != nil {
		return identitysdk.Principal{}, err
	}
	if principal.ContractVersion != identitysdk.PrincipalContextContractVersion {
		return identitysdk.Principal{}, &identitysdk.Error{StatusCode: http.StatusBadGateway, Code: "identity.principal_contract_unsupported"}
	}
	if !principal.Known || strings.TrimSpace(principal.UserID) == "" || strings.TrimSpace(profile.User.ID) == "" || principal.UserID != profile.User.ID {
		return identitysdk.Principal{}, &identitysdk.Error{StatusCode: http.StatusUnauthorized, Code: "auth.token_invalid"}
	}
	if c.workspaceID != "" && strings.TrimSpace(principal.WorkspaceID) != c.workspaceID {
		return identitysdk.Principal{}, &identitysdk.Error{StatusCode: http.StatusForbidden, Code: "auth.workspace_mismatch"}
	}
	principal.User = profile.User
	principal.Roles = append([]identitysdk.Role(nil), profile.Roles...)
	principal.Permissions = uniqueStrings(profile.Permissions)
	principal.MustChangePassword = profile.MustChangePassword
	if strings.TrimSpace(principal.RoleKey) == "" {
		principal.RoleKey = strings.TrimSpace(profile.DefaultRole)
	}
	return principal, nil
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
