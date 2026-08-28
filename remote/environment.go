package remote

import (
	"os"
	"strings"
)

// ConfigFromEnvironment resolves the SaaS transport configuration at the
// application composition root. Runtime hosts receive an already configured
// Factory and never select or configure the Identity deployment topology.
func ConfigFromEnvironment() Config {
	return Config{
		Endpoint:           strings.TrimSpace(os.Getenv("IDENTITY_ENDPOINT")),
		TenantID:           strings.TrimSpace(os.Getenv("IDENTITY_TENANT_ID")),
		WorkspaceID:        strings.TrimSpace(os.Getenv("IDENTITY_WORKSPACE_ID")),
		Issuer:             strings.TrimSpace(os.Getenv("IDENTITY_ISSUER")),
		Audience:           strings.TrimSpace(os.Getenv("IDENTITY_AUDIENCE")),
		ServiceAccessToken: strings.TrimSpace(os.Getenv("IDENTITY_SERVICE_ACCESS_TOKEN")),
		UserAgent:          strings.TrimSpace(os.Getenv("IDENTITY_USER_AGENT")),
	}
}
