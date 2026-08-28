package authentication

import (
	"testing"

	"github.com/domainry/domainry-identity-sdk/authorization"
)

func TestExchangeApplicationServiceTokenRequestRequiresExactScopedUniqueGrants(t *testing.T) {
	valid := ExchangeApplicationServiceTokenRequest{
		Application: authorization.ApplicationRef{TenantID: "tenant-a", WorkspaceID: "workspace-a", ApplicationKey: "orders-runtime"},
		Audience:    "domainry-notification",
		Credential:  "static-secret",
		Grants:      []ApplicationServiceGrant{{Resource: "notification_event", Action: "publish"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ExchangeApplicationServiceTokenRequest){
		"missing tenant":      func(value *ExchangeApplicationServiceTokenRequest) { value.Application.TenantID = "" },
		"missing workspace":   func(value *ExchangeApplicationServiceTokenRequest) { value.Application.WorkspaceID = "" },
		"missing application": func(value *ExchangeApplicationServiceTokenRequest) { value.Application.ApplicationKey = "" },
		"missing audience":    func(value *ExchangeApplicationServiceTokenRequest) { value.Audience = "" },
		"missing credential":  func(value *ExchangeApplicationServiceTokenRequest) { value.Credential = "" },
		"missing grants":      func(value *ExchangeApplicationServiceTokenRequest) { value.Grants = nil },
		"duplicate grant": func(value *ExchangeApplicationServiceTokenRequest) {
			value.Grants = append(value.Grants, value.Grants[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			value.Grants = append([]ApplicationServiceGrant(nil), valid.Grants...)
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid exchange request was accepted")
			}
		})
	}
}
