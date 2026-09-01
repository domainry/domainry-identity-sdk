package browsergateway

import (
	"fmt"
	"net/http"

	actioncontract "github.com/domainry/domainry-foundation/action"
)

const browserGatewayActionOwner = "identity-sdk:browser-gateway"

type browserGatewayRouteSpec struct {
	key, capabilityKey, capabilityLabel string
	operationKey, operationLabel, label string
	method, suffix, handlerKey          string
	authorization                       actioncontract.Authorization
	risk                                actioncontract.RiskLevel
}

func browserGatewayRouteSpecs() []browserGatewayRouteSpec {
	anonymous := func(policy string) actioncontract.Authorization {
		return actioncontract.Authorization{Strategy: actioncontract.AuthorizationAnonymousProtocol, PolicyKey: policy}
	}
	principal := actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticatedPrincipal}
	return []browserGatewayRouteSpec{
		{key: "identity.browser.session.get", capabilityKey: "identity.browser.session", capabilityLabel: "Browser session", operationKey: "get", operationLabel: "Get", label: "Read the current browser session", method: http.MethodGet, suffix: "/auth/session", handlerKey: "session", authorization: principal, risk: actioncontract.RiskLow},
		{key: "identity.browser.authorization_code.exchange", capabilityKey: "identity.browser.authorization_code", capabilityLabel: "Browser authorization code", operationKey: "exchange", operationLabel: "Exchange", label: "Exchange a browser authorization code", method: http.MethodPost, suffix: "/auth/code/exchange", handlerKey: "code_exchange", authorization: anonymous("identity.browser.authorization_code.exchange"), risk: actioncontract.RiskMedium},
		{key: "identity.browser.authentication.login", capabilityKey: "identity.browser.authentication", capabilityLabel: "Browser authentication", operationKey: "login", operationLabel: "Login", label: "Create a browser session with credentials", method: http.MethodPost, suffix: "/auth/login", handlerKey: "login", authorization: anonymous("identity.browser.authentication.login"), risk: actioncontract.RiskMedium},
		{key: "identity.browser.authentication.refresh", capabilityKey: "identity.browser.authentication", capabilityLabel: "Browser authentication", operationKey: "refresh", operationLabel: "Refresh", label: "Rotate a browser refresh credential", method: http.MethodPost, suffix: "/auth/refresh", handlerKey: "refresh", authorization: anonymous("identity.browser.authentication.refresh_credential"), risk: actioncontract.RiskMedium},
		{key: "identity.browser.authentication.logout", capabilityKey: "identity.browser.authentication", capabilityLabel: "Browser authentication", operationKey: "logout", operationLabel: "Logout", label: "Revoke a browser session", method: http.MethodPost, suffix: "/auth/logout", handlerKey: "logout", authorization: anonymous("identity.browser.authentication.logout_credential"), risk: actioncontract.RiskMedium},
		{key: "identity.browser.credentials.change_password", capabilityKey: "identity.browser.credentials", capabilityLabel: "Browser credentials", operationKey: "change_password", operationLabel: "Change password", label: "Change the current subject password", method: http.MethodPost, suffix: "/auth/change-password", handlerKey: "change_password", authorization: principal, risk: actioncontract.RiskHigh},
		{key: "identity.browser.credentials.reset_password", capabilityKey: "identity.browser.credentials", capabilityLabel: "Browser credentials", operationKey: "reset_password", operationLabel: "Reset password", label: "Forward an authenticated password reset command", method: http.MethodPost, suffix: "/auth/reset-password", handlerKey: "reset_password", authorization: principal, risk: actioncontract.RiskHigh},
		{key: "identity.browser.sessions.revoke_others", capabilityKey: "identity.browser.sessions", capabilityLabel: "Browser sessions", operationKey: "revoke_others", operationLabel: "Revoke sessions", label: "Forward an authenticated session revocation command", method: http.MethodPost, suffix: "/auth/sessions/revoke-others", handlerKey: "revoke_sessions", authorization: principal, risk: actioncontract.RiskHigh},
		{key: "identity.browser.providers.list", capabilityKey: "identity.browser.providers", capabilityLabel: "Browser identity providers", operationKey: "list", operationLabel: "List", label: "List browser identity providers", method: http.MethodGet, suffix: "/auth/providers", handlerKey: "providers", authorization: anonymous("identity.browser.providers.list"), risk: actioncontract.RiskLow},
		{key: "identity.browser.providers.start_get", capabilityKey: "identity.browser.providers", capabilityLabel: "Browser identity providers", operationKey: "start_get", operationLabel: "Start", label: "Start a browser provider challenge", method: http.MethodGet, suffix: "/auth/providers/{provider}/start", handlerKey: "provider_start", authorization: anonymous("identity.browser.providers.start"), risk: actioncontract.RiskMedium},
		{key: "identity.browser.providers.start_post", capabilityKey: "identity.browser.providers", capabilityLabel: "Browser identity providers", operationKey: "start_post", operationLabel: "Start", label: "Start a browser provider challenge", method: http.MethodPost, suffix: "/auth/providers/{provider}/start", handlerKey: "provider_start", authorization: anonymous("identity.browser.providers.start"), risk: actioncontract.RiskMedium},
		{key: "identity.browser.providers.callback_get", capabilityKey: "identity.browser.providers", capabilityLabel: "Browser identity providers", operationKey: "callback_get", operationLabel: "Callback", label: "Complete a browser provider callback", method: http.MethodGet, suffix: "/auth/providers/{provider}/callback", handlerKey: "provider_callback", authorization: anonymous("identity.browser.providers.callback"), risk: actioncontract.RiskMedium},
		{key: "identity.browser.providers.callback_post", capabilityKey: "identity.browser.providers", capabilityLabel: "Browser identity providers", operationKey: "callback_post", operationLabel: "Callback", label: "Complete a browser provider callback", method: http.MethodPost, suffix: "/auth/providers/{provider}/callback", handlerKey: "provider_callback", authorization: anonymous("identity.browser.providers.callback"), risk: actioncontract.RiskMedium},
		{key: "identity.browser.providers.verify", capabilityKey: "identity.browser.providers", capabilityLabel: "Browser identity providers", operationKey: "verify", operationLabel: "Verify", label: "Verify a browser provider challenge", method: http.MethodPost, suffix: "/auth/providers/{provider}/verify", handlerKey: "provider_verify", authorization: anonymous("identity.browser.providers.verify"), risk: actioncontract.RiskMedium},
	}
}

// ActionDefinitions is the source-owned browser transport manifest. Route
// mounting and route inventory are both projected from this exact slice.
func ActionDefinitions(prefix string) ([]actioncontract.ActionDefinition, error) {
	prefix, err := normalizeRoutePrefix(prefix)
	if err != nil {
		return nil, err
	}
	specs := browserGatewayRouteSpecs()
	definitions := make([]actioncontract.ActionDefinition, 0, len(specs))
	for _, spec := range specs {
		effect, idempotency := actioncontract.EffectRead, "not_applicable"
		if spec.method != http.MethodGet && spec.method != http.MethodHead {
			effect, idempotency = actioncontract.EffectWrite, "protocol_or_application_receipt"
		}
		definition, err := actioncontract.NormalizeDefinition(actioncontract.ActionDefinition{
			Key: spec.key, Owner: browserGatewayActionOwner, SourceKind: "browser_gateway",
			CapabilityKey: spec.capabilityKey, CapabilityLabel: spec.capabilityLabel,
			OperationKey: spec.operationKey, OperationLabel: spec.operationLabel, Label: spec.label,
			Exposures: []actioncontract.Exposure{actioncontract.ExposurePublic}, Authorization: spec.authorization,
			HTTP:        &actioncontract.HTTPBinding{Method: spec.method, RouteTemplate: prefix + spec.suffix, DisplayRouteTemplate: prefix + spec.suffix},
			EffectClass: effect, RiskLevel: spec.risk, IdempotencyDecision: idempotency,
			AuditClass: "identity_browser_protocol", LifecycleStatus: actioncontract.LifecycleActive,
		})
		if err != nil {
			return nil, fmt.Errorf("browser gateway action %q: %w", spec.key, err)
		}
		definitions = append(definitions, definition)
	}
	return definitions, nil
}

func (gateway *Gateway) routeHandler(handlerKey string) http.HandlerFunc {
	switch handlerKey {
	case "session":
		return gateway.Session
	case "code_exchange":
		return gateway.ExchangeAuthorizationCode
	case "login":
		return gateway.Login
	case "refresh":
		return gateway.Refresh
	case "logout":
		return gateway.Logout
	case "change_password":
		return gateway.ChangePassword
	case "reset_password":
		return gateway.ResetPassword
	case "revoke_sessions":
		return gateway.RevokeSessions
	case "providers":
		return gateway.Providers
	case "provider_start":
		return gateway.StartProvider
	case "provider_callback":
		return gateway.ProviderCallback
	case "provider_verify":
		return gateway.VerifyProvider
	default:
		return nil
	}
}
