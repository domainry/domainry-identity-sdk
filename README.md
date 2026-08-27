# Domainry Identity SDK

`domainry-identity-sdk` is the stable integration boundary between Domainry
applications and Identity. It contains no Identity persistence,
management CRUD, Plane types, or service-side domain implementation.

## Packages

- root package `identity`: the small deployment-neutral `Binding`, `Factory`,
  and application-scope contract.
- `application`: binds a `Binding` to one workspace/application and
  rejects cross-workspace or cross-audience reuse in both deployment modes.
- `identity`: shared identity identifiers, users, roles, and SDK errors.
- `authentication`: login, SSO, OTP, session, token, and credential contracts.
- `authorization`: Principal, AccessBundle, policy, and catalog contracts.
- `authorization/principal`: bounded token/session/AccessBundle resolution and
  cache policy.
- `authorization/evaluator`: local function, record, field, reference, and
  export evaluation.
- `httpapi`: optional exact HTTP administration Surface for embedded modules;
  it is intentionally not part of the consuming application's CRUD contract.
- `httpmiddleware`: fail-closed `net/http` authentication and high-risk gates.
- `browsergateway`: same-origin HttpOnly refresh-cookie HTTP adapter.
- `remote`: SaaS `Factory`, HTTP transport and JWKS token verifier.
- `contracttest`: one parity suite used by Module and SaaS implementations.
- `browser`: the separately versioned `@domainry/identity-client` package.

## HTTP middleware

```go
factory := remote.NewFactory(remote.Config{
	Endpoint:    "https://identity.example.com",
	WorkspaceID: "workspace-a",
	Issuer:      "https://identity.example.com",
	Audience:    "runtime-app",
})
binding, err := factory.Open(ctx, identitysdk.ApplicationRef{
	WorkspaceID: "workspace-a", ApplicationKey: "runtime-app",
})
if err != nil {
    panic(err)
}

resolver, err := principal.NewResolver(binding, principal.Options{})
if err != nil {
    panic(err)
}
security, err := httpmiddleware.New(resolver,
    httpmiddleware.WithAuthorization(binding.Authorization()),
)
if err != nil {
    panic(err)
}

handler := security.Authenticate(
    security.RequirePasswordChanged(
        security.RequirePermission("order.read", orderHandler),
    ),
)
```

Record, data-scope, and field decisions belong inside the application use case,
after the object and record identifiers are known:

```go
requestIdentity, _ := identitysdk.RequestIdentityFromContext(ctx)
decision, err := binding.Authorization().Reauthorize(ctx, identitysdk.DecisionRequest{
	Identity: requestIdentity,
	Access: identitysdk.AccessRequest{
		ObjectKey: "order",
		Action:    "read",
		RecordID:  orderID,
	},
	Facts: identitysdk.ResourceFacts{
		"id":       orderID,
		"owner_id": order.OwnerID,
	},
})
```

Identity never queries the consuming application's business database. The
application projects the bounded facts declared by its published authorization
catalog, and the same evaluator applies those facts in Module and SaaS mode.
Missing facts fail closed.

The remote adapter applies a total request deadline, bounded payload sizes,
safe retries, and a circuit breaker. Authentication and session mutations are
not retried; credential mutations are retried only when the caller supplies an
idempotency key. `ContextHeaders` may propagate request, correlation, and W3C
trace headers, but cannot override authorization, cookies, or workspace scope.
`remote.Factory.Open` first reads `/identity/discovery` and rejects an
incompatible protocol, policy bundle, Catalog version, issuer, deployment mode,
or required capability before it exposes a Binding.

The explicit `ApplicationRef` is authoritative in both topologies. A
conflicting `remote.Config.WorkspaceID` or `Audience` fails startup, while a
matching scope is enforced by the `application` wrapper on login, refresh,
token verification, authorization, credentials, and Catalog operations.

## Module mode

The Identity repository implements this SDK directly. Module mode is composed
with its Factory and never creates loopback HTTP traffic. The module owns its
database pool, schema migration, Identity application graph, and shutdown
lifecycle. The host supplies only its application scope; Identity never
borrows host persistence.

```go
factory := identitymodule.NewFactory(identitymodule.OptionsFromEnvironment())
binding, err := factory.Open(ctx, identitysdk.ApplicationRef{
	WorkspaceID: "workspace-a", ApplicationKey: "runtime-app",
})
if err != nil {
    panic(err)
}
defer binding.Close(shutdownContext)
```

Both `identitymodule.Factory` and `remote.Factory` return the same
`identity.Binding`; consuming request code never branches on deployment mode.

## Development

```bash
go test ./...
go vet ./...
```
