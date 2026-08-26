# Domainry Identity SDK

`domainry-identity-sdk` is the public integration boundary between Domainry
applications and the Identity service. It owns Identity-specific contracts,
request authentication, authorization calls, login/SSO clients, and HTTP
middleware. It does not contain Identity persistence or policy implementation.

## Packages

- `identitysdk`: principals, request identity, authentication, authorization,
  access decisions, login sessions, and provider contracts.
- `httpmiddleware`: fail-closed `net/http` authentication and permission gates.
- `remote`: SaaS client for a remote Domainry Identity service.
- `module`: in-process client that invokes an Identity `http.Handler` without a
  network listener while preserving exactly the same protocol.

## HTTP middleware

```go
identityClient, err := remote.New(remote.Config{
    BaseURL: "https://identity.example.com",
    WorkspaceID: "tenant-a",
})
if err != nil {
    panic(err)
}

security, err := httpmiddleware.New(identityClient)
if err != nil {
    panic(err)
}

handler := security.Authenticate(
    security.RequirePermission("order.read", orderHandler),
)
```

Record, data-scope, and field decisions belong inside the application use case,
after the object and record identifiers are known:

```go
identity, _ := identitysdk.RequestIdentityFromContext(ctx)
decision, err := identityClient.Authorize(ctx, identity, identitysdk.AccessRequest{
    ObjectKey: "order",
    Action: "read",
    RecordID: orderID,
})
```

## Module mode

The Identity service exposes an embeddable module whose handler can be connected
to this SDK without a TCP listener:

```go
identityModule, err := identitymodule.Open(ctx, identitymodule.Options{})
if err != nil {
    panic(err)
}
defer identityModule.Close(context.Background())

identityClient, err := identityModule.NewSDKClient("tenant-a")
if err != nil {
    panic(err)
}
```

The returned client implements the same `identitysdk.Client` interface as
`remote.Client`; application and middleware code do not branch on deployment
mode.

## Development

```bash
go test ./...
go vet ./...
```
