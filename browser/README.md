# @domainry/identity-client

Browser client for a Runtime-mounted Domainry Identity gateway. It keeps the
short-lived access token in memory and relies on a rotating `HttpOnly; Secure;
SameSite=Lax` refresh cookie. It never writes credentials to Web Storage.

The browser contract is Workspace-only. The client sends `workspace_id` and
`X-Workspace-ID` when configured, never sends `tenant_id`, and never accepts a
refresh credential into JavaScript. Requests use `credentials: include`; the
gateway rejects JSON `refresh_token` and all legacy tenant selectors.

The formal request, response, and cookie lifecycle contract is documented in
[`browsergateway/README.md`](../browsergateway/README.md).
