# Identity browser gateway contract

The browser gateway is a Workspace-scoped session boundary over the
deployment-neutral Identity binding. Browser callers never select a tenant:
`tenant_id` is rejected as an unknown JSON field, and `tenant_id` query values
or `X-Tenant-ID` headers return HTTP 400 (`identity.workspace_scope_only`).
Compatibility-only `TenantID` fields may remain in lower SDK contracts, but the
gateway neither sets them on binding requests nor serializes them in responses.

## Request boundary

All JSON is decoded strictly. Unknown fields return HTTP 400. The session and
federated authentication bodies accept only these fields:

- `POST /auth/login`: `workspace_id`, `login`, `password`
- `POST /auth/refresh`: `workspace_id`
- `POST /auth/logout`: `workspace_id`
- `POST /auth/providers/{provider}/start`: `workspace_id`,
  `return_url`, `phone`
- `POST /auth/providers/{provider}/verify`: `workspace_id`, `state`, `code`
- `POST /auth/code/exchange`: `workspace_id`, `code`,
  `return_url`
- `GET /auth/providers` and `GET /auth/session`: no JSON body

Workspace selectors from `X-Workspace-ID`, `workspace_id` query parameters,
and JSON must agree. When omitted, the host's initialized Workspace is used.
The application key is established by the Binding and is never accepted from
browser input.

`refresh_token` is not a valid JSON field on any browser session mutation. A
browser sends the refresh cookie using `credentials: include`.

## Response boundary

Authenticated session JSON is projected through a browser-specific allowlist.
It includes the Workspace ID, short-lived access token, session/user/role and
authorization fields, but never includes `tenant_id` or `refresh_token`.
`GET /auth/session` uses the same Workspace-only rule. Challenge responses
contain only `status` and `challenge`.

Every JSON response and logout response carries `Cache-Control: no-store`.

## Refresh-cookie lifecycle

The refresh credential is carried only by a cookie with an explicit path,
`HttpOnly`, an explicit `SameSite` mode, and the configured lifetime. Hosts must
set `Secure` in production (the standalone Identity server does so from its
production environment setting).

- Successful password, OTP, authorization-code, password-change, and refresh
  operations issue or atomically rotate the cookie.
- Reusing a rotated credential is detected by Identity and revokes its session
  family; the gateway rejects it and expires the browser cookie.
- Logout revokes the presented session and always expires the browser cookie,
  including when the downstream revocation reports an error.
- Invalid, expired, revoked, or reused refresh credentials expire the cookie.
  Transient downstream failures leave it intact so a later retry is possible.
- A successful binding response without a new refresh credential is rejected
  as an invalid upstream response and any stale cookie is expired.

Cookie `Domain`, `Path`, `Secure`, `SameSite`, and maximum age are host
configuration. The cookie path must cover every mounted browser auth endpoint.
