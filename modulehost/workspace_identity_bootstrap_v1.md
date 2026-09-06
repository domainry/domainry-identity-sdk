# Workspace Identity bootstrap V1

Workspace bootstrap is a trusted in-process contract. Its only protocol is
`domainry-workspace-identity-bootstrap-v1`, with SHA-256
`2437c3597855a0985c63d82bc4f524e4e28053ba54d956c790262a1500d7c53c`.

The host binds a `ProjectRoleCatalog` before the first Workspace transaction.
`InitialWorkspaceAdministratorRoleKey` is mandatory. Identity provisions every
role marked `provision_to_workspaces=true` whose audience is `any`, `user`, or
`business_profile` and whose assignment mode is `manual` or `request_only`.
The initial administrator role is more restrictive: it must be explicitly
named, provisioned, manually assignable, have audience `any` or `user`, and
must not require another binding.

The SDK canonicalizes the complete selected authorization definitions and the
explicit administrator key through
`WorkspaceBootstrapProjectRoleCatalogSHA256`. The digest covers permissions,
data scopes, policy JSON, schema hashes, guardrails, role relations, and the
remaining role metadata. Semantic ordering and JSON formatting differences do
not change the digest; authorization changes do.

The public capability is `WorkspaceIdentityBootstrap`:

- `BootstrapWorkspaceIdentity` joins the host-owned transaction and returns a
  non-secret `WorkspaceIdentityBootstrapReceipt`.
- `CompleteWorkspaceIdentityBootstrap` reports the host's commit or rollback.
- `ClaimWorkspaceIdentityBootstrapCredential` releases the volatile initial
  credential once, only after Identity verifies the committed receipt through
  the ordinary database pool.

Requests, completion signals, claims, and one-time credentials are excluded
from JSON. The receipt includes `role_catalog_sha256` and
`initial_workspace_administrator_role_key`, so replay binds to the same trusted
role policy. Identity owns no transaction commit, rollback, migration ledger,
or durable plaintext credential.
