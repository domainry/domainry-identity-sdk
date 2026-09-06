# Workspace Identity bootstrap V2 SDK contract

`WorkspaceIdentityBootstrapV2` is the non-HTTP Protocol V3 initialization
capability. Its pinned version is `domainry-workspace-identity-bootstrap-v2`
and its pinned SHA-256 is
`5011287354029d67c64e1f9dedf3767234c9af8d7ec7e29886a9b4b419ccc9c8`.

The required call order is:

1. `BootstrapWorkspaceIdentityV2(request, hostTransaction)`
2. commit or roll back the host transaction
3. `CompleteWorkspaceIdentityBootstrapV2(completion)` with the actual outcome
4. only after `committed`,
   `ClaimWorkspaceIdentityBootstrapCredentialV2(claim)` exactly once

The bootstrap request carries host-controlled Workspace, company, first-store,
and initial-user identifiers. It has no caller-selected role, organization
parent, `owner_org_id`, or initial password. All request/completion/claim fields
and the one-time credential are excluded from JSON.

The materialized role keys are exactly `tenant_admin`, `headquarters_admin`,
`store_manager`, and `staff`. `tenant_admin` is a role key only; its UI label is
Platform administrator. The initial company-bound user receives only
`headquarters_admin`.

The transaction-phase receipt is non-secret and replayable. The plaintext
credential is volatile, bounded to five minutes, destroyed on rollback, and
returned only once after a verified commit. It is never persisted or included
in a receipt, replay, or audit record.

