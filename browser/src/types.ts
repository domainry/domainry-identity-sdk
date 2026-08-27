export interface IdentityClientConfiguration {
  endpoint?: string
  tenantId?: string
  workspaceId: string
  applicationKey: string
  fetch?: typeof globalThis.fetch
}

export interface IdentityProvider {
  key: string
  label: string
  type: 'password' | 'oidc' | 'saml' | 'otp' | string
  enabled: boolean
  channels?: string[]
}

export interface IdentityProviderChallenge {
  provider: string
  state: string
  nonce?: string
  code?: string
  auth_url?: string
  expires_at: string
}

export interface IdentitySession {
  session_id: string
  tenant_id: string
  workspace_id: string
  access_token: string
  token_type: string
  expires_at: string
  user: { id: string; name: string; email: string; locale?: string; version: number; status: string }
  roles: Array<{ id: string; key: string; label: string }>
  default_role: string
  permissions: string[]
  must_change_password: boolean
}

export interface IdentitySessionView {
  session_id: string
  tenant_id?: string
  workspace_id: string
  subject_id: string
  authorization_revision?: string
  user: IdentitySession['user']
  roles: IdentitySession['roles']
  default_role: string
  permissions: string[]
  must_change_password: boolean
}
