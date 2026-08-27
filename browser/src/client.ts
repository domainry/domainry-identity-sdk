import { IdentityClientError } from './error.js'
import type {
  IdentityClientConfiguration,
  IdentityProvider,
  IdentityProviderChallenge,
  IdentitySession,
  IdentitySessionView,
} from './types.js'

/**
 * Browser Identity client. Access tokens live in memory. Refresh credentials
 * are rotating HttpOnly cookies and therefore never enter JavaScript storage.
 */
export class IdentityClient {
  #accessToken = ''
	#fetch: typeof globalThis.fetch
	#endpoint: string
	#managementEndpoint: string
  #listeners = new Set<(session: IdentitySession | null) => void>()
  #refreshInFlight: Promise<IdentitySession> | null = null

  constructor(private readonly configuration: IdentityClientConfiguration) {
    if (!configuration.workspaceId.trim() || !configuration.applicationKey.trim()) {
      throw new Error('workspaceId and applicationKey are required')
    }
		this.#endpoint = (configuration.endpoint || '').replace(/\/$/, '')
		this.#managementEndpoint = (configuration.managementEndpoint || configuration.endpoint || '').replace(/\/$/, '')
    this.#fetch = configuration.fetch || ((input, init) => globalThis.fetch(input, init))
  }

  accessToken(): string {
    return this.#accessToken
  }

  /**
	 * Sends a downstream request with the current in-memory access token. A 401 is
   * retried once only for read operations or mutations carrying an
   * Idempotency-Key; concurrent callers share the same refresh rotation.
   */
	async authorizedFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
    const replaySafe = this.#isReplaySafe(input, init)
    // A Request body is a one-shot stream. Clone it before the first dispatch so
    // an explicitly idempotent mutation can be retried after token refresh.
    const retryInput = replaySafe && input instanceof Request ? input.clone() : input
    let response = await this.#fetch(input, this.#authorizedInit(init))
    if (response.status !== 401 || !replaySafe) return response

    await response.body?.cancel().catch(() => undefined)
    await this.refresh()
    response = await this.#fetch(retryInput, this.#authorizedInit(init))
		return response
	}

	/**
	 * Sends an authenticated request to an Identity-owned endpoint. Consumers
	 * use this for management APIs without duplicating token refresh/replay
	 * behavior or reaching into the configured Identity base URL.
	 */
	async authorizedRequest(path: string, init: RequestInit = {}): Promise<Response> {
		if (!path.startsWith('/')) throw new Error('Identity request path must start with /')
		return this.authorizedFetch(this.#managementEndpoint + path, init)
	}

  subscribe(listener: (session: IdentitySession | null) => void): () => void {
    this.#listeners.add(listener)
    return () => this.#listeners.delete(listener)
  }

  async providers(): Promise<IdentityProvider[]> {
    return this.#request('/auth/providers', { method: 'GET' })
  }

  async loginWithPassword(login: string, password: string): Promise<IdentitySession> {
    const session = await this.#request<IdentitySession>('/auth/login', {
      method: 'POST',
      body: this.#body({ login, password, application_key: this.configuration.applicationKey }),
    })
    return this.#accept(session)
  }

  async beginProvider(provider: string, options: { returnUrl?: string; phone?: string } = {}): Promise<IdentityProviderChallenge> {
    return this.#request(`/auth/providers/${encodeURIComponent(provider)}/start`, {
      method: 'POST',
      body: this.#body({
        application_key: this.configuration.applicationKey,
        return_url: options.returnUrl,
        phone: options.phone,
      }),
    })
  }

  async beginFederatedLogin(provider: string, returnUrl = `${globalThis.location?.origin || ''}/auth/callback`): Promise<never> {
    const challenge = await this.beginProvider(provider, { returnUrl })
    if (!challenge.auth_url) throw new IdentityClientError('identity.provider_redirect_missing', 502)
    globalThis.location.assign(challenge.auth_url)
    return new Promise<never>(() => undefined)
  }

  async verifyOTP(provider: string, state: string, code: string): Promise<IdentitySession> {
    const session = await this.#request<IdentitySession>(`/auth/providers/${encodeURIComponent(provider)}/verify`, {
      method: 'POST',
      body: this.#body({ state, code }),
    })
    return this.#accept(session)
  }

  async exchangeAuthorizationCode(code: string, returnUrl: string): Promise<IdentitySession> {
    const session = await this.#request<IdentitySession>('/auth/code/exchange', {
      method: 'POST',
      body: this.#body({ code, return_url: returnUrl, application_key: this.configuration.applicationKey }),
    })
    return this.#accept(session)
  }

  async completeFederatedLoginFromLocation(location = globalThis.location?.href || ''): Promise<IdentitySession> {
    const callback = new URL(location)
    const code = callback.searchParams.get('code') || ''
    if (!code) throw new IdentityClientError('auth.authorization_code_required', 400)
    callback.searchParams.delete('code')
    callback.searchParams.delete('state')
    return this.exchangeAuthorizationCode(code, callback.toString())
  }

  async refresh(): Promise<IdentitySession> {
    if (this.#refreshInFlight) return this.#refreshInFlight

    const refresh = this.#withCrossTabRefreshLock(async () => {
      const session = await this.#request<IdentitySession>('/auth/refresh', {
        method: 'POST',
        body: this.#body({}),
      })
      return this.#accept(session)
    })
    this.#refreshInFlight = refresh

    try {
      return await refresh
    } catch (error) {
      if (error instanceof IdentityClientError && (error.status === 401 || error.status === 403)) {
        this.#clearSession()
      }
      throw error
    } finally {
      if (this.#refreshInFlight === refresh) this.#refreshInFlight = null
    }
  }

  async changePassword(currentPassword: string, newPassword: string, idempotencyKey: string): Promise<IdentitySession> {
    const session = await this.#request<IdentitySession>(
      '/auth/change-password',
      {
        method: 'POST',
        headers: { 'Idempotency-Key': idempotencyKey },
        // The bearer token is the authoritative workspace/subject scope. Keep
        // caller-controlled scope fields out of this credential mutation.
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      },
      true,
    )
    return this.#accept(session)
  }

  async currentSession(): Promise<IdentitySessionView> {
    return this.#request('/auth/session', { method: 'GET' }, true)
  }

  async logout(): Promise<void> {
    try {
      await this.#request('/auth/logout', { method: 'POST', body: this.#body({}) })
    } finally {
      this.#clearSession()
    }
  }

  async #request<T>(path: string, init: RequestInit, refreshOnUnauthorized = false): Promise<T> {
    let response = await this.#send(path, init)
    if (response.status === 401 && refreshOnUnauthorized) {
      await response.body?.cancel().catch(() => undefined)
      await this.refresh()
      response = await this.#send(path, init)
    }
    const payload = response.status === 204 ? undefined : await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new IdentityClientError(payload?.code || 'identity.request_failed', response.status, payload?.message, payload)
    }
    return payload as T
  }

  #send(path: string, init: RequestInit): Promise<Response> {
    const headers = new Headers(init.headers)
    headers.set('Accept', 'application/json')
    headers.set('X-Workspace-ID', this.configuration.workspaceId)
    if (init.body) headers.set('Content-Type', 'application/json')
    if (this.#accessToken) headers.set('Authorization', `Bearer ${this.#accessToken}`)
    return this.#fetch(this.#endpoint + path, { ...init, headers, credentials: 'include' })
  }

  #body(value: Record<string, unknown>): string {
    return JSON.stringify({
      tenant_id: this.configuration.tenantId,
      workspace_id: this.configuration.workspaceId,
      ...value,
    })
  }

  #accept(session: IdentitySession): IdentitySession {
    this.#accessToken = session.access_token
    this.#listeners.forEach((listener) => listener(session))
    return session
  }

  #clearSession(): void {
    this.#accessToken = ''
    this.#listeners.forEach((listener) => listener(null))
  }

  #authorizedInit(init: RequestInit): RequestInit {
    const headers = new Headers(init.headers)
    headers.set('X-Workspace-ID', this.configuration.workspaceId)
    if (this.#accessToken) headers.set('Authorization', `Bearer ${this.#accessToken}`)
    else headers.delete('Authorization')
    return { ...init, headers }
  }

  #isReplaySafe(input: RequestInfo | URL, init: RequestInit): boolean {
    const method = (init.method || (input instanceof Request ? input.method : 'GET')).toUpperCase()
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return true
    const headers = new Headers(input instanceof Request ? input.headers : undefined)
    new Headers(init.headers).forEach((value, key) => headers.set(key, value))
    return Boolean(headers.get('Idempotency-Key')?.trim())
  }

  async #withCrossTabRefreshLock<T>(operation: () => Promise<T>): Promise<T> {
    const lockManager = globalThis.navigator?.locks
    if (!lockManager) return operation()

    const endpoint = this.#endpoint || globalThis.location?.origin || 'same-origin'
    const lockName = `domainry.identity.refresh:${endpoint}:${this.configuration.workspaceId}`
    return lockManager.request(lockName, operation)
  }
}
