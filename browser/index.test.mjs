import assert from 'node:assert/strict'
import test from 'node:test'

import { IdentityClient, IdentityClientError } from './dist/index.js'

const session = {
  session_id: 'session-1', tenant_id: '', workspace_id: 'default', access_token: 'access-1',
  token_type: 'Bearer', expires_at: '2026-08-27T00:00:00Z',
  user: { id: 'user-1', name: 'User', email: 'user@example.test', version: 1, status: 'active' },
  roles: [], default_role: '', permissions: [], must_change_password: false,
}

test('keeps access credentials in memory and sends cookie-bound requests', async () => {
  const requests = []
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: new Proxy({}, { get() { throw new Error('storage must not be used') } }) })
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'workspace-a', applicationKey: 'runtime-app',
    fetch: async (url, init) => {
      requests.push([url, init])
      return new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })
  await client.loginWithPassword('user@example.test', 'secret')
  assert.equal(client.accessToken(), 'access-1')
  assert.equal(requests[0][1].credentials, 'include')
  assert.equal(JSON.parse(requests[0][1].body).workspace_id, 'workspace-a')
  assert.equal(new Headers(requests[0][1].headers).get('X-Workspace-ID'), 'workspace-a')
  await client.currentSession()
  assert.equal(new Headers(requests[1][1].headers).get('Authorization'), 'Bearer access-1')
  assert.equal(new Headers(requests[1][1].headers).get('X-Workspace-ID'), 'workspace-a')
})

test('clears the in-memory access token even when remote logout fails', async () => {
  let calls = 0
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async () => {
      calls++
      if (calls === 1) return new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } })
      return new Response(JSON.stringify({ code: 'identity.remote_unavailable' }), { status: 503, headers: { 'content-type': 'application/json' } })
    },
  })
  await client.loginWithPassword('user@example.test', 'secret')
  await assert.rejects(client.logout(), IdentityClientError)
  assert.equal(client.accessToken(), '')
})

test('uses the same provider contract for OTP without exposing refresh credentials', async () => {
  const requests = []
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async (url, init) => {
      requests.push([url, init])
      const body = url.endsWith('/start')
        ? { provider: 'sms', state: 'state-1', expires_at: '2026-08-27T00:00:00Z' }
        : session
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })
  const challenge = await client.beginProvider('sms', { phone: '+8613800000000' })
  assert.equal(challenge.state, 'state-1')
  assert.equal(JSON.parse(requests[0][1].body).phone, '+8613800000000')
  await client.verifyOTP('sms', challenge.state, '123456')
  assert.equal(client.accessToken(), 'access-1')
  assert.equal(JSON.parse(requests[1][1].body).code, '123456')
  assert.equal(requests[1][1].credentials, 'include')
})

test('coalesces concurrent refreshes into one rotating-cookie request', async () => {
  let refreshCalls = 0
  let releaseRefresh
  const refreshReleased = new Promise((resolve) => { releaseRefresh = resolve })
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async (url) => {
      assert.match(url, /\/auth\/refresh$/)
      refreshCalls++
      await refreshReleased
      return new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })

  const refreshes = Array.from({ length: 20 }, () => client.refresh())
  await Promise.resolve()
  assert.equal(refreshCalls, 1)
  releaseRefresh()
  const sessions = await Promise.all(refreshes)

  assert.equal(refreshCalls, 1)
  assert.ok(sessions.every((value) => value.access_token === 'access-1'))
  assert.equal(client.accessToken(), 'access-1')
})

test('releases the single-flight refresh after failure', async () => {
  let refreshCalls = 0
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async () => {
      refreshCalls++
      if (refreshCalls === 1) {
        return new Response(JSON.stringify({ code: 'identity.refresh_failed' }), {
          status: 401, headers: { 'content-type': 'application/json' },
        })
      }
      return new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })

  await assert.rejects(client.refresh(), IdentityClientError)
  const recovered = await client.refresh()

  assert.equal(refreshCalls, 2)
  assert.equal(recovered.access_token, 'access-1')
})

test('clears a stale in-memory credential when refresh is rejected', async () => {
  let calls = 0
  let cleared = false
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async () => {
      calls++
      if (calls === 1) return new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } })
      return new Response(JSON.stringify({ code: 'auth.session_expired' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      })
    },
  })
  client.subscribe((value) => { if (value === null) cleared = true })
  await client.loginWithPassword('user@example.test', 'secret')
  await assert.rejects(client.refresh(), IdentityClientError)
  assert.equal(client.accessToken(), '')
  assert.equal(cleared, true)
})

test('scopes password changes from the bearer token rather than JSON fields', async () => {
  const requests = []
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'workspace-a', applicationKey: 'runtime-app',
    fetch: async (url, init) => {
      requests.push([url, init])
      return new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })
  await client.loginWithPassword('user@example.test', 'secret')
  await client.changePassword('secret', 'new-secret', 'password-change-1')
  const body = JSON.parse(requests[1][1].body)
  assert.deepEqual(body, { current_password: 'secret', new_password: 'new-secret' })
  assert.equal(new Headers(requests[1][1].headers).get('X-Workspace-ID'), 'workspace-a')
})

test('reauthorizes concurrent safe Runtime requests with one refresh', async () => {
  let refreshCalls = 0
  let runtimeCalls = 0
  let refreshed = false
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async (url, init) => {
      if (String(url).endsWith('/auth/refresh')) {
        refreshCalls++
        await Promise.resolve()
        refreshed = true
        return new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      runtimeCalls++
      const headers = new Headers(init?.headers)
      const authorization = headers.get('Authorization')
      assert.equal(headers.get('X-Workspace-ID'), 'default')
      if (!refreshed) return new Response(JSON.stringify({ code: 'auth.token_expired' }), { status: 401 })
      assert.equal(authorization, 'Bearer access-1')
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    },
  })

  const responses = await Promise.all(Array.from({ length: 20 }, () => (
    client.authorizedFetch('https://runtime.example.test/orders')
  )))

  assert.equal(refreshCalls, 1)
  assert.ok(runtimeCalls >= 20)
  assert.ok(responses.every((response) => response.ok))
})

test('does not replay an unsafe mutation without an idempotency key', async () => {
  let calls = 0
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async () => {
      calls++
      return new Response(JSON.stringify({ code: 'auth.token_expired' }), { status: 401 })
    },
  })

  const response = await client.authorizedFetch('https://runtime.example.test/orders', {
    method: 'POST', body: JSON.stringify({ number: 'SO-1' }),
  })

  assert.equal(response.status, 401)
  assert.equal(calls, 1)
})

test('derives replay safety from Request method and preserves idempotent body', async () => {
  let runtimeCalls = 0
  let refreshCalls = 0
  const bodies = []
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async (input) => {
      if (String(input) === 'https://runtime.example.test/auth/refresh') {
        refreshCalls++
        return new Response(JSON.stringify(session), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      runtimeCalls++
      if (input instanceof Request) bodies.push(await input.text())
      return runtimeCalls === 1
        ? new Response(JSON.stringify({ code: 'auth.token_expired' }), { status: 401 })
        : new Response(JSON.stringify({ ok: true }), { status: 200 })
    },
  })

  const request = new Request('https://runtime.example.test/orders', {
    method: 'POST', headers: { 'Idempotency-Key': 'create-order-1' }, body: JSON.stringify({ number: 'SO-1' }),
  })
  const response = await client.authorizedFetch(request)

  assert.equal(response.status, 200)
  assert.equal(refreshCalls, 1)
  assert.equal(runtimeCalls, 2)
  assert.deepEqual(bodies, ['{"number":"SO-1"}', '{"number":"SO-1"}'])
})

test('does not treat a non-idempotent Request mutation as a GET', async () => {
  let calls = 0
  const client = new IdentityClient({
    endpoint: 'https://runtime.example.test', workspaceId: 'default', applicationKey: 'runtime-app',
    fetch: async () => {
      calls++
      return new Response(JSON.stringify({ code: 'auth.token_expired' }), { status: 401 })
    },
  })

  const response = await client.authorizedFetch(new Request('https://runtime.example.test/orders', {
    method: 'POST', body: JSON.stringify({ number: 'SO-2' }),
  }))

  assert.equal(response.status, 401)
  assert.equal(calls, 1)
})
