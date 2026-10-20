export type IdentityHTTPErrorResponse = {
  code: string;
  message: string;
  params?: Record<string, string>;
  request_id: string;
}

export function parseIdentityHTTPErrorResponse(value: unknown): IdentityHTTPErrorResponse | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const record = value as Record<string, unknown>
  if (typeof record.code !== 'string' || !record.code.trim() || typeof record.message !== 'string' || !record.message.trim() || typeof record.request_id !== 'string') return null
  if (record.params !== undefined && (!record.params || typeof record.params !== 'object' || Array.isArray(record.params) || Object.values(record.params).some((item) => typeof item !== 'string'))) return null
  return {
    code: record.code,
    message: record.message,
    ...(record.params === undefined ? {} : { params: record.params as Record<string, string> }),
    request_id: record.request_id,
  }
}

export class IdentityClientError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
    message?: string,
    public readonly params?: Record<string, string>,
    public readonly requestID = '',
  ) {
    super(message || code)
    this.name = 'IdentityClientError'
  }
}

export async function identityClientErrorFromResponse(response: Response): Promise<IdentityClientError> {
  const value = parseIdentityHTTPErrorResponse(await response.json().catch(() => undefined))
  return value
    ? new IdentityClientError(value.code, response.status, value.message, value.params, value.request_id)
    : new IdentityClientError('identity.request_failed', response.status)
}
