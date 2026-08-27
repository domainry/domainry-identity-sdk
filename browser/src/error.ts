export class IdentityClientError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
    message?: string,
    public readonly payload: Record<string, unknown> = {},
  ) {
    super(message || code)
  }
}
