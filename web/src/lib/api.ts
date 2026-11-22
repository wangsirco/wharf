// Thin fetch wrapper: JSON in/out, CSRF header on writes, typed errors.
let csrf = ''
export const setCsrf = (t: string) => { csrf = t }
export const csrfToken = () => csrf

export class ApiError extends Error {
  status: number
  data: Record<string, unknown>
  constructor(status: number, message: string, data: Record<string, unknown> = {}) {
    super(message)
    this.status = status
    this.data = data
  }
}

let onUnauthorized: () => void = () => {}
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn }

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-OWP-CSRF'] = csrf
  const res = await fetch('/api' + path, {
    method, headers, credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/login') && !path.startsWith('/me')) onUnauthorized()
    throw new ApiError(res.status, data?.error ?? res.statusText, data ?? {})
  }
  if (method !== 'GET' && !quiet.some((q) => path.startsWith(q))) window.dispatchEvent(new Event('owp:mutated'))
  return data as T
}

// writes that never produce something to undo (sign-in, the wizard flag, undo itself …)
const quiet = ['/login', '/logout', '/me/onboarded', '/audit/', '/plugins/import/page', '/net/confirm', '/net/rollback', '/passkey', '/webauthn']

export const get = <T,>(p: string) => api<T>('GET', p)
export const post = <T,>(p: string, b: unknown = {}) => api<T>('POST', p, b)
export const put = <T,>(p: string, b: unknown) => api<T>('PUT', p, b)
export const del = <T,>(p: string) => api<T>('DELETE', p)
