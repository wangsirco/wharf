// Thin fetch wrapper: JSON in/out, CSRF header on writes, typed errors.
let csrf = ''
export const setCsrf = (t: string) => { csrf = t }
export const csrfToken = () => csrf

export class ApiError extends Error {
  status: number
  data: Record<string, unknown>
  /** what the server or the router actually said, when message is the plain-words version */
  detail: string
  /** a passing hiccup (router restarting a service, network blip): worth trying again by itself */
  retry: boolean
  constructor(status: number, message: string, data: Record<string, unknown> = {}) {
    const h = humanError(status, message)
    super(h.text)
    this.status = status
    this.data = data
    this.detail = h.text !== message ? message : ''
    this.retry = h.retry
  }
}

// Plain words for the errors people actually run into, with what to do next. Anything not
// listed passes through unchanged (most server messages are already written for people).
const PLAIN: [RegExp, string, boolean?][] = [
  [/agent unreachable|connection refused|connection reset|broken pipe|unexpected EOF|^EOF$/i, '路由器上的服务暂时没有响应（可能正在升级或重启服务），几秒后自动重试', true],
  [/deadline exceeded|i\/o timeout|Client\.Timeout|timed? ?out/i, '路由器响应太慢（超时），稍后自动重试', true],
  [/no space left on device/i, '路由器存储空间不足：先在「系统维护」里看看哪里占满了，清理后再试'],
  [/unknown package|cannot find package|no packages? (installed|available)/i, '软件源里找不到这个软件包：先在「插件 → 插件商店」里更新软件源列表再试'],
  [/wget returned|failed to download|download failed|opkg_download/i, '下载失败：路由器连不上软件源。检查外网是否正常，或稍后再试'],
  [/Invalid API Token|Authentication error|invalid request headers/i, 'Cloudflare 令牌无效或已过期：去「Cloudflare → 连接与令牌」重新填写'],
  [/does not have permission|Unauthorized to access requested resource|9109/i, 'Cloudflare 令牌缺少这项权限：去「Cloudflare → 连接与令牌」，按提示给令牌加上对应权限'],
  [/no such host|server misbehaving|NXDOMAIN/i, '域名解析不到：检查拼写，或等新的 DNS 记录生效（通常几分钟）'],
  [/x509: certificate|certificate signed by unknown authority|tls: bad certificate/i, '证书校验没通过：对方的证书不受信任或已过期'],
  [/Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module/i, '面板刚更新过，刷新一下页面就好'],
]

export function humanError(status: number, msg: string): { text: string; retry: boolean } {
  for (const [re, text, retry] of PLAIN) if (re.test(msg)) return { text, retry: !!retry }
  if ((status === 502 || status === 503 || status === 504) && (!msg || /^(Bad Gateway|Service Unavailable|Gateway Timeout)$/i.test(msg)))
    return { text: '面板暂时连不上路由器上的服务，几秒后自动重试', retry: true }
  if (status === 0) return { text: '连不上面板：网络断了，或者面板正在重启。几秒后自动重试', retry: true }
  return { text: msg, retry: false }
}

let onUnauthorized: () => void = () => {}
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn }

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-OWP-CSRF'] = csrf
  let res: Response
  try {
    res = await fetch('/api' + path, {
      method, headers, credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, 'network')
  }
  const text = await res.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { /* a proxy's HTML error page */ }
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
