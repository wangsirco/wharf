// Reports this page view with the browser's own clock and timezone, plus (if enabled)
// what api.ip.sb sees as this browser's IP. The server records access time, IP,
// ASN/ISP from its offline database and compares (proxy check).
let ipsbEnabled: Promise<boolean> | null = null

async function ipsb(): Promise<unknown> {
  ipsbEnabled ??= fetch('/api/public/config').then((r) => r.json()).then((c) => !!c.ipsb).catch(() => false)
  if (!(await ipsbEnabled)) return undefined
  try {
    const ctl = new AbortController()
    const t = setTimeout(() => ctl.abort(), 3000)
    const r = await fetch('https://api.ip.sb/geoip', { signal: ctl.signal, credentials: 'omit', referrerPolicy: 'no-referrer' })
    clearTimeout(t)
    return r.ok ? await r.json() : undefined
  } catch {
    return undefined
  }
}

export async function sendBeacon(path: string) {
  const now = new Date()
  const p = (x: number) => String(x).padStart(2, '0')
  const local = `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())} ${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`
  const body = JSON.stringify({
    tz: browserTZ(),
    offset: -now.getTimezoneOffset(),
    local_time: local,
    path,
    ipsb: await ipsb(),
  })
  fetch('/api/beacon', { method: 'POST', body, headers: { 'Content-Type': 'application/json' }, keepalive: true, credentials: 'same-origin' }).catch(() => {})
}

export const browserTZ = () => Intl.DateTimeFormat().resolvedOptions().timeZone ?? ''
