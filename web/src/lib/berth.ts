// Berth (the server panel) as seen by every signed-in user: is one paired, which devices
// are its hosts, and "open Berth" without signing in again (one-time ticket from Berth).
import { useEffect, useState } from 'react'
import { get, post } from './api'

export interface BerthStatus { paired: boolean; name?: string; url?: string; state?: 'active' | 'expired' | 'invalid'; hosts?: string[]; lan?: string; public?: string; mode?: string }

let cache: Promise<BerthStatus> | null = null
let cachedAt = 0

export function berthStatus(fresh = false) {
  if (fresh || !cache || Date.now() - cachedAt > 60_000) {
    cachedAt = Date.now()
    cache = get<BerthStatus>('/berth/status').catch(() => ({ paired: false }))
  }
  return cache
}

export function useBerth() {
  const [s, setS] = useState<BerthStatus>({ paired: false })
  useEffect(() => { let on = true; berthStatus().then((v) => on && setS(v)); return () => { on = false } }, [])
  return s
}

export type Via = 'lan' | 'public'
export interface OpenOpts { ref?: string; returnTo?: string }

const VIA_KEY = 'owp-berth-via'
const privateHost = (h: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h) || /\.(lan|local|home\.arpa|internal)$/.test(h)

/** Can this browser reach url within ms (no-cors: only whether it answers)? */
async function reachable(url: string, ms: number) {
  const c = new AbortController()
  const t = setTimeout(() => c.abort(), ms)
  try { await fetch(url, { mode: 'no-cors', cache: 'no-store', signal: c.signal }); return true } catch { return false } finally { clearTimeout(t) }
}

// decideVia (Wharf ⇄ Berth v3 §4): opened by a LAN name or address → Berth's LAN name;
// opened from outside → try Berth's LAN name for 1.5 s, use it when it answers … except
// that this disagrees with how the page was opened, so ask. Ask too when the only name
// Berth has does not match where we are. A remembered choice wins.
export async function decideVia(s: BerthStatus): Promise<{ via?: Via; ask?: Via }> {
  const has = { lan: !!s.lan, public: !!s.public }
  if (!has.lan && !has.public) return {} // an older Berth: its one address
  const saved = localStorage.getItem(VIA_KEY) as Via | null
  if (saved && has[saved]) return { via: saved }
  const atHome = privateHost(location.hostname)
  if (has.lan && has.public) {
    if (atHome) return { via: 'lan' }
    return (await reachable(s.lan!, 1500)) ? { ask: 'lan' } : { via: 'public' }
  }
  const only: Via = has.lan ? 'lan' : 'public'
  if ((only === 'lan') === atHome) return { via: only }
  return { ask: only }
}

export function rememberVia(v: Via | null) { if (v) localStorage.setItem(VIA_KEY, v); else localStorage.removeItem(VIA_KEY) }

// openBerth asks Berth for a sign-in link as this user. The window opens first so the
// browser does not treat it as a pop-up; it is pointed at Berth once the link arrives.
// When it is not clear which of Berth's names this device can reach, the window closes
// again and a small menu asks (BerthChooser).
export async function openBerth(opts: OpenOpts = {}, via?: Via) {
  const win = window.open('about:blank', '_blank')
  if (win) win.opener = null
  try {
    if (!via) {
      const d = await decideVia(await berthStatus())
      if (d.ask) {
        win?.close()
        window.dispatchEvent(new CustomEvent('owp:berth-choose', { detail: { rec: d.ask, opts } }))
        return
      }
      via = d.via
    }
    const r = await post<{ url: string }>('/berth/sso', { ref: opts.ref ?? '', return_to: opts.returnTo ?? '/', via: via ?? '' })
    if (win) win.location.href = r.url
    else window.location.href = r.url
  } catch (e) {
    win?.close()
    throw e
  }
}
