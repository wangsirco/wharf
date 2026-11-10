// Berth (the server panel) as seen by every signed-in user: is one paired, which devices
// are its hosts, and "open Berth" without signing in again (one-time ticket from Berth).
import { useEffect, useState } from 'react'
import { get, post } from './api'

export interface BerthStatus { paired: boolean; name?: string; url?: string; state?: 'active' | 'expired' | 'invalid'; hosts?: string[] }

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

// openBerth asks Berth for a sign-in link as this user. The window opens first so the
// browser does not treat it as a pop-up; it is pointed at Berth once the link arrives.
export async function openBerth(opts: { ref?: string; returnTo?: string } = {}) {
  const win = window.open('about:blank', '_blank')
  if (win) win.opener = null
  try {
    const r = await post<{ url: string }>('/berth/sso', { ref: opts.ref ?? '', return_to: opts.returnTo ?? '/' })
    if (win) win.location.href = r.url
    else window.location.href = r.url
  } catch (e) {
    win?.close()
    throw e
  }
}

