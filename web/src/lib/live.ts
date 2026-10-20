import { useEffect, useState } from 'react'
import { get } from './api'
import type { LiveHost } from './types'

// useLive polls per-device rates (agent samples every 2 s); refreshes immediately when the tab becomes visible.
export function useLive(interval = 3000) {
  const [live, setLive] = useState<Record<string, LiveHost>>({})
  useEffect(() => {
    let alive = true
    const tick = () => {
      if (document.hidden) return
      get<{ hosts: Record<string, LiveHost> }>('/traffic/live').then((r) => { if (alive) setLive(r.hosts ?? {}) }).catch(() => {})
    }
    tick()
    const t = setInterval(tick, interval)
    document.addEventListener('visibilitychange', tick)
    return () => { alive = false; clearInterval(t); document.removeEventListener('visibilitychange', tick) }
  }, [interval])
  return live
}
