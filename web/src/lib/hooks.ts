import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, get } from './api'

// useApi loads a GET endpoint, optionally polling every `interval` ms while the tab is visible.
export function useApi<T>(path: string | null, interval = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const alive = useRef(true)

  const retryT = useRef<number | undefined>(undefined)
  const tries = useRef(0)

  // A passing hiccup (the router restarting a service, a network blip) is retried by
  // itself, a little later each time, and the page says so instead of showing a raw error.
  const load = useCallback(async () => {
    if (!path) return
    clearTimeout(retryT.current)
    try {
      const d = await get<T>(path)
      tries.current = 0
      if (alive.current) { setData(d); setError(null) }
    } catch (e) {
      if (!alive.current) return
      setError((e as Error).message)
      if (e instanceof ApiError && e.retry && tries.current < 8) {
        const wait = [3, 5, 8, 12, 20, 30, 30, 30][tries.current++] * 1000
        retryT.current = window.setTimeout(() => { if (alive.current) load() }, wait)
      }
    } finally {
      if (alive.current) setLoading(false)
    }
  }, [path])

  useEffect(() => {
    alive.current = true
    tries.current = 0
    setLoading(true)
    load()
    let t: number | undefined
    if (interval > 0) {
      t = window.setInterval(() => { if (!document.hidden) load() }, interval)
    }
    return () => { alive.current = false; if (t) clearInterval(t); clearTimeout(retryT.current) }
  }, [load, interval])

  return { data, error, loading, reload: load, setData }
}
