import { useCallback, useEffect, useRef, useState } from 'react'
import { get } from './api'

// useApi loads a GET endpoint, optionally polling every `interval` ms while the tab is visible.
export function useApi<T>(path: string | null, interval = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const alive = useRef(true)

  const load = useCallback(async () => {
    if (!path) return
    try {
      const d = await get<T>(path)
      if (alive.current) { setData(d); setError(null) }
    } catch (e) {
      if (alive.current) setError((e as Error).message)
    } finally {
      if (alive.current) setLoading(false)
    }
  }, [path])

  useEffect(() => {
    alive.current = true
    setLoading(true)
    load()
    let t: number | undefined
    if (interval > 0) {
      t = window.setInterval(() => { if (!document.hidden) load() }, interval)
    }
    return () => { alive.current = false; if (t) clearInterval(t) }
  }, [load, interval])

  return { data, error, loading, reload: load, setData }
}
