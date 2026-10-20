import { useEffect, useState } from 'react'

// Panel name and subtitle, editable in 系统设置 and readable before login.
export interface Brand { name: string; subtitle: string; cert?: { name: string; sha256: string } }

const DEFAULT: Brand = { name: 'Wharf', subtitle: 'OpenWrt 控制面板' }
let current: Brand = DEFAULT
let loaded: Promise<void> | null = null
const subs = new Set<(b: Brand) => void>()

function publish(b: Brand) {
  current = b
  document.title = b.subtitle ? `${b.name} · ${b.subtitle}` : b.name
  subs.forEach((f) => f(b))
}

export function refreshBrand() {
  loaded = fetch('/api/public/config').then((r) => r.json())
    .then((c) => publish({ name: c.name || DEFAULT.name, subtitle: c.subtitle ?? DEFAULT.subtitle, cert: c.cert }))
    .catch(() => {})
  return loaded
}

export function useBrand(): Brand {
  const [b, setB] = useState(current)
  useEffect(() => {
    subs.add(setB)
    if (!loaded) refreshBrand()
    return () => { subs.delete(setB) }
  }, [])
  return b
}
