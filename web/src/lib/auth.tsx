import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { get, post, setCsrf, setUnauthorizedHandler } from './api'
import type { Meta, User } from './types'
import { browserTZ } from './beacon'

interface AuthState {
  user: User | null
  meta: Meta | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
  onboarded: boolean
  setOnboarded: (v: boolean) => void
  can: (perm: string) => boolean
  isSuper: boolean
}

const Ctx = createContext<AuthState>(null!)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [meta, setMeta] = useState<Meta | null>(null)
  const [loading, setLoading] = useState(true)
  const [onboarded, setOnboarded] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const r = await get<{ user: User; csrf: string; onboarded: boolean }>('/me')
      setCsrf(r.csrf)
      setUser(r.user)
      setOnboarded(r.onboarded)
      setMeta(await get<Meta>('/meta'))
    } catch {
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null))
    refresh()
  }, [refresh])

  const login = async (username: string, password: string) => {
    const r = await post<{ user: User; csrf: string }>('/login', { username, password, tz: browserTZ() })
    setCsrf(r.csrf)
    setUser(r.user)
    setMeta(await get<Meta>('/meta'))
    setOnboarded((await get<{ onboarded: boolean }>('/me').catch(() => ({ onboarded: true }))).onboarded)
  }
  const logout = async () => {
    await post('/logout').catch(() => {})
    setUser(null)
  }
  const isSuper = user?.role === 'super'
  const can = (perm: string) => !!user && (isSuper || user.perms.includes(perm))

  return <Ctx.Provider value={{ user, meta, loading, login, logout, refresh, onboarded, setOnboarded, can, isSuper }}>{children}</Ctx.Provider>
}

export const useAuth = () => useContext(Ctx)
