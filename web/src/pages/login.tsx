import { useEffect, useState, type FormEvent } from 'react'
import { BrandMark } from '@/components/brand-mark'
import { useAuth } from '@/lib/auth'
import { sendBeacon } from '@/lib/beacon'
import { useBrand } from '@/lib/brand'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Field, ErrorBox } from '@/components/common'
import { CertHelp } from '@/components/cert-help'

export default function Login() {
  const { login } = useAuth()
  const brand = useBrand()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { sendBeacon('/login') }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true); setError('')
    try { await login(username, password) } catch (err) { setError((err as Error).message) } finally { setBusy(false) }
  }

  return (
    <div className="grid min-h-svh place-content-center justify-items-center gap-3 bg-background p-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border bg-card p-7 shadow-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <div className="grid size-11 place-items-center rounded-xl bg-gradient-to-b from-[#3b8bf6] to-[#1d5fe0] text-white"><BrandMark className="size-7" /></div>
          <div>
            <h1 className="text-lg font-semibold">登录 {brand.name}</h1>
            {brand.subtitle && <p className="text-sm text-muted-foreground">{brand.subtitle}</p>}
          </div>
        </div>
        <div className="grid gap-4">
          <Field label="用户名"><Input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
          <Field label="密码"><Input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
          {error && <ErrorBox>{error}</ErrorBox>}
          <Button type="submit" disabled={busy || !username || !password} className="h-9">{busy ? '登录中…' : '登录'}</Button>
        </div>
      </form>
      {brand.cert && <CertHelp cert={brand.cert} />}
    </div>
  )
}
