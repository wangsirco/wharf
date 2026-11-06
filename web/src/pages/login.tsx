import { useEffect, useState, type FormEvent } from 'react'
import { BrandMark } from '@/components/brand-mark'
import { useAuth } from '@/lib/auth'
import { sendBeacon } from '@/lib/beacon'
import { useBrand } from '@/lib/brand'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Field, ErrorBox } from '@/components/common'
import { CertHelp } from '@/components/cert-help'
import { browserTZ } from '@/lib/beacon'
import { finishSecondStep, passkeyLogin, passkeySupported, type SecondStep } from '@/lib/passkey'
import { KeyRound } from 'lucide-react'

export default function Login() {
  const { login, adopt } = useAuth()
  const brand = useBrand()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [second, setSecond] = useState<SecondStep | null>(null)
  useEffect(() => { sendBeacon('/login') }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true); setError('')
    try { setSecond(await login(username, password)); setPassword('') } catch (err) { setError((err as Error).message) } finally { setBusy(false) }
  }

  const pk = brand.passkey
  const onName = !!pk?.hosts.includes(location.hostname)
  const usePasskey = async () => {
    setBusy(true); setError('')
    try { await adopt(second ? await finishSecondStep(second, browserTZ()) : await passkeyLogin(browserTZ())) } catch (err) { if ((err as Error).message !== '已取消') setError((err as Error).message) } finally { setBusy(false) }
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
        {second ? (
          <div className="grid gap-4">
            <p className="text-center text-sm text-muted-foreground">密码正确。还差一步：用 Passkey 确认是你本人。</p>
            {error && <ErrorBox>{error}</ErrorBox>}
            <Button type="button" autoFocus disabled={busy} className="h-9" onClick={usePasskey}><KeyRound /> 验证 Passkey</Button>
            <Button type="button" variant="ghost" disabled={busy} className="h-9" onClick={() => { setSecond(null); setError('') }}>返回</Button>
          </div>
        ) : (
          <div className="grid gap-4">
            <Field label="用户名"><Input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
            <Field label="密码"><Input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
            {error && <ErrorBox>{error}</ErrorBox>}
            {error === '用户名或密码错误' && pk && onName && passkeySupported() && <p className="text-xs text-muted-foreground">如果这个账号设置了「只用 Passkey」，请点下面的按钮登录。</p>}
            <Button type="submit" disabled={busy || !username || !password} className="h-9">{busy ? '登录中…' : '登录'}</Button>
            {pk && onName && passkeySupported() && (
              <>
                <div className="flex items-center gap-3 text-xs text-muted-foreground"><span className="h-px flex-1 bg-border" />或<span className="h-px flex-1 bg-border" /></div>
                <Button type="button" variant="outline" disabled={busy} className="h-9" onClick={usePasskey}><KeyRound /> 用 Passkey 登录</Button>
              </>
            )}
            {pk && !onName && (
              <p className="text-center text-xs text-muted-foreground">
                想用 Passkey（Face ID / 指纹）登录？请通过 {pk.hosts.map((h, i) => (
                  <span key={h}>{i > 0 && ' 或 '}<a className="text-primary underline" href={`https://${h}${pk.port && pk.port !== '443' ? ':' + pk.port : ''}/login`}>{h}</a></span>
                ))} 打开面板
              </p>
            )}
          </div>
        )}
      </form>
      {brand.cert && <CertHelp cert={brand.cert} />}
    </div>
  )
}
