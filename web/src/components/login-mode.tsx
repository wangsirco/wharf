import { useRef, useState, type ReactNode } from 'react'
import { Check, KeyRound, ShieldCheck, Smartphone } from 'lucide-react'
import { toast } from 'sonner'
import { post, put } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useApi } from '@/lib/hooks'
import { addPasskey, defaultPasskeyName, passkeySupported, verifyPasskey } from '@/lib/passkey'
import { cn } from '@/lib/utils'
import { ErrorBox } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'

export interface PasskeyList {
  passkeys: { id: number; name: string; rp_id: string; created: number; last_used: number }[]
  usable: boolean; here: string; hosts: string[]; port: string
}

export const panelURL = (host: string, port: string, path: string) => `https://${host}${port && port !== '443' ? ':' + port : ''}${path}`

export const loginModeNames: Record<string, string> = { password: '密码或 Passkey', two_step: '密码 + Passkey', passkey: '只用 Passkey' }

// useReauth: someone in a strict mode proves themselves before weakening it, with a passkey
// where this name has one and the password otherwise. The server enforces it.
export function useReauth(pk?: PasskeyList | null) {
  const { user } = useAuth()
  const [asking, setAsking] = useState(false)
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const pending = useRef<{ ok: () => void; no: (e: Error) => void } | null>(null)

  const ensure = async () => {
    if (user?.login_mode === 'password') return
    if (pk?.usable && pk.passkeys.some((p) => p.rp_id === pk.here) && passkeySupported()) return verifyPasskey()
    setPassword(''); setError(''); setAsking(true)
    return new Promise<void>((ok, no) => { pending.current = { ok, no } })
  }
  const close = () => { setAsking(false); pending.current?.no(new Error('已取消')); pending.current = null }
  const submit = async () => {
    try {
      await post('/me/reauth', { password })
      setAsking(false); pending.current?.ok(); pending.current = null
    } catch (e) { setError((e as Error).message) }
  }
  const dialog = (
    <Dialog open={asking} onOpenChange={(o) => { if (!o) close() }}>
      <DialogContent className="sm:max-w-sm">
        <DialogTitle>验证身份</DialogTitle>
        <form className="grid gap-3" onSubmit={(e) => { e.preventDefault(); submit() }}>
          <p className="text-sm text-muted-foreground">这个地址上没有你的 Passkey，请输入当前密码继续。</p>
          <Input autoFocus type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          {error && <ErrorBox>{error}</ErrorBox>}
          <Button type="submit" disabled={!password}>继续</Button>
        </form>
      </DialogContent>
    </Dialog>
  )
  return { ensure, dialog }
}

const modes: { key: string; title: string; desc: string; icon: typeof KeyRound }[] = [
  { key: 'password', title: loginModeNames.password, desc: '输入用户名和密码，或者直接用 Passkey，二选一。', icon: KeyRound },
  { key: 'two_step', title: loginModeNames.two_step, desc: '先输入密码，再用 Passkey 确认。单独的密码或 Passkey 都进不来。', icon: ShieldCheck },
  { key: 'passkey', title: loginModeNames.passkey, desc: '不用记密码；密码再对也登录不了，不怕被人试出来。', icon: Smartphone },
]

// LoginMode: the three ways to sign in. Choosing a strict one on a name where a passkey
// can be made creates the passkey on the spot if there is none yet.
export function LoginMode({ pk, reload }: { pk?: PasskeyList | null; reload: () => void }): ReactNode {
  const { user, refresh } = useAuth()
  const { ensure, dialog } = useReauth(pk)
  const [busy, setBusy] = useState(false)
  if (!pk || !user) return null

  const owned = pk.hosts.filter((h) => pk.passkeys.some((p) => p.rp_id === h))
  const canAddHere = pk.usable && passkeySupported()
  const mode = user.login_mode

  const choose = async (next: string) => {
    if (next === mode || busy) return
    setBusy(true)
    try {
      await ensure()
      if (next !== 'password' && !owned.length) await addPasskey(defaultPasskeyName())
      await put('/me/login-mode', { mode: next })
      await refresh()
      reload()
      toast.success(`登录方式已改为「${loginModeNames[next]}」`)
    } catch (e) { if ((e as Error).message !== '已取消') toast.error((e as Error).message) } finally { setBusy(false) }
  }

  const missing = mode === 'password' ? [] : pk.hosts.filter((h) => !owned.includes(h))
  return (
    <div className="grid gap-3">
      <div className="grid gap-2">
        {modes.map((m) => {
          const blocked = m.key !== 'password' && !owned.length && !canAddHere
          return (
            <button key={m.key} type="button" disabled={busy || blocked} onClick={() => choose(m.key)}
              className={cn('flex items-start gap-3 rounded-xl border p-3 text-left transition-colors', mode === m.key ? 'border-primary bg-accent/50 ring-2 ring-primary/20' : 'hover:border-primary/50', blocked && 'cursor-not-allowed opacity-60')}>
              <m.icon className="mt-0.5 size-4 shrink-0 text-primary" />
              <span className="min-w-0 flex-1"><span className="block text-sm font-medium">{m.title}</span><span className="text-xs text-muted-foreground">{m.desc}</span></span>
              {mode === m.key && <Check className="size-4 shrink-0 text-primary" />}
            </button>
          )
        })}
      </div>
      {!owned.length && !canAddHere && (
        <p className="text-xs text-muted-foreground">
          后两种需要 Passkey，而 Passkey 只能在面板的域名上添加。请从 {pk.hosts.map((h, i) => (
            <span key={h}>{i > 0 && ' 或 '}<a className="text-primary underline" href={panelURL(h, pk.port, '/account')}>{h}</a></span>
          ))} 打开面板再选择。
        </p>
      )}
      {missing.length > 0 && (
        <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs">
          你在 {missing.join('、')} 上还没有 Passkey，从那里打开时无法登录。需要的话，请从那个地址打开面板添加一个。
        </p>
      )}
      {mode !== 'password' && (
        <p className="text-xs text-muted-foreground">建议在两台设备上各加一个 Passkey，或者用能同步的密码管理器（iCloud 钥匙串、Google 密码管理器、1Password）。万一都丢了：超级管理员可以重置你的密码，超级管理员自己可以在 LuCI 里重置，登录方式都会恢复成「{loginModeNames.password}」。</p>
      )}
      {dialog}
    </div>
  )
}

// LoginModeStep: for the welcome wizard.
export function LoginModeStep() {
  const { data, reload } = useApi<PasskeyList>('/me/passkeys')
  return (
    <div className="grid gap-3">
      <p className="text-sm text-muted-foreground">面板开放到公网后，难免有人来试密码。这里随时可以改（右上角「账号安全」）。</p>
      <LoginMode pk={data} reload={reload} />
    </div>
  )
}
