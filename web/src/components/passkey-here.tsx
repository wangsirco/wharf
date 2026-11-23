import { useState } from 'react'
import { toast } from 'sonner'
import { KeyRound, X } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { addPasskey, defaultPasskeyName, passkeySupported } from '@/lib/passkey'
import { useReauth, type PasskeyList } from '@/components/login-mode'
import { Button } from '@/components/ui/button'

// PasskeyHereBanner: signed in on a name from outside (public / tunnel) where this account
// has no passkey yet. Passkeys follow names; add one here now instead of finding out later.
export function PasskeyHereBanner() {
  const { data, reload } = useApi<PasskeyList>('/me/passkeys')
  const { ensure, dialog } = useReauth(data)
  const [gone, setGone] = useState(() => sessionStorage.getItem('owp-pk-here') === '1')
  const [busy, setBusy] = useState(false)
  if (!data || gone || !data.usable || !passkeySupported()) return null
  const lan = data.hosts[0]
  if (data.here === lan || data.passkeys.some((p) => p.rp_id === data.here)) return null
  const elsewhere = [...new Set(data.passkeys.map((p) => p.rp_id))]
  const add = async () => {
    setBusy(true)
    try { await ensure(); await addPasskey(defaultPasskeyName()); toast.success(`已在 ${data.here} 上添加 Passkey`); reload() }
    catch (e) { if ((e as Error).message !== '已取消') toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-destructive/30 bg-destructive/8 px-4 py-2 text-sm">
      <KeyRound className="size-4 shrink-0 text-destructive" />
      <span className="min-w-0 flex-1">
        <b className="font-mono">{data.here}</b> 上还没有你的 Passkey。{elsewhere.length ? `你的 Passkey 在 ${elsewhere.join('、')} 上，Passkey 跟着名字走。` : '这个地址能从外面打开，建议加一个 Passkey 保护账号。'}
      </span>
      <Button size="xs" disabled={busy} onClick={add}>在这里添加 Passkey</Button>
      <Button size="xs" variant="ghost" onClick={() => { sessionStorage.setItem('owp-pk-here', '1'); setGone(true) }}><X /></Button>
      {dialog}
    </div>
  )
}
