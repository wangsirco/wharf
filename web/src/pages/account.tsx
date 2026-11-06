import { useState } from 'react'
import { KeyRound, Plus, Trash2 } from 'lucide-react'
import { api } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { addPasskey, defaultPasskeyName, passkeySupported } from '@/lib/passkey'
import { LoginMode, panelURL, useReauth, type PasskeyList } from '@/components/login-mode'
import { ago, datetime } from '@/lib/format'
import { Empty } from '@/components/common'
import { toast } from 'sonner'
import { post } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { PageHeader } from '@/components/layout'
import { Field, Section } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

export default function Account() {
  const { refresh } = useAuth()
  const { data: pk, reload } = useApi<PasskeyList>('/me/passkeys')
  const [f, setF] = useState({ old: '', new: '', confirm: '' })
  const [busy, setBusy] = useState(false)
  const save = async () => {
    if (f.new !== f.confirm) return toast.error('两次输入的新密码不一致')
    setBusy(true)
    try { await post('/me/password', { old: f.old, new: f.new }); toast.success('密码已修改，请重新登录'); refresh() }
    catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <>
      <PageHeader title="账号安全" />
      <Section title="登录方式" desc="选择登录这个账号需要什么。" className="max-w-2xl">
        <div className="p-4"><LoginMode pk={pk} reload={reload} /></div>
      </Section>
      <Passkeys data={pk} reload={reload} />
      <Section title="修改密码" className="mt-4 max-w-lg">
        <div className="grid gap-4 p-4">
          <Field label="当前密码"><Input type="password" autoComplete="current-password" value={f.old} onChange={(e) => setF({ ...f, old: e.target.value })} /></Field>
          <Field label="新密码" hint="至少 8 位"><Input type="password" autoComplete="new-password" value={f.new} onChange={(e) => setF({ ...f, new: e.target.value })} /></Field>
          <Field label="确认新密码"><Input type="password" autoComplete="new-password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} /></Field>
          <div><Button disabled={busy || !f.old || f.new.length < 8} onClick={save}>修改密码</Button></div>
        </div>
      </Section>
    </>
  )
}

// Passkeys: sign in with Face ID / a fingerprint / a security key; the password stays.
function Passkeys({ data, reload }: { data?: PasskeyList | null; reload: () => void }) {
  const { ensure, dialog } = useReauth(data)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const url = (h: string) => panelURL(h, data?.port ?? '', '/account')
  const add = async () => {
    setBusy(true)
    try { await ensure(); await addPasskey(name || defaultPasskeyName()); setName(''); toast.success('Passkey 已添加，下次可以直接用它登录'); reload() }
    catch (e) { if ((e as Error).message !== '已取消') toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const remove = async (id: number) => {
    try { await ensure(); await api('DELETE', `/me/passkeys/${id}`); toast.success('已删除'); reload() } catch (e) { if ((e as Error).message !== '已取消') toast.error((e as Error).message) }
  }
  return (
    <Section title="Passkey" desc="用 Face ID、指纹或安全密钥确认身份。每台设备 / 每个密码管理器可以各添加一个。" className="mt-4 max-w-2xl">
      <div className="divide-y">
        {data?.passkeys.map((p) => (
          <div key={p.id} className="flex items-center gap-3 px-4 py-2.5">
            <KeyRound className="size-4 text-muted-foreground" />
            <div className="min-w-0 flex-1">
              <div className="text-sm">{p.name}</div>
              <div className="text-xs text-muted-foreground">用于 {p.rp_id} · 添加于 {datetime(p.created).slice(0, 10)} · {p.last_used ? `上次使用 ${ago(p.last_used)}` : '还没用过'}</div>
            </div>
            <Button variant="ghost" size="icon-sm" title="删除" onClick={() => remove(p.id)}><Trash2 /></Button>
          </div>
        ))}
        {data && !data.passkeys.length && <Empty>还没有 Passkey</Empty>}
      </div>
      <div className="grid gap-2 border-t p-4">
        {data && !data.usable ? (
          <p className="text-sm text-muted-foreground">
            Passkey 只能在面板的域名上添加和使用（浏览器不允许在 IP 地址上用）。请通过 {data.hosts.map((h, i) => (
              <span key={h}>{i > 0 && ' 或 '}<a className="text-primary underline" href={url(h)}>{h}</a></span>
            ))} 打开面板再添加。用本地域名时，设备需要先安装面板证书（登录页有下载和步骤）。
          </p>
        ) : !passkeySupported() ? (
          <p className="text-sm text-muted-foreground">这个浏览器不支持 Passkey，或者还不信任面板的证书（地址栏有警告时浏览器会禁用 Passkey）。</p>
        ) : (
          <div className="flex gap-2">
            <Input placeholder={`名称，例如：${defaultPasskeyName()}`} value={name} onChange={(e) => setName(e.target.value)} />
            <Button disabled={busy} onClick={add}><Plus /> 添加 Passkey</Button>
          </div>
        )}
      </div>
      {dialog}
    </Section>
  )
}
