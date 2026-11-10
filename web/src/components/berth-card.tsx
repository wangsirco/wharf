import { useState } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, Anchor, KeyRound, Link2Off, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { datetime } from '@/lib/format'
import { berthStatus } from '@/lib/berth'
import { Dot, Field, Pill, Section } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import type { User } from '@/lib/types'

interface Scope { key: string; label: string; desc: string }
interface Target { ip: string; mac?: string; name?: string }
interface Link {
  id: number; name: string; url: string; cert_fp: string; wharf_url: string; scopes: string[]; targets: Target[]
  expires_at: number; created_at: number; last_seen_at: number; status: 'active' | 'expired' | 'invalid'; last_error: string
}
interface UserMap { berth_user: string; wharf_user_id: number; wharf_username: string; wharf_name: string; super: boolean }
interface BerthInfo { scopes: Scope[]; link: Link | null; users: UserMap[]; self_fp: string; bans?: number; forwards?: number; sni?: { domains: string[] } | null }

const fpText = (s: string) => s.match(/.{1,4}/g)?.join(' ') ?? s

// Settings → 集成 → Berth 泊位
export function BerthCard() {
  const { data, reload } = useApi<BerthInfo>('/berth')
  const { data: users } = useApi<User[]>('/users')
  const [scopes, setScopes] = useState<string[] | null>(null)
  const [unpair, setUnpair] = useState(false)
  const [keep, setKeep] = useState(true)
  const [mapUser, setMapUser] = useState({ berth: '', wharf: 0 })
  const [pw, setPw] = useState<{ open: boolean; value: string }>({ open: false, value: '' })
  const [busy, setBusy] = useState(false)
  if (!data) return <Section title="Berth 泊位" className="xl:col-span-2"><p className="text-sm text-muted-foreground">加载中…</p></Section>
  const l = data.link
  const cur = scopes ?? l?.scopes ?? []

  const run = async (f: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    try { await f(); toast.success(ok); reload(); berthStatus(true) } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const saveMap = async (password = '') => {
    try {
      await put('/berth/users', { berth_user: mapUser.berth.trim(), wharf_user_id: mapUser.wharf, password })
      setMapUser({ berth: '', wharf: 0 }); setPw({ open: false, value: '' }); reload(); toast.success('已保存用户对应')
    } catch (e) {
      const msg = (e as Error).message
      if (msg.includes('密码') && !password) setPw({ open: true, value: '' })
      else toast.error(msg)
    }
  }

  if (!l) {
    return (
      <Section title="Berth 泊位" desc="Berth 是同一系列的服务器管理面板：Wharf 管路由器，Berth 管服务器。" className="xl:col-span-2">
        <div className="grid gap-3 p-4 text-sm">
          <div className="flex gap-3 rounded-xl border bg-muted/30 p-3">
            <Anchor className="mt-0.5 size-5 shrink-0 text-primary" />
            <div className="grid gap-1">
              <div className="font-medium">尚未配对</div>
              <p className="text-muted-foreground">在 Berth 的「设置 → 集成 → Wharf」里填上 Wharf 的地址，它会把你带回这里确认。配对后：建站时自动映射端口或登记 443 分流、DDNS 由一方维护、封禁可以同步、告警只收一份、两边互相跳转不用再登录。</p>
            </div>
          </div>
          {data.self_fp && <p className="text-xs text-muted-foreground">Berth 会要求核对 Wharf 的证书指纹（本地 CA）：<span className="font-mono">{fpText(data.self_fp)}</span></p>}
        </div>
      </Section>
    )
  }

  const dead = l.status !== 'active'
  return (
    <Section title="Berth 泊位" desc="只有超级管理员能看到这里；普通管理员只看到 Berth 徽标。" className="xl:col-span-2"
      action={<Button variant="ghost" size="sm" onClick={reload}><RefreshCw /> 刷新</Button>}>
      <div className="grid gap-4 p-4">
        {dead && (
          <div className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />
            <span>对接已失效（{l.status === 'expired' ? '令牌已过期' : 'Berth 不再接受 Wharf 的令牌'}）。已建好的映射都保留；请解除配对后在 Berth 里重新发起。</span>
          </div>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <Info k="Berth"><a className="text-primary hover:underline" href={l.url} target="_blank" rel="noreferrer">{l.name} · {l.url}</a></Info>
          <Info k="状态"><Dot tone={dead ? 'bad' : l.last_error ? 'warn' : 'ok'} /> {dead ? '对接已失效' : '正常'}{l.last_error && <span className="block text-xs text-muted-foreground">{l.last_error}</span>}</Info>
          <Info k="证书指纹"><span className="break-all font-mono text-xs">{fpText(l.cert_fp)}</span></Info>
          <Info k="配对时间">{datetime(l.created_at)}{l.expires_at ? ` · ${datetime(l.expires_at)} 到期` : ' · 永久'}</Info>
          <Info k="最后通信">{l.last_seen_at ? datetime(l.last_seen_at) : '—'}</Info>
          <Info k="由 Berth 管理">{data.forwards ?? 0} 条端口映射 · {data.sni?.domains.length ?? 0} 个 443 域名 · {data.bans ?? 0} 条封禁</Info>
          <Info k="Berth 主机">{l.targets.map((t) => <Pill key={t.ip} tone="blue">{t.name || t.ip} {t.ip}</Pill>)}</Info>
        </div>

        <div className="grid gap-2">
          <div className="text-sm font-medium">权限范围 <span className="text-xs font-normal text-muted-foreground">（只能收窄；要增加请重新配对）</span></div>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {data.scopes.filter((s) => l.scopes.includes(s.key)).map((s) => (
              <label key={s.key} className="flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2">
                <Checkbox className="mt-0.5" checked={cur.includes(s.key)} onCheckedChange={(c) => setScopes(c ? [...cur, s.key] : cur.filter((x) => x !== s.key))} />
                <span><span className="block text-sm">{s.label}</span><span className="text-xs text-muted-foreground">{s.desc}</span></span>
              </label>
            ))}
          </div>
          {scopes && scopes.length !== l.scopes.length && (
            <div className="flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setScopes(null)}>还原</Button>
              <Button size="sm" disabled={busy} onClick={() => run(() => put('/berth', { scopes, targets: l.targets }), '已收窄权限').then(() => setScopes(null))}>保存权限</Button>
            </div>
          )}
        </div>

        <div className="grid gap-2">
          <div className="text-sm font-medium">用户对应 <span className="text-xs font-normal text-muted-foreground">（从 Berth 免登录跳过来时，以哪个 Wharf 账号登录；没有对应的不能跳转）</span></div>
          {data.users.length > 0 && (
            <div className="grid gap-1">
              {data.users.map((m) => (
                <div key={m.berth_user} className="flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm">
                  <span className="font-mono">{m.berth_user}</span><span className="text-muted-foreground">→</span>
                  <span>{m.wharf_name || '（已删除的用户）'}</span>{m.super && <Pill tone="amber">超级管理员</Pill>}
                  <Button variant="ghost" size="icon-sm" className="ml-auto" onClick={() => run(() => put('/berth/users', { berth_user: m.berth_user, wharf_user_id: 0 }), '已删除对应')}><Trash2 /></Button>
                </div>
              ))}
            </div>
          )}
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Berth 用户名" className="w-40"><Input value={mapUser.berth} onChange={(e) => setMapUser({ ...mapUser, berth: e.target.value })} placeholder="wang" /></Field>
            <Field label="对应的 Wharf 账号" className="w-56">
              <select className="h-9 rounded-md border bg-background px-2 text-sm" value={mapUser.wharf} onChange={(e) => setMapUser({ ...mapUser, wharf: Number(e.target.value) })}>
                <option value={0}>选择账号</option>
                {users?.filter((u) => !u.disabled).map((u) => <option key={u.id} value={u.id}>{u.display_name}（{u.username}{u.role === 'super' ? ' · 超级管理员' : ''}）</option>)}
              </select>
            </Field>
            <Button size="sm" disabled={!mapUser.berth.trim() || !mapUser.wharf} onClick={() => saveMap()}><Plus /> 添加</Button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2 border-t pt-3">
          <Button variant="outline" size="sm" disabled={busy || dead} onClick={() => run(() => post('/berth/rotate'), '已轮换两边的对接令牌')}><KeyRound /> 轮换令牌</Button>
          <Button variant="outline" size="sm" className="text-destructive" onClick={() => { setKeep(true); setUnpair(true) }}><Link2Off /> 解除配对</Button>
        </div>
      </div>

      <Dialog open={unpair} onOpenChange={setUnpair}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>解除与 Berth「{l.name}」的配对？</DialogTitle>
            <DialogDescription>两边的令牌立即失效；Berth 登记的 443 域名、同步来的封禁、DDNS 分工和用户对应都会清除，主通知方改回 Wharf。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2 text-sm">
            <div className="font-medium">由 Berth 创建的 {data.forwards ?? 0} 条端口映射：</div>
            <label className="flex items-center gap-2"><input type="radio" checked={keep} onChange={() => setKeep(true)} /> 保留，转为普通端口转发（归超级管理员）</label>
            <label className="flex items-center gap-2"><input type="radio" checked={!keep} onChange={() => setKeep(false)} /> 一并删除</label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUnpair(false)}>取消</Button>
            <Button variant="destructive" disabled={busy} onClick={() => run(async () => {
              const r = await post<{ message: string; notified: boolean }>('/berth/unpair', { keep })
              setUnpair(false)
              if (!r.notified) toast.warning('Berth 没有响应：Wharf 这边已解除，请在 Berth 里也解除一次')
              return r
            }, '已解除配对')}>解除配对</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={pw.open} onOpenChange={(o) => setPw({ ...pw, open: o })}>
        <DialogContent className="sm:max-w-sm">
          <DialogTitle>对应到超级管理员</DialogTitle>
          <form className="grid gap-3" onSubmit={(e) => { e.preventDefault(); saveMap(pw.value) }}>
            <p className="text-sm text-muted-foreground">Berth 用户 {mapUser.berth} 跳过来后将拥有超级管理员的全部权限。请输入你的密码确认。</p>
            <Input type="password" autoFocus autoComplete="current-password" value={pw.value} onChange={(e) => setPw({ ...pw, value: e.target.value })} />
            <Button type="submit" disabled={!pw.value}>确认</Button>
          </form>
        </DialogContent>
      </Dialog>
    </Section>
  )
}

function Info({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-0.5 rounded-lg bg-muted/30 px-3 py-2 text-sm">
      <span className="text-xs text-muted-foreground">{k}</span>
      <span className="flex flex-wrap items-center gap-1">{children}</span>
    </div>
  )
}
