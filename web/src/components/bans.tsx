import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Anchor, Ban, Plus, Trash2 } from 'lucide-react'
import { del, post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { datetime } from '@/lib/format'
import { Empty, Field, Pill, Section, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

interface BanItem {
  id: number; cidr: string; reason: string; source: string; expires_at: number; created_at: number
  origin: 'berth' | 'wharf'; sync: boolean; remote_id?: string; created_by?: string
}
interface Bans { items: BanItem[]; berth: boolean; default_sync: boolean }

// sourceLabel: "berth:mini:fail2ban" → "Berth · mini · fail2ban"
const sourceLabel = (b: BanItem) => b.origin === 'berth'
  ? 'Berth · ' + b.source.replace(/^berth:/, '').split(':').join(' · ')
  : 'Wharf · ' + (b.created_by || '')

// External bans: dropped at the WAN for the router and everything it forwards (the LAN is not affected).
export function ExternalBans() {
  const { data, reload } = useApi<Bans>('/bans', 30000)
  const [adding, setAdding] = useState(false)
  const { confirm, dialog } = useConfirm()
  const items = data?.items ?? []

  const revoke = async (b: BanItem) => {
    const extra = b.origin === 'berth' ? 'Berth 会收到通知，把这条的「已同步到 Wharf」取消。' : b.sync ? 'Berth 上同步的那一条也会撤回。' : ''
    if (!(await confirm(`撤销封禁 ${b.cidr}？`, extra, { ok: '撤销' }))) return
    try {
      const r = await del<{ warning?: string }>(`/bans/${b.id}`)
      if (r.warning) toast.warning(r.warning); else toast.success('已撤销')
      reload()
    } catch (e) { toast.error((e as Error).message) }
  }
  const sync = async (b: BanItem, on: boolean) => {
    try { await put(`/bans/${b.id}/sync`, { sync: on }); toast.success(on ? '已同步到 Berth：Berth 主机也会拒绝这个地址' : '已撤回 Berth 上的同步'); reload() }
    catch (e) { toast.error((e as Error).message) }
  }

  return (
    <Section title="外部封禁" desc="在 WAN 口丢弃这些地址发往路由器和端口转发的流量；局域网内的访问不受影响。来自 Berth 的封禁会标明来源。" className="xl:col-span-2"
      action={<Button size="sm" onClick={() => setAdding(true)}><Plus /> 封禁地址</Button>}>
      <div className="grid gap-1.5 p-4">
        {items.map((b) => (
          <div key={b.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border px-3 py-2 text-sm">
            <span className="font-mono">{b.cidr}</span>
            {b.origin === 'berth' ? <Pill tone="blue"><Anchor className="size-3" />{sourceLabel(b)}</Pill> : <Pill>{sourceLabel(b)}</Pill>}
            {b.reason && <span className="text-muted-foreground">{b.reason}</span>}
            <span className="text-xs text-muted-foreground">WAN 入站与转发 · {b.expires_at ? `${datetime(b.expires_at)} 到期` : '一直有效'}</span>
            <span className="ml-auto flex items-center gap-2">
              {b.origin === 'wharf' && data?.berth && (
                <label className="flex items-center gap-1.5 text-xs text-muted-foreground" title="同步到 Berth：Berth 主机也会拒绝这个地址">
                  <Switch size="sm" checked={b.sync} onCheckedChange={(c) => sync(b, !!c)} />同步到 Berth
                </label>
              )}
              <Button variant="ghost" size="icon-sm" title="撤销" onClick={() => revoke(b)}><Trash2 /></Button>
            </span>
          </div>
        ))}
        {!items.length && <Empty>{data ? '没有封禁的地址' : '加载中…'}</Empty>}
      </div>
      <BanDialog open={adding} onOpenChange={setAdding} onDone={reload} berth={!!data?.berth} defaultSync={!!data?.default_sync} />
      {dialog}
    </Section>
  )
}

// BanDialog: ban one address (also used from a forward's connection list).
export function BanDialog({ open, onOpenChange, ip = '', reason: reason0 = '', onDone, berth, defaultSync }: {
  open: boolean; onOpenChange: (o: boolean) => void; ip?: string; reason?: string; onDone?: () => void; berth?: boolean; defaultSync?: boolean
}) {
  const [cidr, setCidr] = useState(ip)
  const [reason, setReason] = useState(reason0)
  const [days, setDays] = useState(7)
  const [sync, setSync] = useState(!!defaultSync)
  const [busy, setBusy] = useState(false)
  // opened from elsewhere: look up whether Berth is there
  const { data } = useApi<Bans>(open && berth === undefined ? '/bans' : null)
  const canSync = berth ?? !!data?.berth
  useEffect(() => { if (open) { setCidr(ip); setReason(reason0); setSync(defaultSync ?? !!data?.default_sync) } }, [open, ip]) // eslint-disable-line react-hooks/exhaustive-deps

  const submit = async () => {
    setBusy(true)
    try {
      const r = await post<{ warning?: string }>('/bans', { cidr: cidr.trim(), reason: reason.trim(), days, sync: canSync && sync })
      if (r.warning) toast.warning(r.warning); else toast.success(`已封禁 ${cidr.trim()}`)
      onOpenChange(false); onDone?.()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Ban className="size-4" />封禁地址</DialogTitle>
          <DialogDescription>在 WAN 口丢弃它发来的所有连接（到路由器和到端口转发）。内网地址、路由器自己的公网地址、正在使用面板的人不能被封禁；一次最多 /16。</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <Field label="IP 或网段"><Input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="203.0.113.7 或 203.0.113.0/24" className="font-mono" /></Field>
          <Field label="原因（可选）"><Input value={reason} maxLength={120} onChange={(e) => setReason(e.target.value)} placeholder="SSH 爆破" /></Field>
          <Field label="封禁多久">
            <select className="h-9 w-40 rounded-md border bg-background px-2 text-sm" value={days} onChange={(e) => setDays(Number(e.target.value))}>
              <option value={1}>1 天</option><option value={7}>7 天</option><option value={30}>30 天</option><option value={365}>1 年</option><option value={0}>一直有效</option>
            </select>
          </Field>
          {canSync && (
            <label className="flex items-start gap-2 text-sm">
              <Checkbox className="mt-0.5" checked={sync} onCheckedChange={(c) => setSync(!!c)} />
              <span>同步到 Berth<span className="block text-xs text-muted-foreground">Berth 主机也会拒绝这个地址；以后可以单条撤回</span></span>
            </label>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>取消</Button>
          <Button disabled={busy || !cidr.trim()} onClick={submit}>封禁</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
