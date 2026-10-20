import { useState } from 'react'
import { toast } from 'sonner'
import { Plus, Sparkles, Trash2 } from 'lucide-react'
import { get } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import type { ForwardGrants, PortGrant, PortsInfo, WanInfo } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'

export const emptyGrants: ForwardGrants = { ports: [], lan: [] }

export function grantLabel(g: PortGrant, wans?: WanInfo[] | null) {
  const range = g.from === g.to ? `${g.from}` : `${g.from}-${g.to}`
  // with a known single WAN the interface name adds nothing
  return g.wan && (!wans || wans.length > 1) ? `${g.wan}:${range}` : range
}

const overlap = (a: PortGrant, b: PortGrant) => (!a.wan || !b.wan || a.wan === b.wan) && a.from <= b.to && b.from <= a.to

// GrantsEditor: the super admin assigns WAN port ranges and LAN target ranges to an admin.
export function GrantsEditor({ userId, value, onChange }: { userId?: number; value: ForwardGrants; onChange: (g: ForwardGrants) => void }) {
  const { data } = useApi<PortsInfo>('/forwards/ports')
  const [size, setSize] = useState(10)
  const [lanText, setLanText] = useState(value.lan.join('\n'))
  const wans = data?.wans ?? []
  const multi = wans.length > 1
  const others = (data?.allocations ?? []).filter((a) => a.user_id !== userId)
  const setPort = (i: number, p: Partial<PortGrant>) => onChange({ ...value, ports: value.ports.map((x, j) => (j === i ? { ...x, ...p } : x)) })

  const suggest = async () => {
    try {
      const r = await get<PortsInfo>(`/forwards/ports?size=${size}&exclude_user=${userId ?? 0}&wan=`)
      if (!r.suggest) { toast.error(`找不到连续 ${size} 个空闲端口`); return }
      // also keep clear of ranges already entered in this form
      let s = r.suggest
      while (value.ports.some((p) => overlap(p, s)) && s.to + size <= 65535) s = { ...s, from: s.to + 1, to: s.to + size }
      onChange({ ...value, ports: [...value.ports, s] })
    } catch (e) { toast.error((e as Error).message) }
  }

  return (
    <div className="grid gap-4 rounded-xl border p-4">
      <div>
        <h3 className="text-sm font-semibold">端口转发授权</h3>
        <p className="text-xs text-muted-foreground">不分配端口段时，可使用任意空闲端口；分配后只能在这些端口段内建转发。同一端口段不能分给两个人。</p>
      </div>

      <div className="grid gap-2">
        {value.ports.map((p, i) => {
          const clash = others.filter((o) => overlap(o, p))
          const usedInside = (data?.used ?? []).filter((u) => !u.mine && overlap({ wan: u.wan, from: u.port, to: u.to || u.port }, p))
          const bad = !!(p.from || p.to) && (p.from < 1 || p.to > 65535 || p.from > p.to) // empty rows are dropped on save
          return (
            <div key={i} className="grid gap-1">
              <div className="flex flex-wrap items-center gap-2">
                {multi && (
                  <select className="h-8 rounded-lg border bg-transparent px-2 text-sm" value={p.wan} onChange={(e) => setPort(i, { wan: e.target.value })}>
                    <option value="">全部 WAN</option>
                    {wans.map((w) => <option key={w.interface} value={w.interface}>{w.interface}（{w.ipv4 || w.device}）</option>)}
                  </select>
                )}
                <Input inputMode="numeric" className="h-8 w-24 font-mono" value={p.from || ''} onChange={(e) => setPort(i, { from: Number(e.target.value.replace(/\D/g, '')) })} placeholder="8000" />
                <span className="text-muted-foreground">–</span>
                <Input inputMode="numeric" className="h-8 w-24 font-mono" value={p.to || ''} onChange={(e) => setPort(i, { to: Number(e.target.value.replace(/\D/g, '')) })} placeholder="8010" />
                <span className="text-xs text-muted-foreground tabular-nums">{bad || !p.from || !p.to ? '' : `${p.to - p.from + 1} 个端口`}</span>
                <Button variant="ghost" size="icon-sm" className="ml-auto" title="移除" onClick={() => onChange({ ...value, ports: value.ports.filter((_, j) => j !== i) })}><Trash2 /></Button>
              </div>
              {bad && <p className="text-xs text-destructive">端口范围 1-65535，起始不能大于结束</p>}
              {clash.map((c) => <p key={c.user_id + c.wan + c.from} className="text-xs text-destructive">与「{c.user}」的 {grantLabel(c, wans)} 重叠</p>)}
              {usedInside.length > 0 && <p className="text-xs text-[color-mix(in_oklch,var(--warning),black_35%)] dark:text-warning">其中 {usedInside.map((u) => u.port).join('、')} 已有其他人的转发（不会被删除，但该用户无法使用这些端口）</p>}
            </div>
          )
        })}
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => onChange({ ...value, ports: [...value.ports, { wan: '', from: 0, to: 0 }] })}><Plus /> 添加端口段</Button>
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
            或自动分配
            <Input inputMode="numeric" className="h-7 w-16 text-xs" value={size} onChange={(e) => setSize(Math.min(5000, Number(e.target.value.replace(/\D/g, '')) || 1))} />
            个连续空闲端口
            <Button variant="ghost" size="sm" onClick={suggest}><Sparkles /> 分配</Button>
          </span>
        </div>
      </div>

      <div className="grid gap-1.5">
        <div className="text-xs font-medium text-muted-foreground">允许转发到的内网设备 IP 段</div>
        <Textarea rows={2} className="font-mono text-xs" value={lanText} placeholder={'留空 = 任意内网设备；每行一个，例如\n192.168.1.159\n192.168.1.100-192.168.1.120\n192.168.1.64/28'}
          onChange={(e) => { setLanText(e.target.value); onChange({ ...value, lan: e.target.value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean) }) }} />
      </div>

      {others.length > 0 && (
        <div className="grid gap-1.5">
          <div className="text-xs font-medium text-muted-foreground">已分配给其他管理员</div>
          <div className="flex flex-wrap gap-1.5">
            {others.map((o) => (
              <span key={o.user_id + o.wan + o.from} className={cn('rounded-md bg-muted px-1.5 py-0.5 text-[11px]', value.ports.some((p) => overlap(o, p)) && 'bg-destructive/10 text-destructive')}>
                {o.user} <span className="font-mono">{grantLabel(o, wans)}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
