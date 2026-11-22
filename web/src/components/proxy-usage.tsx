import { useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, CalendarRange, Flame } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { bytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import { Empty, HalfPanel, Pill } from '@/components/common'
import { AreaChart } from '@/components/chart'
import { Input } from '@/components/ui/input'

// Usage of a proxy node, a proxy user, or all nodes, for any period.

export type UsageTarget = { kind: 'node' | 'user' | 'all'; id?: number; name: string }

interface Point { t: number; up: number; down: number }
interface Part { id: number; name: string; up: number; down: number; gone?: boolean; others?: boolean }
interface Usage {
  from: number; to: number; bucket: number; total: Point; series: Point[]; by: Part[]; by_kind: 'user' | 'node'
  peak?: Point; created?: number; kept: number; clipped?: boolean
}

const day0 = (d = new Date()) => new Date(d.getFullYear(), d.getMonth(), d.getDate())
const sec = (d: Date) => Math.floor(d.getTime() / 1000)

type Preset = { k: string; label: string; range: () => [number, number?] }
const PRESETS: Preset[] = [
  { k: '1h', label: '最近 1 小时', range: () => [sec(new Date()) - 3600] },
  { k: '3h', label: '3 小时', range: () => [sec(new Date()) - 3 * 3600] },
  { k: '12h', label: '12 小时', range: () => [sec(new Date()) - 12 * 3600] },
  { k: 'today', label: '今天', range: () => [sec(day0())] },
  { k: 'yesterday', label: '昨天', range: () => { const t = day0(); return [sec(new Date(t.getTime() - 86400000)), sec(t)] } },
  { k: '7d', label: '7 天', range: () => [sec(day0()) - 6 * 86400] },
  { k: '30d', label: '30 天', range: () => [sec(day0()) - 29 * 86400] },
  { k: 'month', label: '本月', range: () => { const n = new Date(); return [sec(new Date(n.getFullYear(), n.getMonth(), 1))] } },
  { k: 'lastmonth', label: '上月', range: () => { const n = new Date(); return [sec(new Date(n.getFullYear(), n.getMonth() - 1, 1)), sec(new Date(n.getFullYear(), n.getMonth(), 1))] } },
  { k: 'all', label: '建立以来', range: () => [0] },
]

const dateInput = (ts: number) => { const d = new Date(ts * 1000); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}` }
const fromInput = (s: string) => (s ? sec(new Date(s + 'T00:00:00')) : 0)

function when(t: number, bucket: number) {
  const d = new Date(t * 1000)
  const md = `${d.getMonth() + 1}月${d.getDate()}日`
  if (bucket >= 86400) return md
  const hm = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  return bucket === 300 ? `${md} ${hm}` : `${md} ${hm} 起的一小时`
}

const span = (from: number, to: number) => {
  const s = to - from
  if (s < 2 * 3600) return `${Math.round(s / 60)} 分钟`
  if (s < 2 * 86400) return `${Math.round(s / 3600)} 小时`
  return `${Math.round(s / 86400)} 天`
}

export function UsagePanel({ target, onClose, onOpen }: { target: UsageTarget | null; onClose: () => void; onOpen?: (t: UsageTarget) => void }) {
  const [preset, setPreset] = useState('7d')
  const [custom, setCustom] = useState<{ from: string; to: string }>({ from: '', to: '' })
  const [from, to] = useMemo(() => {
    if (preset === 'custom') {
      const f = fromInput(custom.from), t = fromInput(custom.to)
      return [f, t ? t + 86400 : 0] // the end date is included
    }
    const [f, t] = PRESETS.find((p) => p.k === preset)!.range()
    return [f, t ?? 0]
  }, [preset, custom])
  const q = target && (preset !== 'custom' || from) ? `/proxy/usage?${target.kind === 'all' ? '' : `${target.kind}=${target.id}&`}from=${from}${to ? `&to=${to}` : ''}` : null
  const { data: u, error, loading } = useApi<Usage>(q, preset === '1h' || preset === '3h' ? 60000 : 0)

  const total = u ? u.total.up + u.total.down : 0
  const days = u ? (u.to - u.from) / 86400 : 0
  const maxPart = Math.max(1, ...(u?.by ?? []).map((p) => p.up + p.down))
  const who = target?.kind === 'node' ? '这个节点' : target?.kind === 'user' ? '这个用户' : '所有节点'

  return (
    <HalfPanel open={!!target} onOpenChange={(o) => { if (!o) onClose() }}
      title={target ? `${target.name} · 用量` : ''}
      desc={u?.created ? `${new Date(u.created * 1000).toLocaleDateString()} 建立` : target?.kind === 'all' ? '你能看到的全部节点合计' : ''}>
      {target && (
        <div className="grid gap-5">
          {/* period */}
          <div className="grid gap-2">
            <div className="flex flex-wrap gap-1.5">
              {PRESETS.map((p) => (
                <button key={p.k} type="button" onClick={() => setPreset(p.k)}
                  className={cn('rounded-full border px-3 py-1 text-xs', preset === p.k ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted')}>{p.label}</button>
              ))}
              <button type="button" onClick={() => { setPreset('custom'); if (!custom.from && u) setCustom({ from: dateInput(u.from), to: dateInput(u.to) }) }}
                className={cn('flex items-center gap-1 rounded-full border px-3 py-1 text-xs', preset === 'custom' ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted')}>
                <CalendarRange className="size-3" /> 选日期
              </button>
            </div>
            {preset === 'custom' && (
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <Input type="date" className="w-40" value={custom.from} onChange={(e) => setCustom({ ...custom, from: e.target.value })} />
                <span className="text-muted-foreground">到</span>
                <Input type="date" className="w-40" value={custom.to} onChange={(e) => setCustom({ ...custom, to: e.target.value })} />
                <span className="text-xs text-muted-foreground">（含结束那天）</span>
              </div>
            )}
          </div>

          {error && <div className="text-sm text-destructive">{error}</div>}
          {u && (
            <>
              {/* totals */}
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-xl border p-4 sm:col-span-1">
                  <div className="text-xs text-muted-foreground">{span(u.from, u.to)}共用了</div>
                  <div className="mt-1 text-2xl font-semibold tabular-nums">{bytes(total)}</div>
                  <div className="mt-1 text-xs text-muted-foreground">{new Date(u.from * 1000).toLocaleString([], { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })} 至 {u.to >= Date.now() / 1000 - 60 ? '现在' : new Date(u.to * 1000).toLocaleString([], { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</div>
                </div>
                <div className="grid grid-cols-2 gap-3 sm:col-span-2">
                  <div className="rounded-xl border p-4"><div className="flex items-center gap-1 text-xs text-muted-foreground"><ArrowDown className="size-3" />下行（下载）</div><div className="mt-1 text-lg font-semibold tabular-nums">{bytes(u.total.down)}</div></div>
                  <div className="rounded-xl border p-4"><div className="flex items-center gap-1 text-xs text-muted-foreground"><ArrowUp className="size-3" />上行（上传）</div><div className="mt-1 text-lg font-semibold tabular-nums">{bytes(u.total.up)}</div></div>
                </div>
              </div>
              {total > 0 && (
                <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm text-muted-foreground">
                  {days >= 2 && <span>平均每天 <b className="text-foreground">{bytes(total / days)}</b></span>}
                  {u.peak && <span className="flex items-center gap-1"><Flame className="size-3.5 text-warning" />最多的是 {when(u.peak.t, u.bucket)}：<b className="text-foreground">{bytes(u.peak.up + u.peak.down)}</b></span>}
                </div>
              )}
              {u.clipped && <p className="text-xs text-muted-foreground">流量按小时只保留 400 天，更早的部分已经不在了。</p>}

              {/* chart */}
              <div className="rounded-xl border p-4">
                <div className="mb-2 text-xs text-muted-foreground">每{u.bucket === 300 ? ' 5 分钟' : u.bucket === 3600 ? '小时' : '天'}用量</div>
                {total > 0 ? (
                  <AreaChart height={160} times={u.series.map((p) => p.t)} format={(v) => bytes(v)} timeLabel={(t) => when(t, u.bucket)}
                    series={[{ label: '下行', color: 'var(--chart-1)', values: u.series.map((p) => p.down) }, { label: '上行', color: 'var(--chart-2)', values: u.series.map((p) => p.up) }]} />
                ) : <Empty>{who}在这段时间没有用流量</Empty>}
              </div>

              {/* breakdown */}
              {u.by.length > 0 && (
                <div className="grid gap-2">
                  <div className="text-sm font-medium">{u.by_kind === 'user' ? '谁用的' : '用在哪些节点'}</div>
                  {u.by.map((p) => {
                    const t = p.up + p.down
                    const click = !p.gone && !p.others && onOpen
                    return (
                      <button key={`${p.id}-${p.others}`} type="button" disabled={!click}
                        onClick={() => click && onOpen({ kind: u.by_kind, id: p.id, name: p.name })}
                        className={cn('grid grid-cols-[8rem_1fr_6rem] items-center gap-3 rounded-lg px-2 py-1.5 text-left text-sm', click && 'hover:bg-muted')}>
                        <span className={cn('truncate', (p.gone || p.others) && 'text-muted-foreground')}>{p.name}</span>
                        <div className="h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary/70" style={{ width: `${(t / maxPart) * 100}%` }} /></div>
                        <span className="text-right tabular-nums">{bytes(t)} <span className="text-xs text-muted-foreground">{total ? `${Math.round((t / total) * 100)}%` : ''}</span></span>
                      </button>
                    )
                  })}
                  {onOpen && u.by.some((p) => !p.gone && !p.others) && <p className="text-xs text-muted-foreground">点一行，看{u.by_kind === 'user' ? '这个用户' : '这个节点'}自己的明细。</p>}
                </div>
              )}
            </>
          )}
          {!u && loading && <div className="text-sm text-muted-foreground">正在统计…</div>}
          {preset === 'custom' && !from && <Pill>先选开始日期</Pill>}
        </div>
      )}
    </HalfPanel>
  )
}
