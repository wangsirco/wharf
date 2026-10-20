import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, ArrowDown, ArrowUp, Ban, Bell, ClipboardCheck, Globe2, House, Info, LogOut, MonitorSmartphone, ShieldAlert, Sparkles } from 'lucide-react'
import { get } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useLive } from '@/lib/live'
import type { Device, Overview, OwpEvent, SystemInfo } from '@/lib/types'
import { ago, bitrate, bytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import { AreaChart } from '@/components/chart'
import { LevelDonut } from '@/components/charts'
import { DeviceIcon } from '@/components/device-icon'
import { Empty } from '@/components/common'

export function Kpi({ icon: Icon, label, value, sub, tone, onClick, big }: {
  icon: typeof ArrowUp; label: string; value: ReactNode; sub?: ReactNode; tone?: 'red' | 'amber' | 'green'; onClick?: () => void; big?: boolean
}) {
  const t = tone === 'red' ? 'text-destructive' : tone === 'amber' ? 'text-[color-mix(in_oklch,var(--warning),black_30%)] dark:text-warning' : tone === 'green' ? 'text-success' : ''
  return (
    <div onClick={onClick} className={cn('min-w-0 rounded-xl border bg-card p-3 sm:p-4', onClick && 'cursor-pointer transition-colors hover:bg-muted/50')}>
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground"><Icon className="size-3.5" />{label}</div>
      <div className={cn('mt-1.5 font-semibold tracking-tight tabular-nums', big ? 'text-2xl sm:text-4xl' : 'text-xl sm:text-2xl', t)}>{value}</div>
      {sub && <div className="mt-0.5 truncate text-xs text-muted-foreground">{sub}</div>}
    </div>
  )
}

// WAN live rate history from /system counters.
export function useWan(poll = 2000) {
  const { data: sys } = useApi<SystemInfo>('/system', poll)
  const prev = useRef<SystemInfo | null>(null)
  const [hist, setHist] = useState<{ t: number[]; rx: number[]; tx: number[] }>({ t: [], rx: [], tx: [] })
  const [rate, setRate] = useState({ rx: 0, tx: 0 })
  useEffect(() => {
    if (!sys) return
    const p = prev.current
    prev.current = sys
    if (!p || sys.time <= p.time) return
    const a = sys.ifaces.find((i) => i.name === sys.wan_ifname), b = p.ifaces.find((i) => i.name === sys.wan_ifname)
    if (!a || !b) return
    const dt = sys.time - p.time
    const r = { rx: Math.max(0, a.rx_bytes - b.rx_bytes) / dt, tx: Math.max(0, a.tx_bytes - b.tx_bytes) / dt }
    setRate(r)
    setHist((h) => ({ t: [...h.t, sys.time].slice(-150), rx: [...h.rx, r.rx].slice(-150), tx: [...h.tx, r.tx].slice(-150) }))
  }, [sys])
  return { sys, rate, hist }
}

export function WanChart({ hist, height = 200 }: { hist: { t: number[]; rx: number[]; tx: number[] }; height?: number }) {
  return <AreaChart height={height} format={bitrate} times={hist.t}
    series={[{ label: '下行', color: 'var(--chart-1)', values: hist.rx }, { label: '上行', color: 'var(--chart-2)', values: hist.tx }]} />
}

// Devices currently using the network, busiest first.
export function LiveDevices({ limit = 8, big }: { limit?: number; big?: boolean }) {
  const live = useLive(3000)
  const { data: devices } = useApi<Device[]>('/devices', 30000)
  const navigate = useNavigate()
  const rows = (devices ?? []).map((d) => ({ d, l: live[d.mac] })).filter((x) => x.l && x.l.up + x.l.down > 256)
    .sort((a, b) => b.l!.up + b.l!.down - (a.l!.up + a.l!.down)).slice(0, limit)
  const max = Math.max(1, ...rows.map((x) => x.l!.up + x.l!.down))
  if (!rows.length) return <Empty>现在没有设备在大量用网</Empty>
  return (
    <div className="divide-y">
      {rows.map(({ d, l }) => (
        <button key={d.mac} type="button" onClick={() => navigate(`/devices/${d.mac}`)} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-muted/50">
          <DeviceIcon type={d.type} online={d.online} />
          <div className="min-w-0 flex-1">
            <div className={cn('truncate font-medium', big && 'text-base')}>{d.name || d.ip}</div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
              <div className="flex h-full" style={{ width: `${((l!.up + l!.down) / max) * 100}%` }}>
                <div className="h-full bg-chart-1" style={{ flex: l!.down }} /><div className="h-full bg-chart-2" style={{ flex: l!.up }} />
              </div>
            </div>
          </div>
          <div className="w-28 text-right text-xs tabular-nums">
            <div><ArrowDown className="mr-0.5 inline size-3 text-chart-1" />{bitrate(l!.down)}</div>
            <div className="text-muted-foreground"><ArrowUp className="mr-0.5 inline size-3 text-chart-2" />{bitrate(l!.up)}</div>
          </div>
        </button>
      ))}
    </div>
  )
}

const EVENT_ICON: Record<string, typeof Bell> = { left: LogOut, back: House,
  new_device: MonitorSmartphone, control: Ban, schedule: Ban, forward: Globe2, access: ShieldAlert, approval: ClipboardCheck, rules: Sparkles,
}

export function EventsFeed({ limit = 15, poll = 30000 }: { limit?: number; poll?: number }) {
  const { data } = useApi<OwpEvent[]>(`/events?limit=${limit}`, poll)
  const navigate = useNavigate()
  if (!data?.length) return <Empty>最近 7 天没有事件</Empty>
  return (
    <div className="divide-y">
      {data.map((e, i) => {
        const Icon = EVENT_ICON[e.kind] ?? Info
        return (
          <button key={i} type="button" disabled={!e.link} onClick={() => e.link && navigate(e.link)} className="flex w-full items-start gap-3 px-4 py-2.5 text-left enabled:hover:bg-muted/50">
            <span className={cn('mt-0.5 grid size-7 shrink-0 place-items-center rounded-full',
              e.level === 'alert' ? 'bg-destructive/12 text-destructive' : e.level === 'warn' ? 'bg-warning/20 text-[color-mix(in_oklch,var(--warning),black_35%)] dark:text-warning'
                : e.kind === 'back' ? 'bg-success/12 text-success' : 'bg-muted text-muted-foreground')}>
              {e.level === 'alert' ? <AlertTriangle className="size-3.5" /> : <Icon className="size-3.5" />}
            </span>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm">{e.title}</div>
              {e.detail && <div className="truncate text-xs text-muted-foreground">{e.detail}</div>}
            </div>
            <span className="shrink-0 text-xs text-muted-foreground">{ago(e.ts)}</span>
          </button>
        )
      })}
    </div>
  )
}

export function useOverview(poll = 30000) {
  return useApi<Overview>('/overview', poll)
}

export function ServicesToday({ data, size }: { data: Overview | null; size?: number }) {
  return <LevelDonut size={size} services={data?.services_today} categories={data?.categories_today} format={bytes} centerLabel="今日" />
}

export async function prefetchDevices() { await get('/devices') }
