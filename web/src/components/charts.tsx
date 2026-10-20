import { useMemo, useState } from 'react'
import { cn } from '@/lib/utils'
import { bytes } from '@/lib/format'
import type { Agg } from '@/lib/types'

export const PALETTE = ['var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)',
  'oklch(0.7 0.12 200)', 'oklch(0.72 0.13 340)', 'oklch(0.68 0.1 120)', 'oklch(0.6 0.08 40)', 'oklch(0.75 0.06 260)']

export interface Slice { name: string; value: number; sub?: string; guess?: boolean; uncertain?: boolean }

// Donut: proportions with a legend; the hovered/selected slice is highlighted.
export function Donut({ data, format, onSelect, selected, size = 180, centerLabel }: {
  data: Slice[]; format: (v: number) => string; onSelect?: (name: string | null) => void; selected?: string | null; size?: number; centerLabel?: string
}) {
  const [hover, setHover] = useState<number | null>(null)
  const total = data.reduce((s, d) => s + d.value, 0)
  const top = data.slice(0, 9)
  const rest = data.slice(9).reduce((s, d) => s + d.value, 0)
  // fold the tail into an existing "其他" slice instead of showing two
  const slices: Slice[] = rest > 0
    ? (top.some((d) => d.name === '其他') ? top.map((d) => (d.name === '其他' ? { ...d, value: d.value + rest } : d)) : [...top, { name: '其他', value: rest }])
    : top
  const r = 70, R = 90, c = 100
  let acc = 0
  const arcs = slices.map((d, i) => {
    const a0 = (acc / (total || 1)) * Math.PI * 2
    acc += d.value
    const a1 = (acc / (total || 1)) * Math.PI * 2
    const large = a1 - a0 > Math.PI ? 1 : 0
    const p = (rad: number, rr: number) => `${c + rr * Math.sin(rad)},${c - rr * Math.cos(rad)}`
    const full = a1 - a0 >= Math.PI * 2 - 1e-6
    const path = full
      ? `M${c},${c - R} A${R},${R} 0 1 1 ${c - 0.01},${c - R} L${c - 0.01},${c - r} A${r},${r} 0 1 0 ${c},${c - r} Z`
      : `M${p(a0, R)} A${R},${R} 0 ${large} 1 ${p(a1, R)} L${p(a1, r)} A${r},${r} 0 ${large} 0 ${p(a0, r)} Z`
    return { d, i, path }
  })
  const focus = hover !== null ? slices[hover] : slices.find((s) => s.name === selected) ?? null
  return (
    <div className="flex flex-wrap items-center justify-center gap-6">
      <svg viewBox="0 0 200 200" width={size} height={size} className="shrink-0">
        {total === 0 && <circle cx={c} cy={c} r={(r + R) / 2} fill="none" strokeWidth={R - r} className="stroke-muted" />}
        {arcs.map(({ d, i, path }) => (
          <path key={d.name} d={path} fill={(d as Slice).uncertain ? 'var(--muted-foreground)' : PALETTE[i % PALETTE.length]}
            opacity={focus && focus.name !== d.name ? 0.35 : 1} className="cursor-pointer transition-opacity"
            onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}
            onClick={() => onSelect?.(selected === d.name || d.name === '其他' ? null : d.name)} />
        ))}
        <text x={c} y={c - 4} textAnchor="middle" className="fill-foreground text-[15px] font-semibold">
          {focus ? `${((focus.value / (total || 1)) * 100).toFixed(1)}%` : format(total)}
        </text>
        <text x={c} y={c + 14} textAnchor="middle" className="fill-muted-foreground text-[10px]">{focus ? focus.name : centerLabel ?? '合计'}</text>
      </svg>
      <div className="grid min-w-0 flex-1 basis-60 gap-1 text-sm">
        {slices.map((d, i) => (
          <button key={d.name} type="button" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}
            onClick={() => onSelect?.(selected === d.name || d.name === '其他' ? null : d.name)}
            className={cn('flex items-center gap-2 rounded-md px-2 py-1 text-left hover:bg-muted', selected === d.name && 'bg-accent')}>
            <span className="size-2.5 shrink-0 rounded-sm" style={{ background: d.uncertain ? 'var(--muted-foreground)' : PALETTE[i % PALETTE.length] }} />
            <span className={cn('flex-1 truncate', d.uncertain && 'text-muted-foreground')}>
              {d.name}{d.guess && <span className="ml-1 rounded border border-dashed px-1 text-[10px] text-muted-foreground">模拟判定</span>}
              {d.sub && <span className="ml-1 text-xs text-muted-foreground">{d.sub}</span>}
            </span>
            <span className="tabular-nums text-muted-foreground">{format(d.value)}</span>
            <span className="w-12 text-right text-xs tabular-nums text-muted-foreground">{((d.value / (total || 1)) * 100).toFixed(1)}%</span>
          </button>
        ))}
        {!slices.length && <span className="text-muted-foreground">暂无数据</span>}
      </div>
    </div>
  )
}

// Bars: stacked up/down volume per bucket.
export function Bars({ series, labelOf, height = 180 }: { series: { t: number; up: number; down: number }[]; labelOf: (t: number) => string; height?: number }) {
  const [hover, setHover] = useState<number | null>(null)
  const max = Math.max(1, ...series.map((p) => p.up + p.down))
  const n = series.length
  return (
    <div className="relative">
      <div className="flex items-end justify-between gap-px" style={{ height }} onMouseLeave={() => setHover(null)}>
        {series.map((p, i) => (
          <div key={p.t} className="flex h-full max-w-6 flex-1 flex-col justify-end" onMouseEnter={() => setHover(i)}>
            <div className={cn('rounded-t-[2px] bg-chart-1 transition-opacity', hover !== null && hover !== i && 'opacity-50')} style={{ height: `${(p.down / max) * 100}%` }} />
            <div className={cn('bg-chart-2 transition-opacity', hover !== null && hover !== i && 'opacity-50')} style={{ height: `${(p.up / max) * 100}%` }} />
          </div>
        ))}
        {!n && <div className="grid h-full w-full place-items-center text-sm text-muted-foreground">暂无数据</div>}
      </div>
      {n > 0 && (
        <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
          <span>{labelOf(series[0].t)}</span><span>{labelOf(series[n - 1].t)}</span>
        </div>
      )}
      {hover !== null && series[hover] && (
        <div className="pointer-events-none absolute top-0 rounded-md border bg-popover px-2.5 py-1.5 text-xs shadow-sm"
          style={{ left: `min(${(hover / Math.max(1, n)) * 100}%, calc(100% - 10rem))` }}>
          <div className="mb-0.5 text-muted-foreground">{labelOf(series[hover].t)}</div>
          <div className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-chart-1" />下行 <b className="ml-auto pl-3 tabular-nums">{bytes(series[hover].down)}</b></div>
          <div className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-chart-2" />上行 <b className="ml-auto pl-3 tabular-nums">{bytes(series[hover].up)}</b></div>
        </div>
      )}
    </div>
  )
}

const WEEK = ['周日', '周一', '周二', '周三', '周四', '周五', '周六']

// Heatmap: weekday × hour usage.
export function Heatmap({ data, format }: { data: number[][]; format: (v: number) => string }) {
  const max = Math.max(1, ...data.flat())
  const order = [1, 2, 3, 4, 5, 6, 0]
  return (
    <div className="overflow-x-auto">
      <div className="grid min-w-[560px] grid-cols-[2.5rem_repeat(24,1fr)] gap-[3px] text-[10px]">
        <div />
        {Array.from({ length: 24 }, (_, h) => <div key={h} className="text-center text-muted-foreground">{h % 3 === 0 ? h : ''}</div>)}
        {order.map((d) => (
          <div key={d} className="contents">
            <div className="pr-1 text-right leading-5 text-muted-foreground">{WEEK[d]}</div>
            {data[d].map((v, h) => (
              <div key={h} title={`${WEEK[d]} ${h}:00 · ${format(v)}`} className="h-5 rounded-[3px]"
                style={{ background: v ? `color-mix(in oklch, var(--chart-1) ${Math.max(8, (v / max) * 100)}%, transparent)` : 'var(--muted)' }} />
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

// HourBars: 24 small bars (activity by hour of day).
export function HourBars({ data, format }: { data: number[]; format: (v: number) => string }) {
  const max = Math.max(1, ...data)
  return (
    <div>
      <div className="flex h-16 items-end gap-[3px]">
        {data.map((v, h) => <div key={h} title={`${h}:00 · ${format(v)}`} className="flex-1 rounded-t-[2px] bg-chart-1/80" style={{ height: `${(v / max) * 100}%` }} />)}
      </div>
      <div className="mt-1 flex justify-between text-[10px] text-muted-foreground"><span>0 点</span><span>6</span><span>12</span><span>18</span><span>23</span></div>
    </div>
  )
}

// RangePicker: presets plus a draggable window over the last 90 days.
export type Range = { from: number; to: number; preset: string }

export function presetRange(p: string): Range {
  const now = Math.floor(Date.now() / 1000)
  const d = new Date(); d.setHours(0, 0, 0, 0)
  const map: Record<string, number> = { '1h': now - 3600, today: Math.floor(d.getTime() / 1000), '7d': now - 7 * 86400, '30d': now - 30 * 86400, '90d': now - 90 * 86400 }
  return { from: map[p] ?? now - 7 * 86400, to: now, preset: p }
}

export function RangePicker({ value, onChange, presets = ['today', '7d', '30d'] }: { value: Range; onChange: (r: Range) => void; presets?: string[] }) {
  const label: Record<string, string> = { '1h': '近 1 小时', today: '今天', '7d': '近 7 天', '30d': '近 30 天', '90d': '近 90 天', custom: '自定义' }
  const now = useMemo(() => Math.floor(Date.now() / 1000), [])
  const min = now - 90 * 86400
  const [open, setOpen] = useState(false)
  const fmt = (t: number) => { const x = new Date(t * 1000); return `${x.getMonth() + 1}/${x.getDate()} ${String(x.getHours()).padStart(2, '0')}:00` }
  const step = 3600
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-1 rounded-lg bg-muted p-[3px] text-sm">
        {[...presets, 'custom'].map((p) => (
          <button key={p} type="button" onClick={() => { if (p === 'custom') setOpen(!open); else { setOpen(false); onChange(presetRange(p)) } }}
            className={cn('rounded-md px-2.5 py-1 transition-colors', value.preset === p ? 'bg-background font-medium shadow-sm' : 'text-muted-foreground hover:text-foreground')}>
            {label[p] ?? p}
          </button>
        ))}
      </div>
      {open && (
        <div className="grid gap-2 rounded-lg border bg-card p-3">
          <div className="flex justify-between text-xs text-muted-foreground"><span>{fmt(value.from)}</span><span>拖动选择时间段（最长 90 天）</span><span>{fmt(value.to)}</span></div>
          <div className="relative h-6">
            <div className="absolute inset-x-0 top-1/2 h-1.5 -translate-y-1/2 rounded-full bg-muted" />
            <div className="absolute top-1/2 h-1.5 -translate-y-1/2 rounded-full bg-primary"
              style={{ left: `${((value.from - min) / (now - min)) * 100}%`, right: `${100 - ((value.to - min) / (now - min)) * 100}%` }} />
            {(['from', 'to'] as const).map((k) => (
              <input key={k} type="range" min={min} max={now} step={step} value={value[k]}
                className="range-thumb pointer-events-none absolute inset-0 w-full appearance-none bg-transparent"
                onChange={(e) => {
                  const v = Number(e.target.value)
                  const next = { ...value, preset: 'custom', [k]: v }
                  if (next.from >= next.to - step) return
                  onChange(next)
                }} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// LevelDonut: the same usage shown either by category (简要) or by service (详细).

export function LevelDonut({ services, categories, format, size, centerLabel, defaultLevel }: {
  services?: Agg[] | null; categories?: Agg[] | null; format: (v: number) => string; size?: number; centerLabel?: string; defaultLevel?: 'brief' | 'detail'
}) {
  const [level, setLevel] = useState<'brief' | 'detail'>(() => {
    try { return (localStorage.getItem('owp-donut-level') as 'brief' | 'detail') || defaultLevel || 'brief' } catch { return defaultLevel ?? 'brief' }
  })
  const pick = (l: 'brief' | 'detail') => { setLevel(l); try { localStorage.setItem('owp-donut-level', l) } catch { /* ignore */ } }
  const data = level === 'brief'
    ? (categories ?? []).map((c) => ({ name: c.name, value: c.bytes }))
    : (services ?? []).map((s) => ({ name: s.name, value: s.bytes, sub: s.category, guess: s.guess, uncertain: s.uncertain }))
  return (
    <div className="grid gap-3">
      <div className="flex justify-end">
        <div className="flex rounded-lg bg-muted p-[3px] text-xs">
          {(['brief', 'detail'] as const).map((l) => (
            <button key={l} type="button" onClick={() => pick(l)}
              className={level === l ? 'rounded-md bg-background px-2 py-0.5 font-medium shadow-sm' : 'rounded-md px-2 py-0.5 text-muted-foreground'}>
              {l === 'brief' ? '简要（按大类）' : '详细（按服务）'}
            </button>
          ))}
        </div>
      </div>
      <Donut data={data} format={format} size={size} centerLabel={centerLabel} />
    </div>
  )
}
