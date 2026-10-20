import { useMemo, useState } from 'react'

export interface Series { label: string; color: string; values: number[] }

// AreaChart: small dependency-free live chart (shared x axis, auto y scale).
export function AreaChart({ series, height = 180, format, times }: {
  series: Series[]; height?: number; format: (v: number) => string; times?: number[]
}) {
  const [hover, setHover] = useState<number | null>(null)
  const n = Math.max(0, ...series.map((s) => s.values.length))
  const max = useMemo(() => Math.max(1, ...series.flatMap((s) => s.values)) * 1.15, [series])
  const W = 600, H = height
  const x = (i: number) => (n <= 1 ? W : (i / (n - 1)) * W)
  const y = (v: number) => H - (v / max) * (H - 8)
  const path = (vals: number[]) => vals.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-[var(--h)] w-full" style={{ ['--h' as string]: `${H}px` }}
        onMouseMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect()
          setHover(n ? Math.round(((e.clientX - r.left) / r.width) * (n - 1)) : null)
        }}
        onMouseLeave={() => setHover(null)}>
        {[0.25, 0.5, 0.75].map((f) => <line key={f} x1="0" x2={W} y1={H * f} y2={H * f} className="stroke-border" strokeDasharray="3 4" vectorEffect="non-scaling-stroke" />)}
        {series.map((s) => s.values.length > 1 && (
          <g key={s.label}>
            <path d={`${path(s.values)} L${x(s.values.length - 1)},${H} L0,${H} Z`} fill={s.color} opacity={0.12} />
            <path d={path(s.values)} fill="none" stroke={s.color} strokeWidth={1.75} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
          </g>
        ))}
        {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={0} y2={H} className="stroke-muted-foreground/50" vectorEffect="non-scaling-stroke" />}
      </svg>
      <div className="absolute left-2 top-1 text-[10px] text-muted-foreground">{format(max)}</div>
      {hover !== null && (
        <div className="pointer-events-none absolute top-2 rounded-md border bg-popover px-2.5 py-1.5 text-xs shadow-sm"
          style={{ left: `min(calc(${(hover / Math.max(1, n - 1)) * 100}% + 8px), calc(100% - 9rem))` }}>
          {times?.[hover] && <div className="mb-0.5 text-muted-foreground">{new Date(times[hover] * 1000).toLocaleTimeString()}</div>}
          {series.map((s) => (
            <div key={s.label} className="flex items-center gap-1.5">
              <span className="size-2 rounded-full" style={{ background: s.color }} />{s.label}
              <span className="ml-auto pl-3 font-medium tabular-nums">{format(s.values[hover] ?? 0)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
