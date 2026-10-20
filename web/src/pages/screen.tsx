import { lazy, Suspense, useEffect, useState } from 'react'
import { useApi } from '@/lib/hooks'
import type { GeoFlows } from '@/components/worldmap'
import { CountryRanking } from '@/pages/world'

const WorldFlowMap = lazy(() => import('@/components/worldmap'))
import { useNavigate } from 'react-router-dom'
import { ArrowDown, ArrowUp, Ban, Database, Maximize, MonitorSmartphone, ShieldAlert, X } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { bitrate, bytes } from '@/lib/format'
import { EventsFeed, Kpi, LiveDevices, ServicesToday, useOverview, useWan, WanChart } from '@/components/monitor'
import { Button } from '@/components/ui/button'

// Big-screen mode: no sidebar, dark, large type, everything refreshing on its own.
export default function Screen() {
  const { sys, rate, hist } = useWan()
  const { data: ov } = useOverview(20000)
  const { can } = useAuth()
  const navigate = useNavigate()
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const root = document.documentElement
    const wasDark = root.classList.contains('dark')
    root.classList.add('dark')
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => { clearInterval(t); if (!wasDark) root.classList.remove('dark') }
  }, [])
  const [geoRange, setGeoRange] = useState('1h')
  const { data: geo } = useApi<GeoFlows>(can('traffic.view') ? `/geo/flows?range=${geoRange}` : null, 60000)
  const dv = ov?.devices
  const today = ov?.today
  const p = (x: number) => String(x).padStart(2, '0')

  return (
    <div className="min-h-svh bg-background p-4 text-foreground md:p-6">
      <div className="mb-4 flex items-center gap-3 sm:gap-4">
        <div className="text-2xl font-semibold tabular-nums sm:text-3xl">{p(now.getHours())}:{p(now.getMinutes())}<span className="text-muted-foreground">:{p(now.getSeconds())}</span></div>
        <div className="min-w-0 truncate text-xs text-muted-foreground sm:text-sm">{now.toLocaleDateString('zh-CN', { weekday: 'long', month: 'long', day: 'numeric' })}<br />{sys?.hostname}</div>
        <div className="flex-1" />
        <Button variant="ghost" size="sm" className="hidden sm:inline-flex" onClick={() => document.documentElement.requestFullscreen?.()}><Maximize /> 全屏</Button>
        <Button variant="ghost" size="sm" onClick={() => { if (document.fullscreenElement) document.exitFullscreen(); navigate('/') }}><X /> 退出</Button>
      </div>
      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-5">
        <Kpi big icon={ArrowDown} label="WAN 下行" value={bitrate(rate.rx)} />
        <Kpi big icon={ArrowUp} label="WAN 上行" value={bitrate(rate.tx)} />
        <Kpi big icon={MonitorSmartphone} label="在线设备" value={dv?.online ?? '–'} sub={dv ? `共 ${dv.total} 台${dv.new_24h ? ` · 新接入 ${dv.new_24h}` : ''}` : ''} tone={dv?.new_24h ? 'amber' : undefined} />
        <Kpi big icon={Database} label="今日流量" value={today ? bytes(today.up + today.down) : '–'} sub={today ? `DNS 拦截 ${today.dns_blocked.toLocaleString()} 次` : ''} />
        <Kpi big icon={dv?.blocked ? Ban : ShieldAlert} label="断网中" value={dv?.blocked ?? '–'} sub={dv ? `${dv.controlled} 台设备受管控` : ''} tone={dv?.blocked ? 'red' : 'green'} />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <div className="rounded-xl border bg-card p-4 xl:col-span-2">
          <div className="mb-2 text-sm text-muted-foreground">WAN 实时流量（最近 5 分钟）</div>
          <WanChart hist={hist} height={300} />
        </div>
        <div className="rounded-xl border bg-card">
          <div className="px-4 pt-4 text-sm text-muted-foreground">正在用网</div>
          {can('devices.view') && <LiveDevices limit={8} big />}
        </div>
      </div>
      {can('traffic.view') && (
        <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
          <div className="rounded-xl border bg-[#060b16] p-2">
            <div className="flex items-center justify-between px-2 pt-1 text-sm text-slate-400">
              <span>全球流量去向</span>
              <span className="flex gap-1 text-xs">
                {[['1h', '实时 1 小时'], ['24h', '24 小时'], ['7d', '7 天'], ['30d', '30 天']].map(([k, l]) => (
                  <button key={k} type="button" onClick={() => setGeoRange(k)} className={geoRange === k ? 'rounded bg-sky-500/20 px-2 py-0.5 text-sky-300' : 'px-2 py-0.5 hover:text-slate-200'}>{l}</button>
                ))}
              </span>
            </div>
            <Suspense fallback={<div className="h-[420px]" />}><WorldFlowMap data={geo ?? null} height={420} /></Suspense>
          </div>
          <div className="rounded-xl border bg-card">
            <div className="px-4 pt-4 text-sm text-muted-foreground">流量最多的国家 / 地区</div>
            <CountryRanking data={geo ?? null} limit={8} />
          </div>
        </div>
      )}
      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        {can('traffic.view') && (
          <div className="rounded-xl border bg-card p-4 xl:col-span-2">
            <div className="mb-2 text-sm text-muted-foreground">今日流量去向</div>
            <ServicesToday data={ov ?? null} size={220} />
          </div>
        )}
        <div className="rounded-xl border bg-card">
          <div className="px-4 pt-4 text-sm text-muted-foreground">最近事件</div>
          <div className="max-h-[320px] overflow-hidden"><EventsFeed limit={10} poll={20000} /></div>
        </div>
      </div>
    </div>
  )
}
