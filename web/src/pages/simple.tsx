import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowDown, ArrowLeft, ArrowUp, Sparkles } from 'lucide-react'
import { get } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { useLive } from '@/lib/live'
import type { Agg, Device, LiveHost, NetworkResp, ProfileResp, SimpleDevice, TrafficResp } from '@/lib/types'
import { publicNow, quality } from '@/lib/net'
import { bitrate, bytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import { AreaChart } from '@/components/chart'
import { Donut, LevelDonut, PALETTE } from '@/components/charts'
import { DeviceIcon } from '@/components/device-icon'
import { Empty, Section, TargetName, VMTag } from '@/components/common'
import { useWan, WanChart } from '@/components/monitor'

// ---------- simple home: the device wall ----------

function CategoryBar({ cats }: { cats: SimpleDevice['categories'] }) {
  const all = cats ?? []
  const total = all.reduce((a, c) => a + c.bytes, 0)
  const list = all.filter((c) => total && c.bytes / total >= 0.01)
  if (!total) return <div className="h-1.5 rounded-full bg-muted" />
  return (
    <div className="grid gap-1.5">
      <div className="flex h-1.5 overflow-hidden rounded-full bg-muted">
        {list.map((c, i) => <div key={c.name} style={{ flex: c.bytes, background: c.name === '其他' ? 'var(--muted-foreground)' : PALETTE[i % PALETTE.length] }} />)}
      </div>
      <div className="flex flex-wrap gap-x-2.5 gap-y-0.5 text-[11px] text-muted-foreground">
        {list.slice(0, 3).map((c, i) => (
          <span key={c.name} className="flex items-center gap-1">
            <span className="size-1.5 rounded-full" style={{ background: c.name === '其他' ? 'var(--muted-foreground)' : PALETTE[i % PALETTE.length] }} />
            {c.name} {Math.round((c.bytes / total) * 100)}%
          </span>
        ))}
      </div>
    </div>
  )
}

// What the household's devices are, by brand or by kind.
function DeviceMix({ devices }: { devices: Device[] }) {
  const [by, setBy] = useState<'vendor' | 'type'>('vendor')
  const data = useMemo(() => {
    const m = new Map<string, number>()
    for (const d of devices) {
      const k = by === 'type' ? d.type || '未知'
        : d.vendor ? d.vendor.split('·')[0].replace(/（.*）$/, '').replace(/生态$/, '').trim()
        : d.random_mac ? '隐私 MAC（手机 / 平板）' : '未知厂商'
      m.set(k, (m.get(k) ?? 0) + 1)
    }
    return [...m.entries()].map(([name, value]) => ({ name, value, uncertain: name.startsWith('未知') || name.startsWith('隐私') }))
      .sort((a, b) => b.value - a.value)
  }, [devices, by])
  return (
    <div className="grid gap-3">
      <div className="flex justify-end">
        <div className="flex rounded-lg bg-muted p-[3px] text-xs">
          {(['vendor', 'type'] as const).map((k) => (
            <button key={k} type="button" onClick={() => setBy(k)}
              className={by === k ? 'rounded-md bg-background px-2 py-0.5 font-medium shadow-sm' : 'rounded-md px-2 py-0.5 text-muted-foreground'}>
              {k === 'vendor' ? '按厂商' : '按类型'}
            </button>
          ))}
        </div>
      </div>
      <Donut data={data} format={(v) => `${v} 台`} centerLabel="台设备" />
    </div>
  )
}

export function SimpleHome() {
  const { data: devices } = useApi<Device[]>('/devices', 30000)
  const { data: sums } = useApi<SimpleDevice[]>('/simple/devices?range=today', 60000)
  const live = useLive(3000)
  const { rate, hist } = useWan()
  const { can } = useAuth()
  const navigate = useNavigate()
  const [all, setAll] = useState(false)
  const { data: day } = useApi<{ services: Agg[] | null; categories: Agg[] | null; up: number; down: number }>(can('traffic.view') ? '/traffic/overview?range=24h' : null, 120000)
  // devices seen in the last 24 h: online now, or holding a DHCP lease that is still valid / renewed recently
  const recent = (devices ?? []).filter((d) => d.ip && (d.online || d.lease_expiry > Date.now() / 1000 - 86400))

  const byMac = useMemo(() => Object.fromEntries((sums ?? []).map((s) => [s.mac, s])), [sums])
  const speed = (d: Device) => (live[d.mac]?.down ?? 0) + (live[d.mac]?.up ?? 0)
  const used = (d: Device) => (byMac[d.mac]?.up ?? 0) + (byMac[d.mac]?.down ?? 0)
  const list = (devices ?? []).filter((d) => d.ip && (all || d.online))
    .sort((a, b) => speed(b) - speed(a) || used(b) - used(a))
  const todayTotal = (sums ?? []).reduce((a, s) => a + s.up + s.down, 0)
  const { data: net } = useApi<NetworkResp>('/network?range=today', 60000)
  const nq = publicNow(net?.targets, net?.wan?.wan.gateway)
  const q = quality(nq.ms, nq.loss)

  return (
    <div className="grid gap-5">
      <div className="grid gap-4 md:grid-cols-[1fr_2fr]">
        <div className="grid gap-3 rounded-2xl border bg-card p-5">
          <div className="text-sm text-muted-foreground">现在家里的网速</div>
          <div className="flex items-end gap-6">
            <div><div className="flex items-center gap-1 text-xs text-muted-foreground"><ArrowDown className="size-3.5 text-chart-1" />下载</div><div className="text-3xl font-semibold tabular-nums">{bitrate(rate.rx)}</div></div>
            <div><div className="flex items-center gap-1 text-xs text-muted-foreground"><ArrowUp className="size-3.5 text-chart-2" />上传</div><div className="text-3xl font-semibold tabular-nums">{bitrate(rate.tx)}</div></div>
          </div>
          <div className="text-sm text-muted-foreground">
            {devices ? `${devices.filter((d) => d.online && d.ip).length} 台设备在线` : '…'}
            {todayTotal > 0 && ` · 今天一共用了 ${bytes(todayTotal)}`}
          </div>
          {net && (
            <div className="flex items-center gap-2 text-sm">
              <span className={cn('size-2 rounded-full', q.tone === 'green' ? 'bg-success' : q.tone === 'amber' ? 'bg-warning' : 'bg-destructive')} />
              网络{q.label}{nq.ms ? `，延迟 ${nq.ms} ms` : ''}
              <span className="text-muted-foreground">· {net.outages?.length ? `今天断网 ${net.outages.length} 次` : '今天没有断网'}</span>
            </div>
          )}
        </div>
        <div className="rounded-2xl border bg-card p-4"><WanChart hist={hist} height={150} /></div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        {can('traffic.view') && (
          <Section title="最近 24 小时，家里大多在访问什么" desc="全部设备合计，按连接统计">
            <div className="p-4"><LevelDonut services={day?.services} categories={day?.categories} format={bytes} centerLabel="24 小时" /></div>
          </Section>
        )}
        <Section title="家里的设备都是什么" desc={devices ? `最近 24 小时出现过 ${recent.length} 台` : undefined}>
          <div className="p-4"><DeviceMix devices={recent} /></div>
        </Section>
      </div>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">家里的设备</h2>
        <div className="flex rounded-lg bg-muted p-[3px] text-xs">
          <button type="button" onClick={() => setAll(false)} className={!all ? 'rounded-md bg-background px-2.5 py-1 font-medium shadow-sm' : 'px-2.5 py-1 text-muted-foreground'}>在线</button>
          <button type="button" onClick={() => setAll(true)} className={all ? 'rounded-md bg-background px-2.5 py-1 font-medium shadow-sm' : 'px-2.5 py-1 text-muted-foreground'}>全部</button>
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        {list.map((d) => {
          const l = live[d.mac], s = byMac[d.mac]
          const active = speed(d) > 2048
          const doing = s?.now?.[0]
          return (
            <button key={d.mac} type="button" onClick={() => navigate(`/devices/${d.mac}`)}
              className={cn('grid gap-3 rounded-2xl border bg-card p-4 text-left transition-colors hover:border-primary/40 hover:bg-muted/30', active && 'border-primary/30')}>
              <div className="flex items-center gap-3">
                <DeviceIcon type={d.type} online={d.online} className="size-10 rounded-xl" />
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 items-center gap-1.5"><span className="truncate font-medium">{d.name || d.ip}</span><VMTag tag={d.vm_tag} /></div>
                  <div className="truncate text-xs text-muted-foreground">{d.type}{d.blocked ? ' · 已断网' : ''}</div>
                </div>
                {active && <span className="relative flex size-2.5"><span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-60" /><span className="relative inline-flex size-2.5 rounded-full bg-success" /></span>}
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs">
                <div><div className="text-muted-foreground">下载</div><div className="font-medium tabular-nums">{l?.down ? bitrate(l.down) : '–'}</div></div>
                <div><div className="text-muted-foreground">上传</div><div className="font-medium tabular-nums">{l?.up ? bitrate(l.up) : '–'}</div></div>
                <div><div className="text-muted-foreground">今天</div><div className="font-medium tabular-nums">{s ? bytes(s.up + s.down) : '–'}</div></div>
              </div>
              {can('traffic.view') && (
                <>
                  <CategoryBar cats={s?.categories ?? null} />
                  <div className="truncate text-xs text-muted-foreground">
                    {doing ? <>最近一小时在用 <span className={doing.uncertain ? '' : 'font-medium text-foreground'}>{doing.name}</span></> : '最近一小时没有明显活动'}
                  </div>
                </>
              )}
            </button>
          )
        })}
      </div>
      {devices && !list.length && <Empty>没有设备</Empty>}
    </div>
  )
}

// ---------- simple device page ----------

function useDeviceLive(mac: string) {
  const [hist, setHist] = useState<{ t: number[]; up: number[]; down: number[] }>({ t: [], up: [], down: [] })
  const [cur, setCur] = useState<LiveHost | null>(null)
  const last = useRef(0)
  useEffect(() => {
    let alive = true
    const tick = async () => {
      if (document.hidden) return
      try {
        const r = await get<{ ts: number; hosts: Record<string, LiveHost> }>('/traffic/live')
        if (!alive || r.ts === last.current) return
        last.current = r.ts
        const h = r.hosts[mac] ?? { mac, ip: '', up: 0, down: 0, up_total: 0, down_total: 0, last_seen: 0 }
        setCur(h)
        setHist((x) => ({ t: [...x.t, r.ts].slice(-90), up: [...x.up, h.up].slice(-90), down: [...x.down, h.down].slice(-90) }))
      } catch { /* keep last */ }
    }
    tick()
    const t = setInterval(tick, 2000)
    document.addEventListener('visibilitychange', tick)
    return () => { alive = false; clearInterval(t); document.removeEventListener('visibilitychange', tick) }
  }, [mac])
  return { cur, hist }
}

export function SimpleDevicePage() {
  const { mac = '' } = useParams()
  const { can } = useAuth()
  const { data: devices } = useApi<Device[]>('/devices', 30000)
  const d = devices?.find((x) => x.mac === mac)
  const [range, setRange] = useState<'today' | '7d'>('today')
  const { cur, hist } = useDeviceLive(mac)
  const { data: tr } = useApi<TrafficResp>(can('traffic.view') ? `/devices/${encodeURIComponent(mac)}/traffic?range=${range}` : null, 60000)
  const { data: pf } = useApi<ProfileResp>(can('traffic.view') ? `/devices/${encodeURIComponent(mac)}/profile?range=${range}` : null, 60000)

  // what it visited: one row per service, most recent first
  const visited = useMemo(() => {
    const m = new Map<string, { name: string; category: string; guess: boolean; uncertain: boolean; requests: number; bytes: number; last: number; domains: string[] }>()
    for (const x of pf?.domains ?? []) {
      const key = x.service
      const e = m.get(key) ?? { name: x.service, category: x.category, guess: x.guess, uncertain: x.uncertain, requests: 0, bytes: 0, last: 0, domains: [] }
      e.requests += x.requests; e.bytes += x.bytes; e.last = Math.max(e.last, x.last_seen)
      if (e.domains.length < 3) e.domains.push(x.domain)
      m.set(key, e)
    }
    return [...m.values()].filter((e) => e.category !== '广告追踪').sort((a, b) => b.last - a.last || b.requests - a.requests).slice(0, 30)
  }, [pf])
  const hh = (t: number) => {
    const x = new Date(t * 1000), now = new Date()
    const y = new Date(now); y.setDate(now.getDate() - 1)
    const day = x.toDateString() === now.toDateString() ? '今天' : x.toDateString() === y.toDateString() ? '昨天' : `${x.getMonth() + 1} 月 ${x.getDate()} 日`
    return `${day} ${x.getHours()} 点`
  }

  return (
    <div className="grid gap-5">
      <Link to="/" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3.5" /> 全部设备</Link>
      <div className="flex items-center gap-4">
        <DeviceIcon type={d?.type} online={d?.online} className="size-14 rounded-2xl [&_svg]:size-7" />
        <div>
          <h1 className="text-2xl font-semibold">{d?.name || d?.ip || '…'}</h1>
          <div className="text-sm text-muted-foreground">{d ? `${d.type}${d.os ? ' · ' + d.os : ''} · ${d.online ? '在线' : '离线'}${d.blocked ? ' · 已断网' : ''}` : ''}</div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-[1fr_2fr]">
        <div className="grid content-start gap-4 rounded-2xl border bg-card p-5">
          <div className="text-sm text-muted-foreground">现在的网速</div>
          <div className="flex gap-6">
            <div><div className="flex items-center gap-1 text-xs text-muted-foreground"><ArrowDown className="size-3.5 text-chart-1" />下载</div><div className="text-3xl font-semibold tabular-nums">{bitrate(cur?.down ?? 0)}</div></div>
            <div><div className="flex items-center gap-1 text-xs text-muted-foreground"><ArrowUp className="size-3.5 text-chart-2" />上传</div><div className="text-3xl font-semibold tabular-nums">{bitrate(cur?.up ?? 0)}</div></div>
          </div>
          {tr && <div className="text-sm text-muted-foreground">{range === 'today' ? '今天' : '最近 7 天'}用了 <span className="font-medium text-foreground">{bytes(tr.up + tr.down)}</span>（下载 {bytes(tr.down)} · 上传 {bytes(tr.up)}）</div>}
        </div>
        <div className="rounded-2xl border bg-card p-4">
          <AreaChart height={150} format={bitrate} times={hist.t}
            series={[{ label: '下载', color: 'var(--chart-1)', values: hist.down }, { label: '上传', color: 'var(--chart-2)', values: hist.up }]} />
        </div>
      </div>

      {can('traffic.view') && (
        <>
          <div className="flex rounded-lg bg-muted p-[3px] text-sm self-start w-fit">
            {(['today', '7d'] as const).map((r) => (
              <button key={r} type="button" onClick={() => setRange(r)} className={range === r ? 'rounded-md bg-background px-3 py-1 font-medium shadow-sm' : 'px-3 py-1 text-muted-foreground'}>{r === 'today' ? '今天' : '最近 7 天'}</button>
            ))}
          </div>
          {pf?.summary?.length ? (
            <div className="rounded-2xl border bg-gradient-to-br from-accent/60 to-card p-4 text-sm">
              <div className="mb-1 flex items-center gap-2 font-medium"><Sparkles className="size-4 text-primary" />这台设备{range === 'today' ? '今天' : '最近'}主要在做什么</div>
              <ul className="grid gap-0.5">{pf.summary.map((s) => <li key={s}>· {s}</li>)}</ul>
            </div>
          ) : null}
          <div className="grid gap-4 xl:grid-cols-2">
            <Section title="流量都花在哪了">
              <div className="p-4"><LevelDonut services={tr?.services} categories={tr?.categories} format={bytes} /></div>
            </Section>
            <Section title="访问了什么" desc="按服务归类，最近的在前（已隐藏广告与追踪）">
              <div className="max-h-[420px] divide-y overflow-y-auto">
                {visited.map((v) => (
                  <div key={v.name} className="flex items-center gap-3 px-4 py-2.5">
                    <div className="min-w-0 flex-1">
                      <TargetName name={v.name} guess={v.guess} uncertain={v.uncertain} className="font-medium" />
                      <div className="truncate text-xs text-muted-foreground">{v.category} · {v.domains.join('、')}</div>
                    </div>
                    <div className="text-right text-xs text-muted-foreground">
                      <div>{hh(v.last)}</div>
                      <div>{v.requests ? `${v.requests} 次` : ''}{v.bytes ? ` · ${bytes(v.bytes)}` : ''}</div>
                    </div>
                  </div>
                ))}
                {pf && !visited.length && <Empty>还没有记录</Empty>}
              </div>
            </Section>
          </div>
        </>
      )}
    </div>
  )
}
