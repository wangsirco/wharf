import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import { ArrowDown, ArrowUp, Check, Copy, Gauge, Loader2, Play, Radar, Server, Square, Timer } from 'lucide-react'
import { csrfToken, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import type { Device, ForwardTarget } from '@/lib/types'
import { bytes, datetime } from '@/lib/format'
import { cn } from '@/lib/utils'
import { DepHint } from '@/components/deps'
import { Empty, Field, Pill, Section, VMTag } from '@/components/common'
import { DeviceSelect } from '@/components/pickers'
import { DeviceIcon } from '@/components/device-icon'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { TraceHop, TraceResult } from '@/components/worldmap'

const TraceMap = lazy(() => import('@/components/worldmap').then((m) => ({ default: m.TraceMap })))

// ---- small shared bits ----

function Seg<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: [T, string][] }) {
  return (
    <Tabs value={value} onValueChange={(v) => onChange(v as T)}>
      <TabsList>{items.map(([k, l]) => <TabsTrigger key={k} value={k} className="px-2.5">{l}</TabsTrigger>)}</TabsList>
    </Tabs>
  )
}

const mbps = (bps: number) => (bps >= 1e9 ? `${(bps / 1e9).toFixed(2)} Gbps` : `${(bps / 1e6).toFixed(bps < 1e7 ? 2 : 1)} Mbps`)
const msTone = (ms: number) => (ms < 0 ? 'text-muted-foreground' : ms < 50 ? 'text-success' : ms < 150 ? 'text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning' : 'text-destructive')

function useRun<T>() {
  const [busy, setBusy] = useState(false)
  const [data, setData] = useState<T | null>(null)
  const run = async (body: Record<string, unknown>) => {
    setBusy(true)
    try { setData(await post<T>('/tools/diag', body)) } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return { busy, data, run, setData }
}

function Elapsed({ est }: { est: number }) {
  const [t, setT] = useState(0)
  useEffect(() => { const id = setInterval(() => setT((x) => x + 1), 1000); return () => clearInterval(id) }, [])
  return (
    <div className="grid gap-2 px-4 py-6">
      <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />路由器正在测试… {t}s{est ? ` / 约 ${est}s` : ''}</div>
      {est > 0 && <div className="h-1 overflow-hidden rounded bg-muted"><div className="h-full bg-primary transition-all duration-1000" style={{ width: `${Math.min(96, (t / est) * 100)}%` }} /></div>}
    </div>
  )
}

function CopyText({ text }: { text: string }) {
  const [ok, setOk] = useState(false)
  return (
    <button type="button" className="group flex w-full items-center gap-2 rounded-md bg-muted/60 px-2.5 py-1.5 text-left font-mono text-xs hover:bg-muted"
      onClick={() => { navigator.clipboard?.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1200) }) }}>
      <span className="min-w-0 flex-1 truncate">{text}</span>
      {ok ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5 text-muted-foreground group-hover:text-foreground" />}
    </button>
  )
}

// ---- route trace (OpenTrace / NextTrace style) ----

export function TraceTool() {
  const [target, setTarget] = useState('')
  const [mode, setMode] = useState<'icmp' | 'tcp' | 'udp'>('icmp')
  const [port, setPort] = useState('443')
  const [count, setCount] = useState('5')
  const { busy, data, run } = useRun<TraceResult>()
  const start = () => target.trim() && run({ tool: 'trace', target: target.trim(), mode, port: Number(port) || 0, count: Number(count) || 5 })
  const hops = data?.hops ?? []
  const maxMs = Math.max(1, ...hops.map((h) => h.avg))
  const showMap = hops.some((h) => h.lat !== undefined)
  return (
    <div className="grid gap-4">
      <Section title="路由追踪" desc="像 OpenTrace / NextTrace 一样：看数据包从家里出发，经过哪些城市、哪些运营商，在哪一跳变慢或丢包">
        <DepHint ids={['mtr']} className="mx-4 mt-3" />
        <form className="flex flex-wrap items-end gap-3 px-4 py-3" onSubmit={(e) => { e.preventDefault(); start() }}>
          <Field label="目标" className="min-w-52 flex-1"><Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="域名或 IP，例如 1.1.1.1、github.com" /></Field>
          <Field label="协议"><Seg value={mode} onChange={setMode} items={[['icmp', 'ICMP'], ['tcp', 'TCP'], ['udp', 'UDP']]} /></Field>
          {mode !== 'icmp' && <Field label="端口" className="w-24"><Input value={port} inputMode="numeric" onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} /></Field>}
          <Field label="每跳探测次数" className="w-28"><Input value={count} inputMode="numeric" onChange={(e) => setCount(e.target.value.replace(/\D/g, ''))} /></Field>
          <Button type="submit" disabled={busy || !target.trim()}>{busy ? <Loader2 className="animate-spin" /> : <Radar />} 开始追踪</Button>
        </form>
        <div className="flex flex-wrap gap-1.5 px-4 pb-3">
          {['1.1.1.1', '8.8.8.8', 'www.baidu.com', 'www.qq.com', 'github.com', 'www.youtube.com'].map((t) => (
            <button key={t} type="button" className="rounded-full border px-2.5 py-0.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground" onClick={() => setTarget(t)}>{t}</button>
          ))}
        </div>
        {busy && <Elapsed est={(Number(count) || 5) + 12} />}
      </Section>
      {data && !busy && (
        <>
          {showMap && (
            <Section title={`${data.target}${data.target !== data.ip ? ` (${data.ip})` : ''}`} desc={`${data.mode.toUpperCase()} · ${hops.length} 跳 · 用时 ${data.secs.toFixed(1)}s · 地图位置来自离线 IP 库，仅供参考`}>
              <div className="p-3"><Suspense fallback={<div className="h-60" />}><TraceMap data={data} /></Suspense></div>
            </Section>
          )}
          <Section title="逐跳详情" desc="中间节点不回应（*）很常见，只要后面的跳正常就不是问题；看丢包要看最后一跳">
            {!hops.length ? <Empty>没有结果</Empty> : (
              <div className="divide-y">
                {hops.map((h) => <HopRow key={h.hop} h={h} max={maxMs} last={h.hop === hops[hops.length - 1].hop} />)}
              </div>
            )}
          </Section>
        </>
      )}
    </div>
  )
}

function HopRow({ h, max, last }: { h: TraceHop; max: number; last: boolean }) {
  const place = h.private ? '局域网 / 运营商内网' : [h.country_name, h.region !== h.city ? h.region : '', h.city].filter(Boolean).join(' · ')
  return (
    <div className="grid grid-cols-[2rem_1fr] gap-x-2 px-4 py-2 text-sm sm:grid-cols-[2rem_minmax(0,1.3fr)_minmax(0,1.2fr)_9rem_8rem] sm:items-center">
      <span className={cn('font-mono text-xs text-muted-foreground', last && 'font-semibold text-foreground')}>{h.hop}</span>
      <div className="min-w-0">
        {h.ip ? (
          <>
            <div className="truncate font-mono text-xs">{h.ip}</div>
            {h.host && <div className="truncate text-[11px] text-muted-foreground">{h.host}</div>}
          </>
        ) : <span className="text-muted-foreground">* 无回应</span>}
      </div>
      <div className="col-start-2 min-w-0 sm:col-start-auto">
        {h.ip && <div className="truncate text-xs">{place || '未知位置'}</div>}
        {h.asn ? <div className="truncate text-[11px] text-muted-foreground">AS{h.asn} {h.as_org}</div> : null}
      </div>
      <div className="col-start-2 flex items-center gap-2 sm:col-start-auto">
        {h.ip && (
          <>
            <div className="h-1.5 w-14 overflow-hidden rounded bg-muted"><div className="h-full rounded bg-primary/70" style={{ width: `${Math.max(4, (h.avg / max) * 100)}%` }} /></div>
            <span className={cn('font-mono text-xs tabular-nums', msTone(h.avg))}>{h.avg.toFixed(1)} ms</span>
          </>
        )}
      </div>
      <div className="col-start-2 text-xs text-muted-foreground sm:col-start-auto">
        {h.ip && <>{h.loss > 0 ? <span className={cn(h.loss >= 50 ? 'text-destructive' : 'text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning')}>丢包 {h.loss}%</span> : '无丢包'}<span className="hidden sm:inline"> · {h.best.toFixed(0)}–{h.worst.toFixed(0)}</span></>}
      </div>
    </div>
  )
}

// ---- TCP ping / DNS / HTTP ----

interface TCPing { target: string; ip: string; port: number; rtts: number[]; errors?: string[] }
interface DNSAnswer { server: string; records: string[] | null; status: string; ms: number; error?: string }
interface HTTPRes { url: string; code: number; remote_ip: string; dns: number; connect: number; tls: number; ttfb: number; total: number; size: number; speed: number; redirect: string; http_version: string; error?: string }

export function ConnTools() {
  return (
    <div className="grid items-start gap-4 xl:grid-cols-2">
      <div className="grid min-w-0 gap-4"><TCPingTool /><HTTPTool /></div>
      <DNSTool />
    </div>
  )
}

function TCPingTool() {
  const [target, setTarget] = useState('')
  const [port, setPort] = useState('443')
  const { busy, data, run } = useRun<TCPing>()
  const ok = (data?.rtts ?? []).filter((x) => x >= 0)
  return (
    <Section title="端口连通（TCP Ping）" desc="从路由器连一下某个地址的端口：服务开没开、被不被防火墙挡、延迟多少">
      <form className="flex flex-wrap items-end gap-3 px-4 py-3" onSubmit={(e) => { e.preventDefault(); if (target.trim()) run({ tool: 'tcping', target: target.trim(), port: Number(port), count: 5 }) }}>
        <Field label="地址" className="min-w-40 flex-1"><Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="域名或 IP" /></Field>
        <Field label="端口" className="w-24"><Input value={port} inputMode="numeric" onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} /></Field>
        <Button type="submit" disabled={busy || !target.trim() || !port}>{busy ? <Loader2 className="animate-spin" /> : <Play />} 测试</Button>
      </form>
      {data && !busy && (
        <div className="grid gap-2 border-t px-4 py-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            {ok.length ? <Pill tone="green">端口开放</Pill> : <Pill tone="red">连不上</Pill>}
            <span className="font-mono text-xs">{data.ip}:{data.port}</span>
            {ok.length > 0 && <span className="text-xs text-muted-foreground">平均 {(ok.reduce((a, b) => a + b, 0) / ok.length).toFixed(1)} ms · 成功 {ok.length}/{data.rtts.length}</span>}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {data.rtts.map((r, i) => <span key={i} className={cn('rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]', msTone(r))}>{r < 0 ? '失败' : `${r.toFixed(1)}ms`}</span>)}
          </div>
          {data.errors?.map((e) => <div key={e} className="text-xs text-muted-foreground">{e}</div>)}
        </div>
      )}
    </Section>
  )
}

const RESOLVERS: [string, string][] = [['', '路由器'], ['223.5.5.5', '阿里'], ['119.29.29.29', '腾讯'], ['1.1.1.1', 'Cloudflare'], ['8.8.8.8', 'Google'], ['9.9.9.9', 'Quad9']]

function DNSTool() {
  const [name, setName] = useState('')
  const [type, setType] = useState('A')
  const [servers, setServers] = useState<string[]>(['', '223.5.5.5', '1.1.1.1', '8.8.8.8'])
  const [custom, setCustom] = useState('')
  const { busy, data, run } = useRun<DNSAnswer[]>()
  const all = [...servers, ...(custom.trim() ? [custom.trim()] : [])]
  const label = (s: string) => RESOLVERS.find(([ip]) => ip === s)?.[1] ?? s
  return (
    <Section title="DNS 查询对比" desc="同一个域名问几家 DNS：看是否被污染、被拦截（NextDNS / 广告过滤），以及谁更快">
      <DepHint ids={['dig']} className="mx-4 mt-3" />
      <form className="grid gap-3 px-4 py-3" onSubmit={(e) => { e.preventDefault(); if (name.trim()) run({ tool: 'dns', target: name.trim(), type, servers: all }) }}>
        <div className="flex flex-wrap items-end gap-3">
          <Field label="域名" className="min-w-40 flex-1"><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="例如 www.google.com" /></Field>
          <Field label="类型"><Seg value={type} onChange={setType} items={[['A', 'A'], ['AAAA', 'AAAA'], ['CNAME', 'CNAME'], ['MX', 'MX'], ['TXT', 'TXT']]} /></Field>
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
          {RESOLVERS.map(([ip, l]) => (
            <label key={ip || 'router'} className="flex items-center gap-1.5">
              <Checkbox checked={servers.includes(ip)} onCheckedChange={(c) => setServers(c ? [...servers, ip] : servers.filter((x) => x !== ip))} />{l}
              {ip && <span className="font-mono text-[11px] text-muted-foreground">{ip}</span>}
            </label>
          ))}
          <Input value={custom} onChange={(e) => setCustom(e.target.value.trim())} placeholder="其他 DNS IP" className="h-7 w-32 font-mono text-xs" />
        </div>
        <div><Button type="submit" disabled={busy || !name.trim() || !all.length}>{busy ? <Loader2 className="animate-spin" /> : <Play />} 查询</Button></div>
      </form>
      {data && !busy && (
        <div className="divide-y border-t">
          {data.map((a) => (
            <div key={a.server} className="grid gap-1 px-4 py-2.5 text-sm">
              <div className="flex items-center gap-2">
                <span className="font-medium">{label(a.server)}</span>
                {a.error ? <Pill tone="red">{a.error}</Pill> : a.status && a.status !== 'NOERROR' ? <Pill tone="amber">{a.status === 'NXDOMAIN' ? '域名不存在' : a.status}</Pill> : !a.records?.length ? <Pill>无记录</Pill> : null}
                {!a.error && <span className={cn('ml-auto font-mono text-xs', msTone(a.ms))}>{a.ms} ms</span>}
              </div>
              {a.records?.map((r, i) => <div key={i} className="truncate font-mono text-[11px] text-muted-foreground">{r}</div>)}
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}

function HTTPTool() {
  const [url, setUrl] = useState('')
  const { busy, data, run } = useRun<HTTPRes>()
  const phases = data ? ([
    ['DNS 解析', 0, data.dns, '#a78bfa'], ['TCP 连接', data.dns, data.connect, '#60a5fa'],
    ['TLS 握手', data.connect, data.tls || data.connect, '#34d399'], ['等待首字节', data.tls || data.connect, data.ttfb, '#fbbf24'], ['下载内容', data.ttfb, data.total, '#f472b6'],
  ] as [string, number, number, string][]).filter(([, a, b]) => b > a) : []
  return (
    <Section title="网站访问测试" desc="从路由器打开一个网址，拆开看慢在哪：DNS、连接、TLS 还是服务器本身">
      <DepHint ids={['curl']} className="mx-4 mt-3" />
      <form className="flex flex-wrap items-end gap-3 px-4 py-3" onSubmit={(e) => { e.preventDefault(); if (url.trim()) run({ tool: 'http', target: url.trim() }) }}>
        <Field label="网址" className="min-w-52 flex-1"><Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://www.example.com" /></Field>
        <Button type="submit" disabled={busy || !url.trim()}>{busy ? <Loader2 className="animate-spin" /> : <Play />} 测试</Button>
      </form>
      {data && !busy && (
        <div className="grid gap-2.5 border-t px-4 py-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            {data.code ? <Pill tone={data.code < 400 ? 'green' : 'red'}>HTTP {data.code}</Pill> : <Pill tone="red">失败</Pill>}
            {data.remote_ip && <span className="font-mono text-xs text-muted-foreground">{data.remote_ip}</span>}
            {data.http_version && <span className="text-xs text-muted-foreground">HTTP/{data.http_version}</span>}
            <span className="ml-auto font-mono text-xs">{data.total.toFixed(0)} ms</span>
          </div>
          {data.error && <div className="text-xs text-destructive">{data.error}</div>}
          {data.redirect && <div className="truncate text-xs text-muted-foreground">跳转到 {data.redirect}</div>}
          <div className="grid gap-1">
            {phases.map(([l, a, b, c]) => (
              <div key={l} className="grid grid-cols-[5.5rem_1fr_4rem] items-center gap-2 text-xs">
                <span className="text-muted-foreground">{l}</span>
                <div className="relative h-2.5 rounded bg-muted"><div className="absolute h-full rounded" style={{ left: `${(a / data.total) * 100}%`, width: `${Math.max(1, ((b - a) / data.total) * 100)}%`, background: c }} /></div>
                <span className="text-right font-mono tabular-nums">{(b - a).toFixed(0)} ms</span>
              </div>
            ))}
          </div>
          {data.size > 0 && <div className="text-xs text-muted-foreground">下载 {bytes(data.size)} · {mbps(data.speed * 8)}</div>}
        </div>
      )}
    </Section>
  )
}

// ---- LAN speed: browser ↔ router, iperf3 ----

export function SpeedTools() {
  return (
    <div className="grid items-start gap-4 xl:grid-cols-2">
      <BrowserSpeed />
      <div className="grid min-w-0 gap-4"><IperfServerCard /><IperfClientCard /></div>
    </div>
  )
}

type Phase = 'idle' | 'down' | 'up' | 'done'

async function measureDown(secs: number, onRate: (bps: number) => void, signal: AbortSignal) {
  let total = 0, counted = 0
  const t0 = performance.now(), warm = 1000
  const worker = async () => {
    while (performance.now() - t0 < secs * 1000 && !signal.aborted) {
      const res = await fetch('/api/tools/speed/down?mb=64', { credentials: 'same-origin', cache: 'no-store', signal })
      if (!res.ok || !res.body) throw new Error('测速失败：' + res.status)
      const reader = res.body.getReader()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        total += value.length
        if (performance.now() - t0 > warm) counted += value.length
        if (performance.now() - t0 >= secs * 1000) { await reader.cancel(); break }
      }
    }
  }
  const tick = setInterval(() => { const el = performance.now() - t0 - warm; if (el > 200) onRate((counted * 8) / (el / 1000)) }, 250)
  try { await Promise.all([worker(), worker(), worker()]) } catch (e) { if (!signal.aborted) throw e } finally { clearInterval(tick) }
  void total
  return (counted * 8) / ((performance.now() - t0 - warm) / 1000)
}

async function measureUp(secs: number, onRate: (bps: number) => void, signal: AbortSignal) {
  const chunk = new Blob([new Uint8Array(8 << 20)]) // TLS doesn't compress, zeros are fine
  const t0 = performance.now(), warm = 1000
  let done = 0
  const live = new Map<XMLHttpRequest, number>()
  const sent = () => done + [...live.values()].reduce((a, b) => a + b, 0)
  let base = -1
  const send = () => new Promise<void>((resolve, reject) => {
    const x = new XMLHttpRequest()
    x.open('POST', '/api/tools/speed/up')
    x.setRequestHeader('X-OWP-CSRF', csrfToken())
    x.upload.onprogress = (e) => live.set(x, e.loaded)
    x.onload = () => { live.delete(x); done += chunk.size; x.status === 200 ? resolve() : reject(new Error('测速失败：' + x.status)) }
    x.onerror = () => { live.delete(x); reject(new Error('上传中断')) }
    x.onabort = () => { live.delete(x); resolve() }
    signal.addEventListener('abort', () => x.abort())
    x.send(chunk)
  })
  const worker = async () => { while (performance.now() - t0 < secs * 1000 && !signal.aborted) await send() }
  const stopper = new AbortController()
  const timer = setTimeout(() => stopper.abort(), secs * 1000 + 300)
  stopper.signal.addEventListener('abort', () => { for (const x of live.keys()) x.abort() })
  const rate = () => { const el = performance.now() - t0 - warm; return el > 200 && base >= 0 ? ((sent() - base) * 8) / (el / 1000) : 0 }
  const tick = setInterval(() => { if (base < 0 && performance.now() - t0 >= warm) base = sent(); const r = rate(); if (r) onRate(r) }, 250)
  let final = 0
  const snap = setTimeout(() => { final = rate() }, secs * 1000)
  try { await Promise.all([worker(), worker(), worker()]) } catch (e) { if (!signal.aborted && !stopper.signal.aborted) throw e } finally { clearInterval(tick); clearTimeout(timer); clearTimeout(snap) }
  return final || rate()
}

function BrowserSpeed() {
  const [phase, setPhase] = useState<Phase>('idle')
  const [down, setDown] = useState(0)
  const [up, setUp] = useState(0)
  const [ping, setPing] = useState(0)
  const ctl = useRef<AbortController | null>(null)
  const start = async () => {
    const ac = new AbortController(); ctl.current = ac
    setDown(0); setUp(0); setPing(0)
    try {
      const ts: number[] = []
      for (let i = 0; i < 5; i++) { const t = performance.now(); await fetch('/api/public/config', { cache: 'no-store', signal: ac.signal }); ts.push(performance.now() - t) }
      setPing(Math.min(...ts))
      setPhase('down'); setDown(await measureDown(7, setDown, ac.signal))
      if (ac.signal.aborted) return
      setPhase('up'); setUp(await measureUp(7, setUp, ac.signal))
      setPhase('done')
    } catch (e) { if (!ac.signal.aborted) toast.error((e as Error).message); setPhase('idle') }
  }
  const stop = () => { ctl.current?.abort(); setPhase('idle') }
  useEffect(() => () => ctl.current?.abort(), [])
  const running = phase === 'down' || phase === 'up'
  return (
    <Section title="本机 ↔ 路由器测速" desc="不用装任何软件：测的是你现在这台设备到路由器之间的速度（Wi-Fi / 网线 / 交换机），和宽带无关"
      action={running ? <Button size="sm" variant="outline" onClick={stop}><Square /> 停止</Button> : <Button size="sm" onClick={start}><Gauge /> {phase === 'done' ? '再测一次' : '开始测速'}</Button>}>
      <div className="grid grid-cols-3 gap-3 p-4">
        <SpeedBox icon={ArrowDown} label="下载" value={down} active={phase === 'down'} />
        <SpeedBox icon={ArrowUp} label="上传" value={up} active={phase === 'up'} />
        <div className="grid content-start gap-1 rounded-xl border p-3">
          <span className="flex items-center gap-1 text-xs text-muted-foreground"><Timer className="size-3.5" />延迟</span>
          <span className="text-xl font-semibold tabular-nums sm:text-2xl">{ping ? ping.toFixed(0) : '–'}<span className="ml-1 text-xs font-normal text-muted-foreground">ms</span></span>
        </div>
      </div>
      <div className="grid gap-1 border-t px-4 py-3 text-xs text-muted-foreground">
        <p>参考：Wi-Fi 6 近距离一般 500–1200 Mbps，Wi-Fi 5 约 300–600 Mbps，千兆网线约 900+ Mbps。</p>
        <p>浏览器测速受 HTTPS 加密和浏览器本身限制，结果通常略低于 iperf3；想测到极限请用右侧的 iperf3。</p>
      </div>
    </Section>
  )
}

function SpeedBox({ icon: Icon, label, value, active }: { icon: typeof ArrowDown; label: string; value: number; active: boolean }) {
  return (
    <div className={cn('grid content-start gap-1 rounded-xl border p-3 transition-colors', active && 'border-primary/60 bg-accent/40')}>
      <span className="flex items-center gap-1 text-xs text-muted-foreground"><Icon className="size-3.5" />{label}{active && <Loader2 className="ml-auto size-3 animate-spin" />}</span>
      <span className="text-xl font-semibold tabular-nums sm:text-2xl">{value ? (value / 1e6).toFixed(value < 1e7 ? 1 : 0) : '–'}<span className="ml-1 text-xs font-normal text-muted-foreground">Mbps</span></span>
    </div>
  )
}

interface IperfResult { ts: number; peer: string; proto: string; direction: string; secs: number; bps: number; sent_bps: number; retransmits: number; jitter_ms?: number; lost_percent?: number; streams: number; error?: string }
interface IperfServer { running: boolean; port: number; until: number; results: IperfResult[] | null; error?: string }

function IperfServerCard() {
  const { data, reload } = useApi<IperfServer>('/tools/iperf-server', 2000)
  const { data: devs } = useApi<Device[]>('/devices', 60000)
  const [busy, setBusy] = useState(false)
  const [now, setNow] = useState(Date.now() / 1000)
  useEffect(() => { const id = setInterval(() => setNow(Date.now() / 1000), 1000); return () => clearInterval(id) }, [])
  const host = location.hostname
  const act = async (tool: string) => {
    setBusy(true)
    try { await post('/tools/diag', { tool, secs: 10, port: 5201 }); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const nameOf = (ip: string) => devs?.find((d) => d.ip === ip)?.name || ip
  const left = data?.running ? Math.max(0, data.until - now) : 0
  return (
    <Section title="iperf3 服务端" desc="让路由器临时当测速服务器：电脑或手机装 iperf3 客户端（手机可用 iPerf3 / Magic iPerf 等 App）连过来测"
      action={data?.running
        ? <Button size="sm" variant="outline" disabled={busy} onClick={() => act('iperf-server-stop')}><Square /> 关闭</Button>
        : <Button size="sm" disabled={busy} onClick={() => act('iperf-server')}><Server /> 开启 10 分钟</Button>}>
      <DepHint ids={['iperf3']} className="mx-4 mt-3" />
      <div className="grid gap-2 px-4 py-3 text-sm">
        {data?.running ? (
          <>
            <div className="flex items-center gap-2"><Pill tone="green">运行中</Pill><span className="text-xs text-muted-foreground">端口 {data.port} · 还剩 {Math.floor(left / 60)}:{String(Math.floor(left % 60)).padStart(2, '0')} 自动关闭（只对局域网开放）</span></div>
            <div className="grid gap-1.5">
              <span className="text-xs text-muted-foreground">设备上传到路由器：</span><CopyText text={`iperf3 -c ${host} -p ${data.port} -t 10`} />
              <span className="text-xs text-muted-foreground">路由器下载到设备：</span><CopyText text={`iperf3 -c ${host} -p ${data.port} -t 10 -R`} />
            </div>
          </>
        ) : <span className="text-xs text-muted-foreground">未开启。开启后 10 分钟内可以反复测试，到时自动关闭。</span>}
        {data?.error && <div className="text-xs text-destructive">{data.error}</div>}
      </div>
      {!!data?.results?.length && (
        <div className="divide-y border-t">
          {data.results.map((r) => (
            <div key={r.ts + r.peer} className="flex items-center gap-3 px-4 py-2 text-sm">
              {r.direction === 'down' ? <ArrowDown className="size-4 text-primary" /> : <ArrowUp className="size-4 text-success" />}
              <div className="min-w-0 flex-1">
                <div className="truncate">{nameOf(r.peer)} <span className="text-xs text-muted-foreground">{r.direction === 'down' ? '路由器 → 设备' : '设备 → 路由器'} · {r.proto}{r.streams > 1 ? ` ×${r.streams}` : ''}</span></div>
                <div className="text-[11px] text-muted-foreground">{datetime(r.ts)}{r.retransmits ? ` · 重传 ${r.retransmits}` : ''}{r.lost_percent ? ` · 丢包 ${r.lost_percent.toFixed(1)}%` : ''}{r.error ? ` · ${r.error}` : ''}</div>
              </div>
              <span className="font-mono text-sm font-semibold tabular-nums">{mbps(r.bps)}</span>
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}

function IperfClientCard() {
  const { can } = useAuth()
  const { data: devs } = useApi<Device[]>(can('devices.view') ? '/devices' : null, 60000)
  const targets: ForwardTarget[] | undefined = devs?.map((d) => ({ ip: d.ip, mac: d.mac, name: d.name, hostname: d.hostname, type: d.type, vendor: d.vendor, vm_tag: d.vm_tag, note: d.note, online: d.online }))
  const [ip, setIp] = useState('')
  const [reverse, setReverse] = useState<'send' | 'recv'>('send')
  const [proto, setProto] = useState<'tcp' | 'udp'>('tcp')
  const [streams, setStreams] = useState('1')
  const [results, setResults] = useState<(IperfResult & { name: string })[]>([])
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try {
      const r = await post<IperfResult>('/tools/diag', { tool: 'iperf', target: ip, reverse: reverse === 'recv', mode: proto, secs: 8, streams: Number(streams) || 1, rate: '1G' })
      if (r.error) toast.error(r.error)
      setResults([{ ...r, name: targets?.find((t) => t.ip === ip)?.name || ip }, ...results].slice(0, 10))
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <Section title="路由器 → 设备（iperf3 客户端）" desc="对方设备先运行 iperf3 -s（NAS、电脑、PVE 虚拟机都行），由路由器发起测试">
      <DepHint ids={['iperf3']} className="mx-4 mt-3" />
      <div className="grid gap-3 px-4 py-3">
        <Field label="目标设备"><DeviceSelect devices={targets} value={ip} onChange={(v) => setIp(v)} /></Field>
        <div className="flex flex-wrap items-end gap-3">
          <Field label="方向"><Seg value={reverse} onChange={setReverse} items={[['send', '路由器发送'], ['recv', '路由器接收']]} /></Field>
          <Field label="协议"><Seg value={proto} onChange={setProto} items={[['tcp', 'TCP'], ['udp', 'UDP']]} /></Field>
          <Field label="并发流" className="w-20"><Input value={streams} inputMode="numeric" onChange={(e) => setStreams(e.target.value.replace(/\D/g, ''))} /></Field>
          <Button disabled={busy || !ip} onClick={run}>{busy ? <Loader2 className="animate-spin" /> : <Play />} 测试 8 秒</Button>
        </div>
      </div>
      {busy && <Elapsed est={10} />}
      {results.length > 0 && (
        <div className="divide-y border-t">
          {results.map((r, i) => (
            <div key={i} className="flex items-center gap-3 px-4 py-2 text-sm">
              {r.direction === 'recv' ? <ArrowDown className="size-4 text-primary" /> : <ArrowUp className="size-4 text-success" />}
              <div className="min-w-0 flex-1">
                <div className="truncate">{r.name} <span className="text-xs text-muted-foreground">{r.direction === 'recv' ? '设备 → 路由器' : '路由器 → 设备'} · {r.proto || proto.toUpperCase()}</span></div>
                <div className="truncate text-[11px] text-muted-foreground">{r.error || [r.retransmits ? `重传 ${r.retransmits}` : '', r.jitter_ms ? `抖动 ${r.jitter_ms.toFixed(2)} ms` : '', r.lost_percent ? `丢包 ${r.lost_percent.toFixed(1)}%` : ''].filter(Boolean).join(' · ') || '正常'}</div>
              </div>
              <span className="font-mono text-sm font-semibold tabular-nums">{r.error ? '–' : mbps(r.bps)}</span>
            </div>
          ))}
        </div>
      )}
      {!results.length && !busy && <Empty>还没有测试结果</Empty>}
    </Section>
  )
}

// ---- LAN scan ----

interface ScanHost { ip: string; mac: string; ping: boolean; rtt_ms: number; ports: { port: number; service: string }[] | null; vendor?: string; random_mac?: boolean }
interface ScanResult { subnet: string; hosts: ScanHost[] | null; secs: number; ports: boolean }

export function ScanTool() {
  const { can } = useAuth()
  const { data: devs } = useApi<Device[]>(can('devices.view') ? '/devices' : null)
  const [ports, setPorts] = useState(true)
  const [only, setOnly] = useState<'all' | 'unknown' | 'services'>('all')
  const { busy, data, run } = useRun<ScanResult>()
  const byMac = new Map((devs ?? []).map((d) => [d.mac, d]))
  const hosts = (data?.hosts ?? []).filter((h) => only === 'all' || (only === 'unknown' ? !byMac.get(h.mac)?.lease_expiry && !byMac.get(h.mac)?.static : !!h.ports?.length))
  const silent = (data?.hosts ?? []).filter((h) => !h.ping).length
  return (
    <div className="grid gap-4">
      <Section title="局域网扫描" desc="把整个网段挨个问一遍：找出不走 DHCP 的静态 IP 设备、不回 ping 的「哑设备」，以及每台设备开着哪些服务（SSH、网页、共享、摄像头……）"
        action={<Button size="sm" disabled={busy} onClick={() => run({ tool: 'scan', ports })}>{busy ? <Loader2 className="animate-spin" /> : <Radar />} 开始扫描</Button>}>
        <div className="flex flex-wrap items-center gap-4 px-4 py-3 text-sm">
          <label className="flex items-center gap-1.5"><Checkbox checked={ports} onCheckedChange={(c) => setPorts(!!c)} />同时探测 32 个常用端口</label>
          {data && <span className="text-xs text-muted-foreground">{data.subnet} · 发现 {data.hosts?.length ?? 0} 台 · {silent} 台不回应 ping · 用时 {data.secs}s</span>}
        </div>
        {busy && <Elapsed est={ports ? 25 : 10} />}
      </Section>
      {data && !busy && (
        <Section title="扫描结果" action={<Seg value={only} onChange={setOnly} items={[['all', '全部'], ['unknown', '不在 DHCP 里'], ['services', '有开放端口']]} />}>
          {!hosts.length ? <Empty>没有符合条件的设备</Empty> : (
            <div className="divide-y">
              {hosts.map((h) => {
                const d = byMac.get(h.mac)
                const dhcp = !!d?.lease_expiry || !!d?.static
                return (
                  <div key={h.ip} className="grid gap-1.5 px-4 py-2.5 sm:grid-cols-[minmax(0,1.1fr)_minmax(0,1.6fr)] sm:items-center">
                    <div className="flex min-w-0 items-center gap-3">
                      <DeviceIcon type={d?.type} online className="size-8" />
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5 text-sm"><span className="truncate font-medium">{d?.name || h.vendor || '未知设备'}</span><VMTag tag={d?.vm_tag} />
                          {!dhcp && <Pill tone="amber">静态 IP</Pill>}{!h.ping && <Pill>不回 ping</Pill>}</div>
                        <div className="truncate font-mono text-[11px] text-muted-foreground">{h.ip} · {h.mac || '无 MAC'}{h.vendor && d?.name ? ` · ${h.vendor}` : ''}{h.ping ? ` · ${h.rtt_ms.toFixed(1)} ms` : ''}</div>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1 sm:justify-end">
                      {h.ports?.map((p) => {
                        const web = [80, 443, 3000, 5000, 5001, 7080, 8006, 8080, 8123, 8443, 8888, 9000, 10000, 32400].includes(p.port)
                        const scheme = [443, 5001, 7080, 8006, 8443, 10000].includes(p.port) ? 'https' : 'http'
                        return web
                          ? <a key={p.port} href={`${scheme}://${h.ip}:${p.port}/`} target="_blank" rel="noreferrer" className="rounded-md bg-accent px-1.5 py-0.5 text-[11px] text-accent-foreground hover:underline">{p.service} :{p.port}</a>
                          : <span key={p.port} className="rounded-md bg-muted px-1.5 py-0.5 text-[11px]">{p.service} :{p.port}</span>
                      })}
                      {data.ports && !h.ports?.length && <span className="text-[11px] text-muted-foreground">没有开放常用端口</span>}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </Section>
      )}
    </div>
  )
}
