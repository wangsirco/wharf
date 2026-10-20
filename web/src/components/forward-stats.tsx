import { useState } from 'react'
import { AlertTriangle, ArrowDown, ArrowUp, CheckCircle2, Info, Lock, RefreshCw, XCircle } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import type { Forward } from '@/lib/types'
import { ago, bytes, datetime, duration } from '@/lib/format'
import { cn } from '@/lib/utils'
import { Empty, HalfPanel, Pill } from '@/components/common'
import { AreaChart } from '@/components/chart'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

const dur = (sec: number) => (sec < 60 ? `${Math.max(0, Math.round(sec))} 秒` : duration(sec))

export interface FwdUsage { up: number; down: number; conns: number; remotes: number; probes: number; live: number }

interface Svc { service: string; detail?: string; tls?: boolean; cert_cn?: string; open: boolean; error?: string; checked: number }
interface Remote {
  ip: string; conns: number; up: number; down: number; secs: number; first: number; last: number; probes: number; short: number; bulk: number; long: number
  country?: string; country_name?: string; city?: string; asn?: number; as_org?: string; verdict: string; live?: number; probe_pct: number
}
interface Conn { start: number; end: number; remote: string; rport: number; port: number; proto: string; up: number; down: number; class: string; country?: string }
interface Stats {
  forward: Forward; service: Svc; range: string; bucket: number; points: { t: number; up: number; down: number; conns: number }[]
  total: { up: number; down: number; conns: number; remotes: number; probes: number; short: number }
  remotes: Remote[] | null; recent: Conn[] | null; live: Conn[]; countries: { name: string; conns: number }[] | null
  insights: { level: 'error' | 'warn' | 'info' | 'ok'; title: string; detail: string }[] | null
}

const VERDICT: Record<string, [string, 'red' | 'amber' | 'green' | 'muted' | 'blue', string]> = {
  user: ['正常使用', 'green', '有持续的会话或真实的数据交换'],
  bulk: ['大流量', 'blue', '单个连接传输超过 10 MB'],
  brute: ['暴力破解嫌疑', 'red', '反复建立短连接，像在一次次试密码'],
  scanner: ['扫描机构', 'muted', 'Censys / Shodan 等全网测绘机构'],
  probe: ['扫描 / 探测', 'amber', '只连接不交换数据'],
  light: ['零星访问', 'muted', '少量短连接'],
  lan: ['内网', 'blue', '来自局域网（回环访问）'],
}
const CLASS: Record<string, [string, 'red' | 'amber' | 'green' | 'muted' | 'blue']> = {
  probe: ['探测', 'amber'], short: ['短连接', 'muted'], session: ['会话', 'green'], long: ['长会话', 'green'], bulk: ['大流量', 'blue'], live: ['进行中', 'green'],
}
const LV = { error: [XCircle, 'text-destructive'], warn: [AlertTriangle, 'text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning'], info: [Info, 'text-primary'], ok: [CheckCircle2, 'text-success'] } as const

const flag = (cc?: string) => (cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : '')

export function UsageCell({ u, onOpen }: { u?: FwdUsage; onOpen: () => void }) {
  if (!u) return <span className="text-xs text-muted-foreground">–</span>
  const total = u.up + u.down
  return (
    <button type="button" onClick={(e) => { e.stopPropagation(); onOpen() }} className="grid gap-0.5 rounded-md px-1.5 py-1 text-left text-xs hover:bg-muted">
      <span className="flex items-center gap-1.5 font-medium tabular-nums">{u.live > 0 && <span className="size-1.5 rounded-full bg-success" title={`${u.live} 个连接进行中`} />}{total ? bytes(total) : '无流量'}</span>
      <span className="text-[11px] text-muted-foreground">{u.conns ? `${u.conns.toLocaleString()} 次连接${u.remotes ? ` · ${u.remotes} 个 IP` : ''}` : u.live ? `${u.live} 个连接进行中` : '24 小时内无连接'}</span>
    </button>
  )
}

export function ForwardStats({ f, onClose }: { f: Forward | null; onClose: () => void }) {
  const [range, setRange] = useState('24h')
  const [refresh, setRefresh] = useState(0)
  const [tab, setTab] = useState('remotes')
  const [filter, setFilter] = useState('all')
  const { data, error } = useApi<Stats>(f ? `/forwards/${f.id}/stats?range=${range}${refresh ? `&refresh=1&n=${refresh}` : ''}` : null, 30000)
  const s = data && data.forward.id === f?.id ? data : null
  const remotes = (s?.remotes ?? []).filter((r) => filter === 'all' || (filter === 'real' ? ['user', 'bulk'].includes(r.verdict) : filter === 'bad' ? ['brute', 'probe', 'scanner'].includes(r.verdict) : true))
  const title = f ? (f.managed ? f.device_now || f.device_name || f.lan_ip : f.name || f.id) : ''
  return (
    <HalfPanel open={!!f} onOpenChange={(o) => { if (!o) onClose() }} title={`${title} · 流量与连接`}
      desc={f ? `公网 ${f.wan_port} → ${f.lan_ip}:${f.lan_port} · ${f.proto.toUpperCase()} · ${f.mode === 'restrict' ? '已限制来源' : '对所有人开放'}` : ''}>
      {error && <Empty>{error}</Empty>}
      {!s ? (!error && <div className="py-10 text-center text-sm text-muted-foreground">加载中…</div>) : (
        <div className="grid gap-5">
          <div className="flex flex-wrap items-start gap-3 rounded-xl border p-3">
            <div className="grid size-9 place-items-center rounded-lg bg-accent text-accent-foreground">{s.service.tls ? <Lock className="size-4" /> : <Info className="size-4" />}</div>
            <div className="min-w-0 flex-1">
              <div className="text-xs text-muted-foreground">转发后面运行的服务</div>
              <div className="font-medium">{s.service.service || (s.service.open ? '未能识别（端口开着，但协议不认识）' : '—')}</div>
              {s.service.detail && <div className="truncate text-xs text-muted-foreground" title={s.service.detail}>{s.service.detail}</div>}
              {s.service.cert_cn && <div className="truncate text-xs text-muted-foreground">证书：{s.service.cert_cn}</div>}
              {s.service.error && <div className="text-xs text-destructive">{s.service.error}</div>}
            </div>
            <Button variant="ghost" size="sm" onClick={() => setRefresh(refresh + 1)} title="重新识别"><RefreshCw /> 重新识别</Button>
          </div>

          <Tabs value={range} onValueChange={(v) => setRange(String(v))}>
            <TabsList>{[['24h', '24 小时'], ['7d', '7 天'], ['30d', '30 天']].map(([k, l]) => <TabsTrigger key={k} value={k} className="px-3">{l}</TabsTrigger>)}</TabsList>
          </Tabs>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <K label="外部 → 设备" icon={ArrowDown} value={bytes(s.total.down)} sub="对方上传 / 请求" />
            <K label="设备 → 外部" icon={ArrowUp} value={bytes(s.total.up)} sub="设备发出 / 下载" />
            <K label="连接次数" value={s.total.conns.toLocaleString()} sub={s.total.conns ? `${Math.round((100 * s.total.probes) / Math.max(1, s.total.conns))}% 是探测` : ''} />
            <K label="来源 IP" value={s.total.remotes.toLocaleString()} sub={s.live.length ? `${s.live.length} 个连接进行中` : '当前无连接'} />
          </div>

          {!!s.insights?.length && (
            <div className="grid gap-2">
              {s.insights.map((x, i) => {
                const [Icon, tone] = LV[x.level]
                return (
                  <div key={i} className="flex gap-2.5 rounded-lg border px-3 py-2">
                    <Icon className={cn('mt-0.5 size-4 shrink-0', tone)} />
                    <div className="min-w-0"><div className="text-sm font-medium">{x.title}</div><div className="text-xs text-muted-foreground">{x.detail}</div></div>
                  </div>
                )
              })}
            </div>
          )}

          {s.points.some((p) => p.up + p.down > 0) && (
            <div>
              <div className="mb-1 text-xs text-muted-foreground">每{s.bucket === 86400 ? '天' : '小时'}流量</div>
              <AreaChart height={140} times={s.points.map((p) => p.t)} format={(v) => bytes(v)}
                series={[{ label: '外部 → 设备', color: '#3b82f6', values: s.points.map((p) => p.down) }, { label: '设备 → 外部', color: '#10b981', values: s.points.map((p) => p.up) }]} />
            </div>
          )}

          <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
            <TabsList>
              <TabsTrigger value="remotes" className="px-3">谁连了它</TabsTrigger>
              <TabsTrigger value="live" className="px-3">正在连接{s.live.length ? ` ${s.live.length}` : ''}</TabsTrigger>
              <TabsTrigger value="recent" className="px-3">最近连接</TabsTrigger>
              <TabsTrigger value="geo" className="px-3">来源地区</TabsTrigger>
            </TabsList>
          </Tabs>

          {tab === 'remotes' && (
            <div className="grid gap-2">
              <Tabs value={filter} onValueChange={(v) => setFilter(String(v))}>
                <TabsList><TabsTrigger value="all" className="px-2.5">全部</TabsTrigger><TabsTrigger value="real" className="px-2.5">真实使用</TabsTrigger><TabsTrigger value="bad" className="px-2.5">扫描 / 爆破</TabsTrigger></TabsList>
              </Tabs>
              {!remotes.length ? <Empty>这段时间没有记录（逐连接记录从 0.15 版开始采集）</Empty> : (
                <div className="divide-y rounded-lg border">
                  {remotes.map((r) => {
                    const [label, tone, hint] = VERDICT[r.verdict] ?? [r.verdict, 'muted', '']
                    return (
                      <div key={r.ip} className="grid gap-1 px-3 py-2 text-xs sm:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)] sm:items-center">
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-[13px]">{r.ip}</span><span title={hint}><Pill tone={tone}>{label}</Pill></span>
                            {!!r.live && <Pill tone="green">在线 {r.live}</Pill>}
                          </div>
                          <div className="truncate text-muted-foreground">{flag(r.country)} {[r.country_name, r.city].filter(Boolean).join(' · ')}{r.asn ? ` · AS${r.asn} ${r.as_org ?? ''}` : ''}</div>
                        </div>
                        <div className="flex flex-wrap gap-x-3 text-muted-foreground sm:justify-end">
                          <span>{r.conns.toLocaleString()} 次{r.probes ? `（探测 ${r.probe_pct.toFixed(0)}%）` : ''}</span>
                          <span>↓{bytes(r.down)} ↑{bytes(r.up)}</span>
                          {r.long > 0 && <span>长会话 {r.long}</span>}
                          {r.secs > 0 && <span>共 {dur(r.secs)}</span>}
                          <span>{ago(r.last)}</span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
              <p className="text-[11px] text-muted-foreground">判定依据：连上就断、交换不到 600 字节算「探测」；SSH 上反复出现 1 分钟内、15 KB 以内的短连接算「暴力破解嫌疑」；超过 5 分钟算长会话；单个连接超过 10 MB 算大流量。</p>
            </div>
          )}
          {tab === 'live' && <ConnList list={s.live} live />}
          {tab === 'recent' && <ConnList list={s.recent ?? []} />}
          {tab === 'geo' && (
            !s.countries?.length ? <Empty>没有数据</Empty> : (
              <div className="grid gap-1.5">
                {s.countries.map((c) => (
                  <div key={c.name} className="grid gap-0.5 text-xs">
                    <div className="flex"><span className="flex-1">{c.name}</span><span className="tabular-nums text-muted-foreground">{c.conns.toLocaleString()} 次</span></div>
                    <div className="h-1.5 rounded bg-muted"><div className="h-full rounded bg-primary/60" style={{ width: `${(c.conns / s.countries![0].conns) * 100}%` }} /></div>
                  </div>
                ))}
              </div>
            )
          )}
        </div>
      )}
    </HalfPanel>
  )
}

function K({ label, value, sub, icon: Icon }: { label: string; value: string; sub?: string; icon?: typeof ArrowDown }) {
  return (
    <div className="min-w-0 rounded-xl border p-3">
      <div className="flex items-center gap-1 text-xs text-muted-foreground">{Icon && <Icon className="size-3.5" />}{label}</div>
      <div className="mt-1 truncate text-lg font-semibold tabular-nums">{value}</div>
      {sub && <div className="truncate text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  )
}

function ConnList({ list, live }: { list: Conn[]; live?: boolean }) {
  if (!list.length) return <Empty>{live ? '现在没有人连着' : '没有记录'}</Empty>
  return (
    <div className="max-h-[480px] divide-y overflow-auto rounded-lg border">
      {list.map((c, i) => {
        const [label, tone] = CLASS[c.class] ?? [c.class, 'muted']
        return (
          <div key={i} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-3 py-1.5 text-xs">
            <Pill tone={tone}>{label}</Pill>
            <span className="font-mono">{flag(c.country)} {c.remote}:{c.rport}</span>
            <span className="text-muted-foreground">→ :{c.port}</span>
            <span className="ml-auto flex gap-3 text-muted-foreground">
              <span>↓{bytes(c.down)} ↑{bytes(c.up)}</span>
              <span>{c.end - c.start > 0 ? dur(c.end - c.start) : '<10 秒'}</span>
              <span>{live ? `开始于 ${datetime(c.start)}` : datetime(c.end)}</span>
            </span>
          </div>
        )
      })}
    </div>
  )
}
