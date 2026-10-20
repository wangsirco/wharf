import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { ArrowDown, ArrowLeft, ArrowUp, Ban, Clock, House, LogOut, Pencil, Pin, Radar, Search, ShieldCheck, Sparkles } from 'lucide-react'
import { get, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import type { Catalog, Device, LiveHost, ProfileResp, Probe, RemoteRow, TrafficResp } from '@/lib/types'
import { ago, bitrate, bytes, datetime } from '@/lib/format'
import { cn } from '@/lib/utils'
import { Empty, ErrorBox, Pill, Section, TargetName, VMTag } from '@/components/common'
import { AreaChart } from '@/components/chart'
import { Bars, Donut, Heatmap, HourBars, LevelDonut, presetRange, RangePicker, type Range } from '@/components/charts'
import { DevicePanel, quickBlock } from '@/pages/devices'
import { DeviceIcon, TYPE_BY } from '@/components/device-icon'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field } from '@/components/common'
import { runAction } from '@/lib/actions'
import { PolicyEditor } from '@/components/policy'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

const devName = (d?: Device) => d?.name || d?.static_name || d?.hostname || ''
const qs = (r: Range) => `from=${r.from}&to=${r.to}`

function Stat({ label, value, sub, icon: Icon }: { label: string; value: string; sub?: string; icon?: typeof ArrowUp }) {
  return (
    <div className="min-w-0 rounded-xl border bg-card p-3 sm:p-4">
      <div className="flex items-center gap-1.5 truncate text-xs text-muted-foreground">{Icon && <Icon className="size-3.5 shrink-0" />}{label}</div>
      <div className="mt-1.5 text-xl font-semibold tracking-tight tabular-nums sm:text-2xl">{value}</div>
      {sub && <div className="mt-0.5 truncate text-xs text-muted-foreground">{sub}</div>}
    </div>
  )
}

export default function DevicePage() {
  const { mac = '' } = useParams()
  const { can } = useAuth()
  const { data: devices, reload } = useApi<Device[]>('/devices', 30000)
  const d = devices?.find((x) => x.mac === mac)
  const [params] = useSearchParams()
  const [tab, setTab] = useState(params.get('tab') ?? (can('traffic.view') ? 'profile' : 'live'))
  const [edit, setEdit] = useState<Device | null>(null)
  const [info, setInfo] = useState(false)

  return (
    <>
      <div className="mb-3"><Link to="/devices" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3.5" /> 设备列表</Link></div>
      <div className="mb-5 flex flex-wrap items-center gap-4">
        <DeviceIcon type={d?.type} online={d?.online} className="size-12 rounded-xl [&_svg]:size-6" />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h1 className="truncate text-xl font-semibold tracking-tight">{devName(d) || (devices ? '未知设备' : '…')}</h1>
            <VMTag tag={d?.vm_tag} />
            {d?.is_new && <Pill tone="amber">新设备</Pill>}
            {d?.blocked && <Pill tone="red"><Ban className="size-3" />{d.blocked_by === 'schedule' ? '定时断网中' : '已断网'}</Pill>}
            {d && can('devices.manage') && <Button variant="ghost" size="icon-sm" title="修改名称 / 类型" onClick={() => setInfo(true)}><Pencil /></Button>}
          </div>
          <div className="mt-0.5 flex flex-wrap gap-x-3 text-sm text-muted-foreground">
            <span className="font-mono">{d?.ip}</span><span className="font-mono">{mac}</span>
            {d && <span>{d.type}{d.os ? ` · ${d.os}` : ''}{d.vendor ? ` · ${d.vendor}` : d.random_mac ? ' · 隐私 MAC' : ''}</span>}
            {d?.type_by && <span className="text-xs">（{TYPE_BY[d.type_by] ?? d.type_by}识别）</span>}
            {d?.first_seen ? <span className="text-xs">首次出现 {datetime(d.first_seen)}</span> : null}
          </div>
          {d?.note && <div className="mt-1 text-sm">{d.note}</div>}
        </div>
        {d && can('devices.manage') && <Button variant="outline" size="sm" onClick={() => setEdit(d)}><Pin /> 静态 IP</Button>}
        {d && can('access.manage') && (
          <Button variant={d.blocked ? 'outline' : 'destructive'} size="sm" onClick={async () => {
            try { await quickBlock(d, !d.blocked) } catch (e) { toast.error((e as Error).message) } finally { reload() }
          }}>{d.blocked ? <><ShieldCheck /> 恢复上网</> : <><Ban /> 断网</>}</Button>
        )}
      </div>
      <Tabs value={tab} onValueChange={(v) => setTab(String(v))} className="mb-4">
        <TabsList>
          <TabsTrigger value="live">实时网速</TabsTrigger>
          {can('traffic.view') && <TabsTrigger value="traffic">流量统计</TabsTrigger>}
          {can('traffic.view') && <TabsTrigger value="profile">设备画像</TabsTrigger>}
          {can('traffic.view') && <TabsTrigger value="remotes">访问明细</TabsTrigger>}
          {can('access.manage') && <TabsTrigger value="control">访问控制</TabsTrigger>}
        </TabsList>
      </Tabs>
      {tab === 'live' && <LiveTab mac={mac} />}
      {tab === 'traffic' && <TrafficTab mac={mac} />}
      {tab === 'profile' && <ProfileTab mac={mac} />}
      {tab === 'remotes' && <RemotesTab mac={mac} />}
      {tab === 'control' && <PolicyEditor mac={mac} name={devName(d)} />}
      <DevicePanel device={edit} onClose={() => setEdit(null)} canManage={can('devices.manage')} onSaved={() => { setEdit(null); reload() }} />
      {d && <InfoDialog open={info} device={d} onClose={() => setInfo(false)} onSaved={() => { setInfo(false); reload() }} />}
    </>
  )
}

function LiveTab({ mac }: { mac: string }) {
  const [hist, setHist] = useState<{ t: number[]; up: number[]; down: number[] }>({ t: [], up: [], down: [] })
  const [cur, setCur] = useState<LiveHost | null>(null)
  const [err, setErr] = useState('')
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
        setHist((x) => ({ t: [...x.t, r.ts].slice(-150), up: [...x.up, h.up].slice(-150), down: [...x.down, h.down].slice(-150) }))
        setErr('')
      } catch (e) { setErr((e as Error).message) }
    }
    tick()
    const t = setInterval(tick, 2000)
    document.addEventListener('visibilitychange', tick)
    return () => { alive = false; clearInterval(t); document.removeEventListener('visibilitychange', tick) }
  }, [mac])
  return (
    <div className="grid gap-4">
      {err && <ErrorBox>{err}</ErrorBox>}
      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <Stat icon={ArrowDown} label="下行（下载）" value={bitrate(cur?.down ?? 0)} />
        <Stat icon={ArrowUp} label="上行（上传）" value={bitrate(cur?.up ?? 0)} />
        <Stat label="Agent 启动以来下载" value={bytes(cur?.down_total ?? 0)} />
        <Stat label="Agent 启动以来上传" value={bytes(cur?.up_total ?? 0)} sub={cur?.last_seen ? `最后活动 ${datetime(cur.last_seen)}` : undefined} />
      </div>
      <Section title="实时网速" desc="每 2 秒采样，保留最近 5 分钟（设备与互联网之间的流量）">
        <div className="p-4">
          <AreaChart height={220} format={bitrate} times={hist.t}
            series={[{ label: '下行', color: 'var(--chart-1)', values: hist.down }, { label: '上行', color: 'var(--chart-2)', values: hist.up }]} />
        </div>
      </Section>
      <PresenceCard mac={mac} />
    </div>
  )
}

interface PresenceResp { state?: 'home' | 'away'; online?: boolean; now?: number; last_seen?: number; since?: number; away_minutes: number; events: { ts: number; kind: 'left' | 'back'; ip: string; away_secs: number }[] }

// PresenceCard: when this device left and came back to the home network.
function PresenceCard({ mac }: { mac: string }) {
  const { data } = useApi<PresenceResp>(`/devices/${encodeURIComponent(mac)}/presence`, 15000)
  if (!data) return null
  const away = data.state === 'away'
  // disconnected, but not long enough yet to count as "left"
  const gone = !away && data.online === false && !!data.last_seen
  const goneMin = gone ? Math.max(1, Math.round(((data.now ?? Date.now() / 1000) - data.last_seen!) / 60)) : 0
  const awayFor = (s: number) => (s < 3600 ? `${Math.max(1, Math.round(s / 60))} 分钟` : s < 86400 ? `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分` : `${Math.floor(s / 86400)} 天 ${Math.floor((s % 86400) / 3600)} 小时`)
  return (
    <Section title="上下线记录" desc={`连续 ${data.away_minutes} 分钟没有在网络中出现，即记为离开（可在系统设置中调整）`}>
      <div className="flex items-center gap-2 border-b px-4 py-3 text-sm">
        {data.state ? (
          <>
            <span className={cn('size-2 rounded-full', away ? 'bg-muted-foreground/40' : gone ? 'bg-warning' : 'bg-success')} />
            {gone ? <>已断开约 {goneMin} 分钟 <span className="text-muted-foreground">· 最后在线 {datetime(data.last_seen!).slice(11, 16)}{goneMin < data.away_minutes ? `，再过约 ${data.away_minutes - goneMin} 分钟记为离开` : '，即将记为离开'}</span></>
              : away ? <>已离开网络 {data.last_seen ? <span className="text-muted-foreground">· 最后在线 {datetime(data.last_seen).slice(5, 16)}（{ago(data.last_seen)}）</span> : null}</>
              : <>在网络中 {data.since ? <span className="text-muted-foreground">· 自 {datetime(data.since).slice(5, 16)} 起</span> : null}</>}
          </>
        ) : <span className="text-muted-foreground">正在建立在线记录，几分钟后显示</span>}
      </div>
      {data.events.length ? (
        <div className="divide-y">
          {data.events.map((e) => (
            <div key={e.ts + e.kind} className="flex items-center gap-3 px-4 py-2 text-sm">
              <span className={cn('grid size-6 shrink-0 place-items-center rounded-full', e.kind === 'back' ? 'bg-success/12 text-success' : 'bg-muted text-muted-foreground')}>
                {e.kind === 'back' ? <House className="size-3" /> : <LogOut className="size-3" />}
              </span>
              <span className="flex-1">{e.kind === 'back' ? (e.away_secs ? `回到网络 · 离开了 ${awayFor(e.away_secs)}` : '回到网络') : '离开网络'}</span>
              <span className="text-xs tabular-nums text-muted-foreground">{datetime(e.ts).slice(5, 16)}</span>
            </div>
          ))}
        </div>
      ) : <Empty>还没有离开或回来的记录</Empty>}
    </Section>
  )
}

function TrafficTab({ mac }: { mac: string }) {
  const [range, setRange] = useState<Range>(presetRange('7d'))
  const { data, error, loading } = useApi<TrafficResp>(`/devices/${encodeURIComponent(mac)}/traffic?${qs(range)}`)
  const label = (t: number) => {
    const x = new Date(t * 1000)
    if (data?.step === 86400) return `${x.getMonth() + 1}/${x.getDate()}`
    return `${x.getMonth() + 1}/${x.getDate()} ${String(x.getHours()).padStart(2, '0')}:${String(x.getMinutes()).padStart(2, '0')}`
  }
  const busiest = data?.series?.reduce((m, p) => (p.up + p.down > m.up + m.down ? p : m), { t: 0, up: 0, down: 0 })
  return (
    <div className="grid gap-4">
      <RangePicker value={range} onChange={setRange} presets={['1h', 'today', '7d', '30d', '90d']} />
      {error && <ErrorBox>{error}</ErrorBox>}
      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <Stat icon={ArrowDown} label="下载总量" value={bytes(data?.down ?? 0)} />
        <Stat icon={ArrowUp} label="上传总量" value={bytes(data?.up ?? 0)} />
        <Stat icon={Clock} label="最常用的时段" value={data ? `${String(data.peak_hour).padStart(2, '0')}:00` : '–'} sub="按一天中的小时汇总" />
        <Stat label="用量最高的时间点" value={busiest?.t ? bytes(busiest.up + busiest.down) : '–'} sub={busiest?.t ? label(busiest.t) : undefined} />
      </div>
      <Section title="流量趋势" desc={data ? `粒度：${data.step === 60 ? '每分钟' : data.step === 3600 ? '每小时' : '每天'}` : ''}>
        <div className="p-4">{loading && !data ? <Empty>加载中…</Empty> : <Bars series={data?.series ?? []} labelOf={label} />}</div>
      </Section>
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title="时段分布" desc="一周 × 24 小时，颜色越深用量越大">
          <div className="p-4">{data && <Heatmap data={data.heatmap} format={bytes} />}</div>
        </Section>
        <Section title="流量去向（按服务）">
          <div className="p-4">
            <LevelDonut services={data?.services} categories={data?.categories} format={bytes} />
          </div>
        </Section>
      </div>
    </div>
  )
}

function ProfileTab({ mac }: { mac: string }) {
  const [range, setRange] = useState<Range>(presetRange('7d'))
  const [category, setCategory] = useState<string | null>(null)
  const [company, setCompany] = useState<string | null>(null)
  const [metric, setMetric] = useState<'bytes' | 'requests'>('bytes')
  const [q, setQ] = useState('')
  const { data: catalog } = useApi<Catalog>('/rules/catalog')
  const params = `${qs(range)}${category ? `&category=${encodeURIComponent(category)}` : ''}${company ? `&company=${encodeURIComponent(company)}` : ''}`
  const { data, error, loading } = useApi<ProfileResp>(`/devices/${encodeURIComponent(mac)}/profile?${params}`)
  const fmt = metric === 'bytes' ? bytes : (v: number) => `${v.toLocaleString()} 次`
  const cats = (metric === 'bytes' ? data?.categories : data?.categories_by_req) ?? []
  const svcs = (metric === 'bytes' ? data?.services : data?.services_by_req) ?? []
  const domains = useMemo(() => {
    const s = q.trim().toLowerCase()
    return (data?.domains ?? []).filter((d) => !s || d.domain.includes(s) || d.service.toLowerCase().includes(s))
  }, [data, q])

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-start gap-3">
        <RangePicker value={range} onChange={setRange} />
        <Select value={category ?? 'all'} onValueChange={(v) => setCategory(v === 'all' ? null : String(v))}>
          <SelectTrigger className="w-36"><SelectValue>{(v: string) => (v === 'all' ? '全部大类' : v)}</SelectValue></SelectTrigger>
          <SelectContent><SelectItem value="all">全部大类</SelectItem>{catalog?.categories.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent>
        </Select>
        <Select value={company ?? 'all'} onValueChange={(v) => setCompany(v === 'all' ? null : String(v))}>
          <SelectTrigger className="w-40"><SelectValue>{(v: string) => (v === 'all' ? '全部平台' : v)}</SelectValue></SelectTrigger>
          <SelectContent className="max-h-72"><SelectItem value="all">全部平台</SelectItem>{catalog?.companies.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent>
        </Select>
        <Tabs value={metric} onValueChange={(v) => setMetric(v as 'bytes' | 'requests')} className="ml-auto">
          <TabsList><TabsTrigger value="bytes">按流量</TabsTrigger><TabsTrigger value="requests">按请求次数</TabsTrigger></TabsList>
        </Tabs>
      </div>
      {error && <ErrorBox>{error}</ErrorBox>}
      {loading && !data && <Empty>分析中…</Empty>}
      {data && (
        <>
          <div className="rounded-xl border bg-gradient-to-br from-accent/60 to-card p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold"><Sparkles className="size-4 text-primary" />设备画像</div>
            {data.summary?.length ? (
              <ul className="grid gap-1 text-sm">{data.summary.map((s) => <li key={s}>· {s}</li>)}</ul>
            ) : <p className="text-sm text-muted-foreground">该时间段内还没有足够的数据。数据开始采集后，几分钟内就会出现。</p>}
            <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted-foreground">
              <span>流量 {bytes(data.bytes)}</span><span>DNS 请求 {data.requests.toLocaleString()} 次</span>
              {data.blocked > 0 && <span>被拦截 {data.blocked.toLocaleString()} 次</span>}<span>规则库 {data.rules_version}</span>
            </div>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <Section title="内容大类" desc="点击扇区可筛选">
              <div className="p-4"><Donut data={cats.map((c) => ({ name: c.name, value: metric === 'bytes' ? c.bytes : c.requests }))} format={fmt} selected={category} onSelect={setCategory} /></div>
            </Section>
            <Section title={category ? `${category} · 细分` : '细分类别'} desc={category ? undefined : '例如 视频 → 短视频 / 流媒体 / 直播，AI → 聊天助手 / 编程助手'}>
              <div className="p-4"><Donut data={((metric === 'bytes' ? data.subcategories : data.subcategories_by_req) ?? []).map((c) => ({ name: c.name, value: metric === 'bytes' ? c.bytes : c.requests, sub: category ? undefined : c.category }))} format={fmt} /></div>
            </Section>
            <Section title="服务 / 应用">
              <div className="p-4"><Donut data={svcs.map((s) => ({ name: s.name, value: metric === 'bytes' ? s.bytes : s.requests, sub: s.sub && s.sub !== s.category ? `${s.category} · ${s.sub}` : s.category, guess: s.guess, uncertain: s.uncertain }))} format={fmt} /></div>
            </Section>
            <Section title="平台（所属公司）" desc="点击可筛选">
              <div className="p-4"><Donut data={data.companies.map((c) => ({ name: c.name, value: c.bytes || c.requests }))} format={metric === 'bytes' ? bytes : fmt} selected={company} onSelect={setCompany} /></div>
            </Section>
            <Section title="访问目标所在国家 / 地区">
              <div className="p-4"><Donut data={data.countries.map((c) => ({ name: c.name, value: c.bytes }))} format={bytes} /></div>
            </Section>
          </div>
          <Section title="一天中的活跃时段" desc="按 DNS 请求次数">
            <div className="p-4"><HourBars data={data.requests_by_hour} format={(v) => `${v} 次`} /></div>
          </Section>
          <Section title="请求了哪些内容" desc="DNS 请求与流量合并统计，最多 300 条" action={
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input placeholder="域名 / 服务" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-44 pl-8" />
            </div>
          }>
            <Table>
              <TableHeader><TableRow>
                <TableHead className="pl-4">域名</TableHead><TableHead>识别为</TableHead><TableHead>大类</TableHead>
                <TableHead className="text-right">请求次数</TableHead><TableHead className="text-right">流量</TableHead><TableHead className="pr-4">最近</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {domains.map((d) => (
                  <TableRow key={d.domain}>
                    <TableCell className="max-w-72 truncate pl-4 font-mono text-xs">{d.domain}</TableCell>
                    <TableCell className="max-w-64"><TargetName name={d.service} guess={d.guess} uncertain={d.uncertain} />{d.company && d.company !== d.service && !d.uncertain && <span className="ml-1 text-xs text-muted-foreground">{d.company}</span>}</TableCell>
                    <TableCell><Pill tone={d.category === '广告追踪' ? 'red' : 'muted'}>{d.category}{d.sub && d.sub !== d.category ? ` · ${d.sub}` : ''}</Pill></TableCell>
                    <TableCell className="text-right tabular-nums">
                      {d.requests.toLocaleString()}
                      {d.blocked > 0 && <span className="ml-1 text-xs text-destructive" title={d.nextdns?.reasons ? `拦截原因：${d.nextdns.reasons}` : '被 DNS 拦截'}>（拦 {d.blocked}）</span>}
                      {d.nextdns?.reasons && <div className="truncate text-[10px] text-muted-foreground">{d.nextdns.reasons}</div>}
                      {d.nextdns?.tracker && <div className="text-[10px] text-warning">追踪器：{d.nextdns.tracker}</div>}
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-muted-foreground">{d.bytes ? bytes(d.bytes) : '–'}</TableCell>
                    <TableCell className="pr-4 text-xs text-muted-foreground">{datetime(d.last_seen)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {!domains.length && <Empty>暂无数据</Empty>}
          </Section>
        </>
      )}
    </div>
  )
}

function ProbeCell({ r }: { r: RemoteRow }) {
  const [p, setP] = useState<Probe | undefined>(r.probe)
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try { setP(await post<Probe>('/probe', { ip: r.ip, port: r.port, domain: '' })) } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  if (p) return <span className={p.status === 'failed' ? 'text-destructive' : ''} title={p.detail}>{p.summary}</span>
  return <Button variant="ghost" size="xs" disabled={busy} onClick={run}><Radar /> {busy ? '探测中…' : '模拟访问'}</Button>
}

function RemotesTab({ mac }: { mac: string }) {
  const [range, setRange] = useState<Range>(presetRange('today'))
  const { data, error } = useApi<ProfileResp>(`/devices/${encodeURIComponent(mac)}/profile?${qs(range)}`)
  const byLabel: Record<string, string> = { domain: '域名规则', keyword: '关键词', ip: 'IP 规则', asn: 'ASN', probe: '模拟访问' }
  return (
    <div className="grid gap-4">
      <RangePicker value={range} onChange={setRange} presets={['1h', 'today', '7d', '30d']} />
      {error && <ErrorBox>{error}</ErrorBox>}
      <Section title="连接目标" desc="按流量排序。规则库无法识别的目标可以「模拟访问」：读取证书、网页标题与反向解析来判断是什么（标注「模拟判定」）；拿不准的以灰色显示并归入「其他」，失败则记为「测试失败」。">
        <Table>
          <TableHeader><TableRow>
            <TableHead className="pl-4">目标</TableHead><TableHead>识别为</TableHead><TableHead>依据</TableHead><TableHead>国家</TableHead>
            <TableHead>运营商</TableHead><TableHead className="text-right">流量</TableHead><TableHead className="text-right">连接</TableHead><TableHead className="pr-4">探测</TableHead>
          </TableRow></TableHeader>
          <TableBody>
            {data?.remotes.map((r) => (
              <TableRow key={`${r.ip}|${r.port}|${r.proto}|${r.inbound}`}>
                <TableCell className="whitespace-nowrap pl-4 font-mono text-xs">
                  {r.inbound && <Pill tone="amber">入站</Pill>} {r.ip}:{r.port}<span className="ml-1 text-muted-foreground">{r.proto}</span>
                </TableCell>
                <TableCell className="max-w-64"><TargetName name={r.service} guess={r.guess} uncertain={r.uncertain} /><div className="text-xs text-muted-foreground">{r.category}{r.sub && r.sub !== r.category ? ` · ${r.sub}` : ''}</div></TableCell>
                <TableCell className="text-xs text-muted-foreground">{byLabel[r.by] ?? '—'}</TableCell>
                <TableCell>{r.country || '—'}</TableCell>
                <TableCell className="max-w-44 truncate text-muted-foreground">{r.as_org || '—'}</TableCell>
                <TableCell className="text-right tabular-nums">{bytes(r.bytes)}</TableCell>
                <TableCell className="text-right tabular-nums text-muted-foreground">{r.conns}</TableCell>
                <TableCell className="max-w-72 truncate pr-4 text-xs">{(r.guess || r.uncertain || r.probe) ? <ProbeCell r={r} /> : '—'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {data && !data.remotes.length && <Empty>暂无数据</Empty>}
      </Section>
    </div>
  )
}

function InfoDialog({ open, device, onClose, onSaved }: { open: boolean; device: Device; onClose: () => void; onSaved: () => void }) {
  const { data: types } = useApi<string[]>('/device-types')
  const [f, setF] = useState({ alias: device.alias, type: device.type_by === 'manual' ? device.type : '', note: device.note })
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try { await runAction('device.meta.save', { mac: device.mac, ...f }); onSaved() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent>
        <DialogHeader><DialogTitle>设备信息</DialogTitle></DialogHeader>
        <div className="grid gap-4">
          <Field label="显示名称（仅面板内使用）" hint={`留空则使用 DHCP 名称：${device.static_name || device.hostname || '无'}`}>
            <Input value={f.alias} maxLength={40} onChange={(e) => setF({ ...f, alias: e.target.value })} placeholder="例如：客厅电视、妈妈的手机" />
          </Field>
          <Field label="设备类型" hint={`自动识别为「${device.type}」`}>
            <select className="h-8 rounded-lg border bg-transparent px-2 text-sm" value={f.type} onChange={(e) => setF({ ...f, type: e.target.value })}>
              <option value="">自动识别</option>
              {types?.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </Field>
          <Field label="备注"><Input value={f.note} maxLength={200} onChange={(e) => setF({ ...f, note: e.target.value })} /></Field>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>取消</Button>
          <Button disabled={busy} onClick={save}>保存</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
