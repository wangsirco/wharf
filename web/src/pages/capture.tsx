import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, BarChart3, CheckCircle2, CircleDot, Download, FileSearch, Info, Loader2, Play, Square, Trash2, XCircle } from 'lucide-react'
import { post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import type { Device, ForwardTarget } from '@/lib/types'
import { bytes, datetime } from '@/lib/format'
import { cn } from '@/lib/utils'
import { DepHint } from '@/components/deps'
import { Empty, Field, Pill, Section, useConfirm } from '@/components/common'
import { DeviceSelect } from '@/components/pickers'
import { AreaChart } from '@/components/chart'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

interface Iface { name: string; label: string; hint: string }
interface Capture {
  id: string; iface: string; filter: string; note: string; by: string; snap: number; secs: number; max_mb: number
  started: number; ended?: number; size: number; packets: number; dropped: number; running: boolean; reason?: string; error?: string
}
interface NC { name: string; packets: number; bytes: number }
interface Conv {
  proto: string; a: string; b: string; service?: string; packets: number; bytes_ab: number; bytes_ba: number; start: number; dur: number
  state: string; syn_tries?: number; rtt_ms?: number; retrans?: number; dup_acks?: number; zero_win?: number; resets?: number; mss?: number; peer_mss?: number; sni?: string; reset_by?: string
}
interface DNSTx { ts: number; client: string; server: string; name: string; type: string; rcode: string; ms: number }
interface Analysis {
  id: string; packets: number; bytes: number; first: number; last: number; truncated: boolean; snap_cut: number
  protocols: NC[] | null; services: NC[] | null; timeline: { t: number; packets: number; bytes: number; retrans: number }[] | null; bucket: number
  hosts: { ip: string; sent: number; recv: number; packets: number; peers: number }[] | null; conversations: Conv[] | null
  tcp: { conns: number; handshakes: number; failed: number; reset: number; rtt_avg_ms: number; rtt_p50_ms: number; rtt_p95_ms: number; data_segments: number; retrans: number; retrans_rate: number; dup_acks: number; zero_win: number }
  dns: { queries: number; answered: number; no_answer: number; errors: NC[] | null; avg_ms: number; p95_ms: number; names: NC[] | null; slow: DNSTx[] | null; failures: DNSTx[] | null; resolvers: NC[] | null }
  tls_sni: NC[] | null; http_hosts: NC[] | null; icmp: { kind: string; from: string; about?: string; count: number }[] | null
  findings: { level: 'error' | 'warn' | 'info' | 'ok'; title: string; detail: string }[] | null; sizes: NC[] | null
}

const DURATIONS: [number, string][] = [[30, '30 秒'], [60, '1 分钟'], [300, '5 分钟'], [600, '10 分钟'], [1800, '30 分钟']]
const SIZES = [10, 20, 50, 100, 200]
const REASON: Record<string, string> = { time: '到时间自动停止', size: '达到大小上限', stopped: '手动停止', error: '出错' }

export function CaptureTool() {
  const { can } = useAuth()
  const { data, reload } = useApi<{ ifaces: Iface[] | null; captures: Capture[] | null }>('/tools/captures', 2000)
  const { data: devs } = useApi<Device[]>(can('devices.view') ? '/devices' : null, 60000)
  const targets: ForwardTarget[] | undefined = devs?.map((d) => ({ ip: d.ip, mac: d.mac, name: d.name, hostname: d.hostname, type: d.type, vendor: d.vendor, vm_tag: d.vm_tag, note: d.note, online: d.online }))
  const [f, setF] = useState({ iface: '', host: '', port: '', proto: '', filter: '', snap: 0, secs: 60, max_mb: 20, skip_panel: true, note: '' })
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState<string | null>(null)
  const { confirm, dialog } = useConfirm()
  const ifaces = data?.ifaces ?? []
  const iface = f.iface || ifaces[0]?.name || ''
  const caps = data?.captures ?? []
  const set = (p: Partial<typeof f>) => setF({ ...f, ...p })

  const start = async () => {
    setBusy(true)
    try {
      const c = await post<Capture>('/tools/captures', { ...f, iface, port: Number(f.port) || 0 })
      toast.success('开始抓包', { description: c.filter || '全部流量' }); reload()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const op = async (c: Capture, o: 'stop' | 'delete') => {
    if (o === 'delete' && !(await confirm('删除这个抓包？', '文件会从路由器上删除。', { danger: true, ok: '删除' }))) return
    try { await post(`/tools/captures/${c.id}/${o}`); if (o === 'stop') setOpen(c.id); if (open === c.id && o === 'delete') setOpen(null); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const wanSel = ifaces.find((i) => i.name === iface)?.label.startsWith('外网')

  return (
    <div className="grid gap-4">
      <Section title="抓包" desc="在路由器上用 tcpdump 抓包，自动分析连接质量、握手失败、重传、DNS、TLS 域名，并可下载 pcap 用 Wireshark 打开。抓包能看到通信内容，每次操作都记入审计">
        <DepHint ids={['tcpdump']} className="mx-4 mt-3" />
        <div className="grid gap-4 px-4 py-3">
          <Field label="抓哪个接口">
            <div className="grid gap-2 sm:grid-cols-3">
              {ifaces.slice(0, 3).map((i) => (
                <button key={i.name} type="button" onClick={() => set({ iface: i.name })}
                  className={cn('grid gap-0.5 rounded-xl border p-3 text-left transition-colors hover:border-primary/50', iface === i.name && 'border-primary bg-accent/40 ring-2 ring-primary/15')}>
                  <span className="text-sm font-medium">{i.label}</span><span className="text-[11px] text-muted-foreground">{i.hint}</span>
                </button>
              ))}
            </div>
            {ifaces.length > 3 && (
              <div className="flex flex-wrap gap-1.5 pt-1">{ifaces.slice(3).map((i) => <button key={i.name} type="button" onClick={() => set({ iface: i.name })} className={cn('rounded-md border px-2 py-0.5 font-mono text-xs', iface === i.name ? 'border-primary bg-accent' : 'text-muted-foreground hover:bg-muted')}>{i.name}</button>)}</div>
            )}
          </Field>
          <div className="grid gap-3 lg:grid-cols-2">
            <Field label={wanSel ? '对端 IP（外网接口上看不到内网设备 IP）' : '设备 / IP'} hint="留空 = 不限">
              {wanSel ? <Input value={f.host} onChange={(e) => set({ host: e.target.value.trim() })} placeholder="例如 91.108.56.130" className="font-mono" />
                : <DeviceSelect devices={targets} value={f.host} onChange={(ip) => set({ host: ip })} />}
              {f.host && <button type="button" className="justify-self-start text-[11px] text-muted-foreground hover:text-foreground" onClick={() => set({ host: '' })}>清除</button>}
            </Field>
            <div className="flex flex-wrap items-end gap-3">
              <Field label="端口" className="w-24"><Input value={f.port} inputMode="numeric" placeholder="不限" onChange={(e) => set({ port: e.target.value.replace(/\D/g, '') })} /></Field>
              <Field label="协议">
                <Tabs value={f.proto || 'all'} onValueChange={(v) => set({ proto: v === 'all' ? '' : String(v) })}>
                  <TabsList>{[['all', '全部'], ['tcp', 'TCP'], ['udp', 'UDP'], ['dns', 'DNS'], ['icmp', 'ICMP']].map(([k, l]) => <TabsTrigger key={k} value={k} className="px-2">{l}</TabsTrigger>)}</TabsList>
                </Tabs>
              </Field>
            </div>
          </div>
          <div className="grid gap-3 lg:grid-cols-2">
            <Field label="最长时间">
              <div className="flex flex-wrap gap-1.5">{DURATIONS.map(([s, l]) => <Chip key={s} on={f.secs === s} onClick={() => set({ secs: s })}>{l}</Chip>)}</div>
            </Field>
            <Field label="文件上限">
              <div className="flex flex-wrap gap-1.5">{SIZES.map((s) => <Chip key={s} on={f.max_mb === s} onClick={() => set({ max_mb: s })}>{s} MB</Chip>)}</div>
            </Field>
          </div>
          <details className="group rounded-lg border px-3 py-2">
            <summary className="cursor-pointer text-sm text-muted-foreground">高级选项</summary>
            <div className="grid gap-3 pt-3">
              <Field label="BPF 过滤表达式（与上面的条件同时生效）" hint="tcpdump 语法，例如 net 91.108.56.0/22、tcp[tcpflags] & tcp-syn != 0、not port 443">
                <Input value={f.filter} onChange={(e) => set({ filter: e.target.value })} className="font-mono text-xs" placeholder="可留空" />
              </Field>
              <Field label="每个包保存多少">
                <div className="flex flex-wrap gap-1.5">
                  <Chip on={f.snap === 0} onClick={() => set({ snap: 0 })}>完整数据包</Chip>
                  <Chip on={f.snap === 128} onClick={() => set({ snap: 128 })}>只抓包头（128 字节，隐私友好、文件小）</Chip>
                </div>
              </Field>
              <label className="flex items-center gap-2 text-sm"><Checkbox checked={f.skip_panel} onCheckedChange={(c) => set({ skip_panel: !!c })} />排除面板自己的流量（7080 / 7071 / SSH）</label>
              <Field label="备注"><Input value={f.note} maxLength={120} onChange={(e) => set({ note: e.target.value })} placeholder="例如：Telegram 发图卡顿复现" /></Field>
            </div>
          </details>
          <div><Button disabled={busy || !iface} onClick={start}>{busy ? <Loader2 className="animate-spin" /> : <Play />} 开始抓包</Button></div>
        </div>
      </Section>

      <Section title="抓包记录" desc="保存在路由器内存里（重启后清空），最多保留 12 个">
        {!caps.length ? <Empty>还没有抓包</Empty> : (
          <div className="divide-y">
            {caps.map((c) => <CaptureRow key={c.id} c={c} open={open === c.id} onOpen={() => setOpen(open === c.id ? null : c.id)} onOp={(o) => op(c, o)} />)}
          </div>
        )}
      </Section>
      {open && caps.find((c) => c.id === open && !c.running) && <AnalysisView key={open} id={open} />}
      {dialog}
    </div>
  )
}

function Chip({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return <button type="button" onClick={onClick} className={cn('rounded-md border px-2.5 py-1 text-xs', on ? 'border-primary bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted')}>{children}</button>
}

function CaptureRow({ c, open, onOpen, onOp }: { c: Capture; open: boolean; onOpen: () => void; onOp: (o: 'stop' | 'delete') => void }) {
  const [now, setNow] = useState(Date.now() / 1000)
  useEffect(() => { if (!c.running) return; const t = setInterval(() => setNow(Date.now() / 1000), 1000); return () => clearInterval(t) }, [c.running])
  const el = Math.max(0, (c.running ? now : c.ended ?? now) - c.started)
  const pct = c.running ? Math.min(100, Math.max((el / c.secs) * 100, (c.size / (c.max_mb << 20)) * 100)) : 100
  return (
    <div className={cn('grid gap-2 px-4 py-3', open && 'bg-accent/30')}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {c.running ? <CircleDot className="size-4 animate-pulse text-destructive" /> : c.error ? <XCircle className="size-4 text-destructive" /> : <CheckCircle2 className="size-4 text-success" />}
        <span className="font-mono text-xs">{c.iface}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" title={c.filter}>{c.filter || '全部流量'}</span>
        <span className="text-xs tabular-nums text-muted-foreground">{bytes(c.size)}{!c.running && c.packets ? ` · ${c.packets.toLocaleString()} 包` : ''}{c.dropped ? ` · 丢弃 ${c.dropped}` : ''}</span>
        <div className="flex">
          {c.running ? <Button size="sm" variant="outline" onClick={() => onOp('stop')}><Square /> 停止</Button> : (
            <>
              <Button size="sm" variant={open ? 'secondary' : 'ghost'} onClick={onOpen}><FileSearch /> 分析</Button>
              <a href={`/api/tools/captures/${c.id}/download`} className="inline-flex h-8 items-center gap-1 rounded-lg px-2.5 text-sm hover:bg-muted" title="下载 pcap（Wireshark）"><Download className="size-4" /></a>
              <Button size="icon-sm" variant="ghost" title="删除" onClick={() => onOp('delete')}><Trash2 /></Button>
            </>
          )}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 text-[11px] text-muted-foreground">
        <span>{datetime(c.started)}</span><span>{c.by}</span><span>{Math.floor(el / 60)}:{String(Math.floor(el % 60)).padStart(2, '0')}{c.running ? ` / ${Math.floor(c.secs / 60)}:${String(c.secs % 60).padStart(2, '0')}` : ''}</span>
        {c.snap > 0 && <span>只抓包头</span>}{c.reason && <span>{REASON[c.reason]}</span>}{c.note && <span className="text-foreground">{c.note}</span>}
        {c.error && <span className="text-destructive">{c.error}</span>}
      </div>
      {c.running && <div className="h-1 overflow-hidden rounded bg-muted"><div className="h-full bg-destructive/70 transition-all" style={{ width: `${pct}%` }} /></div>}
    </div>
  )
}

const LEVEL = {
  error: [XCircle, 'text-destructive', 'border-destructive/40 bg-destructive/5'],
  warn: [AlertTriangle, 'text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning', 'border-warning/40 bg-warning/5'],
  info: [Info, 'text-primary', ''],
  ok: [CheckCircle2, 'text-success', ''],
} as const

const STATE: Record<string, [string, 'red' | 'amber' | 'green' | 'muted' | 'blue']> = {
  ok: ['正常', 'green'], failed: ['握手失败', 'red'], refused: ['被拒绝', 'red'], reset: ['被重置', 'amber'], partial: ['抓包前已建立', 'muted'], udp: ['UDP', 'blue'],
}

function AnalysisView({ id }: { id: string }) {
  const { data, error } = useApi<Analysis>(`/tools/captures/${id}/analysis`)
  const [tab, setTab] = useState('conv')
  const [onlyBad, setOnlyBad] = useState(false)
  const convs = useMemo(() => (data?.conversations ?? []).filter((c) => !onlyBad || ['failed', 'refused', 'reset'].includes(c.state) || (c.retrans ?? 0) > 0), [data, onlyBad])
  if (error) return <Section title="分析"><Empty>{String(error)}</Empty></Section>
  if (!data) return <Section title="分析"><div className="flex items-center gap-2 px-4 py-8 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />正在分析…</div></Section>
  const dur = Math.max(0.001, data.last - data.first)
  const t = data.tcp
  const attempts = t.handshakes + t.failed
  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <Kpi label="数据包" value={data.packets.toLocaleString()} sub={`${bytes(data.bytes)} · ${dur < 60 ? `${dur.toFixed(1)} 秒` : `${(dur / 60).toFixed(1)} 分钟`}`} />
        <Kpi label="平均速率" value={`${((data.bytes * 8) / dur / 1e6).toFixed(2)} Mbps`} sub={`${Math.round(data.packets / dur)} 包/秒`} />
        <Kpi label="TCP 握手成功" value={attempts ? `${t.handshakes}/${attempts}` : '–'} tone={t.failed && attempts && t.failed / attempts >= 0.1 ? 'red' : undefined} sub={t.failed ? `${t.failed} 个失败` : '无失败'} />
        <Kpi label="握手延迟" value={t.handshakes ? `${t.rtt_p50_ms.toFixed(0)} ms` : '–'} sub={t.handshakes ? `P95 ${t.rtt_p95_ms.toFixed(0)} ms` : ''} />
        <Kpi label="TCP 重传率" value={t.data_segments ? `${(t.retrans_rate * 100).toFixed(2)}%` : '–'} tone={t.retrans_rate >= 0.05 ? 'red' : t.retrans_rate >= 0.01 ? 'amber' : undefined} sub={`${t.retrans} / ${t.data_segments} 段`} />
        <Kpi label="DNS" value={data.dns.queries ? `${data.dns.avg_ms.toFixed(0)} ms` : '–'} sub={data.dns.queries ? `${data.dns.queries} 次查询${data.dns.no_answer ? ` · ${data.dns.no_answer} 无应答` : ''}` : '无查询'} />
      </div>

      <Section title="诊断结论" desc="类似 Wireshark 的「专家信息」，按严重程度排序">
        <div className="divide-y">
          {(data.findings ?? []).map((f, i) => {
            const [Icon, tone, bg] = LEVEL[f.level]
            return (
              <div key={i} className={cn('flex gap-3 px-4 py-2.5', bg)}>
                <Icon className={cn('mt-0.5 size-4 shrink-0', tone)} />
                <div className="min-w-0"><div className="text-sm font-medium">{f.title}</div><div className="text-xs text-muted-foreground">{f.detail}</div></div>
              </div>
            )
          })}
        </div>
      </Section>

      {(data.timeline?.length ?? 0) > 1 && (
        <Section title="时间线" desc={`每 ${data.bucket} 秒一个点`}>
          <div className="p-3">
            <AreaChart height={150} times={data.timeline!.map((p) => p.t)} format={(v) => `${((v * 8) / data.bucket / 1e6).toFixed(2)} Mbps`}
              series={[{ label: '流量', color: '#3b82f6', values: data.timeline!.map((p) => p.bytes) }]} />
            {data.timeline!.some((p) => p.retrans) && (
              <div className="mt-2 flex h-8 items-end gap-px" title="重传">
                {data.timeline!.map((p) => <div key={p.t} className="min-w-px flex-1 bg-destructive/70" style={{ height: `${p.retrans ? Math.max(10, Math.min(100, p.retrans * 10)) : 0}%` }} />)}
              </div>
            )}
          </div>
        </Section>
      )}

      <Section title="详情" action={<Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
        <TabsList>{[['conv', '会话'], ['proto', '协议'], ['hosts', '主机'], ['dns', 'DNS'], ['tls', '域名'], ['icmp', 'ICMP']].map(([k, l]) => <TabsTrigger key={k} value={k} className="px-2.5">{l}</TabsTrigger>)}</TabsList>
      </Tabs>}>
        {tab === 'conv' && (
          <>
            <div className="flex items-center gap-2 border-b px-4 py-2 text-xs">
              <label className="flex items-center gap-1.5"><Checkbox checked={onlyBad} onCheckedChange={(c) => setOnlyBad(!!c)} />只看有问题的（握手失败 / 重置 / 重传）</label>
              <span className="ml-auto text-muted-foreground">按问题和流量排序，最多 200 条</span>
            </div>
            {!convs.length ? <Empty>没有会话</Empty> : (
              <div className="max-h-[560px] divide-y overflow-auto">
                {convs.map((c, i) => {
                  const [label, tone] = STATE[c.state] ?? [c.state, 'muted']
                  return (
                    <div key={i} className="grid gap-1 px-4 py-2 text-xs sm:grid-cols-[5.5rem_minmax(0,1fr)_minmax(0,0.9fr)] sm:items-center">
                      <div className="flex items-center gap-1.5"><Pill tone={tone}>{label}</Pill></div>
                      <div className="min-w-0">
                        <div className="truncate font-mono">{c.a} → {c.b}</div>
                        <div className="truncate text-muted-foreground">{c.proto} · {c.service}{c.sni ? ` · ${c.sni}` : ''}</div>
                      </div>
                      <div className="flex flex-wrap gap-x-3 text-muted-foreground sm:justify-end">
                        <span>↑{bytes(c.bytes_ab)} ↓{bytes(c.bytes_ba)}</span>
                        {c.rtt_ms ? <span>握手 {c.rtt_ms.toFixed(0)} ms</span> : null}
                        {c.syn_tries && c.syn_tries > 1 ? <span className="text-destructive">SYN ×{c.syn_tries}</span> : null}
                        {c.retrans ? <span className="text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning">重传 {c.retrans}</span> : null}
                        {c.zero_win ? <span>零窗口 {c.zero_win}</span> : null}
                        {c.reset_by ? <span>RST 来自 {c.reset_by}</span> : null}
                        {c.mss && c.peer_mss ? <span>MSS {c.mss}/{c.peer_mss}</span> : null}
                        <span>{c.dur.toFixed(1)}s</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </>
        )}
        {tab === 'proto' && (
          <div className="grid gap-6 p-4 lg:grid-cols-3">
            <BarList title="网络层协议" items={data.protocols} total={data.bytes} />
            <BarList title="服务 / 端口" items={data.services} total={data.bytes} />
            <BarList title="包大小分布" items={data.sizes} total={data.packets} byPackets />
          </div>
        )}
        {tab === 'hosts' && (
          <div className="max-h-[520px] divide-y overflow-auto">
            {(data.hosts ?? []).map((h) => (
              <div key={h.ip} className="flex items-center gap-3 px-4 py-2 text-xs">
                <span className="min-w-0 flex-1 truncate font-mono">{h.ip}</span>
                <span className="text-muted-foreground">{h.peers} 个对端</span>
                <span className="w-24 text-right tabular-nums">↑ {bytes(h.sent)}</span>
                <span className="w-24 text-right tabular-nums">↓ {bytes(h.recv)}</span>
              </div>
            ))}
          </div>
        )}
        {tab === 'dns' && (
          <div className="grid gap-5 p-4 lg:grid-cols-2">
            <div className="grid content-start gap-2 text-xs">
              <div className="text-sm font-medium">概况</div>
              <div className="text-muted-foreground">{data.dns.queries} 次查询 · {data.dns.answered} 次成功 · {data.dns.no_answer} 次无应答 · 平均 {data.dns.avg_ms.toFixed(0)} ms · P95 {data.dns.p95_ms.toFixed(0)} ms</div>
              {!!data.dns.errors?.length && <div className="flex flex-wrap gap-1.5">{data.dns.errors.map((e) => <Pill key={e.name} tone="amber">{e.name} ×{e.packets}</Pill>)}</div>}
              {!!data.dns.resolvers?.length && <div className="text-muted-foreground">DNS 服务器：{data.dns.resolvers.map((r) => `${r.name}（${r.packets}）`).join('、')}</div>}
              <BarList title="查询最多的域名" items={data.dns.names} total={data.dns.queries} byPackets />
            </div>
            <div className="grid content-start gap-4">
              <DNSList title="失败的查询" list={data.dns.failures} />
              <DNSList title="慢查询（>300 ms）" list={data.dns.slow} />
            </div>
          </div>
        )}
        {tab === 'tls' && (
          <div className="grid gap-6 p-4 lg:grid-cols-2">
            <BarList title="HTTPS 访问的域名（TLS SNI）" items={data.tls_sni} total={(data.tls_sni ?? []).reduce((a, x) => a + x.packets, 0)} byPackets unit="次连接" />
            <BarList title="HTTP 明文访问的域名" items={data.http_hosts} total={(data.http_hosts ?? []).reduce((a, x) => a + x.packets, 0)} byPackets unit="次连接" />
          </div>
        )}
        {tab === 'icmp' && (!data.icmp?.length ? <Empty>没有 ICMP 消息</Empty> : (
          <div className="divide-y">
            {data.icmp.map((m, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2 text-xs">
                <span className="w-40 shrink-0">{m.kind}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-muted-foreground">{m.from}{m.about ? ` → 关于 ${m.about}` : ''}</span>
                <span className="tabular-nums">×{m.count}</span>
              </div>
            ))}
          </div>
        ))}
      </Section>
    </div>
  )
}

function Kpi({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: 'red' | 'amber' }) {
  return (
    <div className="min-w-0 rounded-xl border bg-card p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={cn('mt-1 truncate text-lg font-semibold tabular-nums', tone === 'red' && 'text-destructive', tone === 'amber' && 'text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning')}>{value}</div>
      {sub && <div className="truncate text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  )
}

function BarList({ title, items, total, byPackets, unit }: { title: string; items: NC[] | null | undefined; total: number; byPackets?: boolean; unit?: string }) {
  const list = items ?? []
  return (
    <div className="grid content-start gap-1.5">
      <div className="flex items-center gap-1.5 text-sm font-medium"><BarChart3 className="size-3.5 text-muted-foreground" />{title}</div>
      {!list.length ? <div className="text-xs text-muted-foreground">无</div> : list.slice(0, 20).map((x) => {
        const v = byPackets ? x.packets : x.bytes
        return (
          <div key={x.name} className="grid gap-0.5 text-xs">
            <div className="flex gap-2"><span className="min-w-0 flex-1 truncate">{x.name}</span><span className="tabular-nums text-muted-foreground">{byPackets ? `${x.packets.toLocaleString()}${unit ? ` ${unit}` : ''}` : bytes(x.bytes)}</span></div>
            <div className="h-1.5 rounded bg-muted"><div className="h-full rounded bg-primary/60" style={{ width: `${total ? Math.max(1, (v / total) * 100) : 0}%` }} /></div>
          </div>
        )
      })}
    </div>
  )
}

function DNSList({ title, list }: { title: string; list: DNSTx[] | null | undefined }) {
  return (
    <div className="grid gap-1">
      <div className="text-sm font-medium">{title}</div>
      {!list?.length ? <div className="text-xs text-muted-foreground">无</div> : list.slice(0, 30).map((d, i) => (
        <div key={i} className="flex gap-2 text-xs">
          <span className="min-w-0 flex-1 truncate font-mono">{d.name} <span className="text-muted-foreground">{d.type}</span></span>
          <span className="text-muted-foreground">{d.client}</span>
          <span className={cn('w-20 text-right', d.rcode !== 'NOERROR' && 'text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning')}>{d.rcode !== 'NOERROR' ? d.rcode : `${d.ms.toFixed(0)} ms`}</span>
        </div>
      ))}
    </div>
  )
}
