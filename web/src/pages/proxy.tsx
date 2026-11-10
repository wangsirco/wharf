import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import qrcode from 'qrcode-generator'
import {
  Anchor, ArrowDown, ArrowUp, Ban, Download, Globe2, KeyRound, Link2, Loader2, MapPin, Pencil, Plus, QrCode, RefreshCw, Search,
  Server, ShieldCheck, Trash2, Users as UsersIcon, Zap,
} from 'lucide-react'
import { api, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { runAction } from '@/lib/actions'
import { ago, bitrate, bytes, datetime } from '@/lib/format'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Dot, Empty, ErrorBox, Field, HalfPanel, Pill, Section, useConfirm } from '@/components/common'
import { AreaChart } from '@/components/chart'
import { CopyText } from '@/pages/diag'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'

// ---- types ----

interface Params {
  flow?: string; target?: string; server_names?: string[]; private_key?: string; public_key?: string; short_ids?: string[]
  fingerprint?: string; cert?: 'acme' | 'self'; path?: string; xhttp_mode?: string; ss_method?: string; ss_key?: string
}
interface PNode {
  id: number; owner_id: number; owner_name?: string; name: string; enabled: boolean
  protocol: string; transport: string; security: string; entry: 'sni' | 'port'; port: number; wan: string; domain: string
  params: Params; note: string; created: number; updated: number
}
interface PUser {
  id: number; owner_id: number; owner_name?: string; name: string; secret: string; sub_token: string; nodes: number[]
  limit_bytes: number; reset_day: number; expire_at: number; ip_limit: number; allow_lan: boolean; enabled: boolean
  stopped: '' | 'quota' | 'expired'; used_up: number; used_down: number; period_at: number; note: string; created: number
}
interface Ext {
  installed: boolean; version: string; previous: string; on_disk: string[] | null; asset: string; dir: string; free_mb: number
  running: Record<string, boolean>; configured: boolean; system_xray: string
  job: { running: boolean; action: string; tag: string; log: string[] | null; error: string; ended: number }
}
interface Settings {
  address: string; site: { mode: 'builtin' | 'html' | 'proxy'; proxy: string; title: string; domain: string }
  acme_email: string; block_bt: boolean; block_ports: number[] | null; block_hosts: string[] | null; access_days: number
  share_443: '' | 'cloudflare' | 'takeover'; share_skip: string[] | null; takeover_443?: boolean; takeover_proxy: boolean
  share_port?: number
}
interface Cert { domain: string; issuer: string; not_after: number; self_signed: boolean; status?: string }
interface ProxyResp {
  ext: Ext; nodes: PNode[]; users: PUser[]; host: string; quota: { nodes: number; users: number }
  front: { port: number; site_domain: string; share_port?: number; firewall?: string }; settings?: Settings; site_html?: string; certs?: Cert[] | null
  port443?: { forward: string; target: string; adopted: boolean }
  berth_sni?: { target: string; domains: string[]; proxy_protocol: boolean }
}
interface Rate { up: number; down: number }
interface OnlineIP { ip: string; seen: number; country: string; city: string; as_org: string; nodes: number[] | null }
interface Live { ts: number; total: Rate; nodes: Record<string, Rate>; users: Record<string, Rate>; online: Record<string, OnlineIP[]> }
interface Stats {
  since: number; series: Record<string, { hour: number; up: number; down: number }[]>
  nodes: Record<string, Rate>; users: Record<string, Rate>; today: Rate; month: Rate; range: Rate
}

// ---- labels ----

const PROTO: Record<string, string> = { vless: 'VLESS', vmess: 'VMess', trojan: 'Trojan', shadowsocks: 'Shadowsocks 2022', hysteria: 'Hysteria 2' }
const TRANSPORT: Record<string, string> = { raw: 'RAW (TCP)', xhttp: 'XHTTP', ws: 'WebSocket', grpc: 'gRPC', httpupgrade: 'HTTPUpgrade', hysteria: 'QUIC' }
const SECURITY: Record<string, string> = { reality: 'REALITY', tls: 'TLS', none: '无加密' }

function nodeDesc(n: PNode) {
  const parts = [PROTO[n.protocol] ?? n.protocol]
  if (n.transport !== 'raw' && n.transport !== 'hysteria') parts.push(TRANSPORT[n.transport] ?? n.transport)
  if (n.security !== 'none' && n.protocol !== 'hysteria') parts.push(SECURITY[n.security])
  if (n.params.flow) parts.push('Vision')
  return parts.join(' + ')
}
const entryDesc = (n: PNode) => (n.entry === 'sni' ? `${n.port} 分流 · ${n.security === 'reality' ? (n.params.server_names ?? []).join(', ') : n.domain}` : `${n.wan ? n.wan + ':' : ''}${n.port}${n.protocol === 'hysteria' ? ' UDP' : n.protocol === 'shadowsocks' ? ' TCP+UDP' : ''}`)

const userState = (u: PUser): [string, 'green' | 'amber' | 'red' | 'muted'] => {
  if (!u.enabled) return ['已停用', 'muted']
  if (u.stopped === 'quota') return ['流量用完', 'red']
  if (u.stopped === 'expired' || (u.expire_at && u.expire_at * 1000 < Date.now())) return ['已到期', 'red']
  if (u.expire_at && u.expire_at * 1000 - Date.now() < 7 * 86400e3) return ['即将到期', 'amber']
  return ['正常', 'green']
}

const GB = 1024 ** 3

// ---- page ----

const TABS: [string, string][] = [['overview', '概览'], ['nodes', '节点'], ['users', '用户'], ['access', '访问记录'], ['settings', '扩展设置']]

export default function ProxyPage() {
  const { isSuper } = useAuth()
  const { data, error, reload } = useApi<ProxyResp>('/proxy', 15000)
  const saved = (() => { try { return localStorage.getItem('owp-proxy-tab') } catch { return null } })()
  const [tab, setTab] = useState(saved && TABS.some(([k]) => k === saved) ? saved : 'overview')
  const pick = (v: string) => { setTab(v); try { localStorage.setItem('owp-proxy-tab', v) } catch { /* private mode */ } }
  const tabs = TABS.filter(([k]) => k !== 'settings' || isSuper)

  if (error) return <><PageHeader title="代理" /><ErrorBox>{error}</ErrorBox></>
  if (!data) return <><PageHeader title="代理" /><Empty>加载中…</Empty></>
  if (!data.ext.installed || (data.ext.job.running && data.ext.job.action === 'install' && !data.ext.version)) {
    return <><PageHeader title="代理" desc="在路由器上直接搭建代理节点，给自己和朋友用" /><Install data={data} reload={reload} /></>
  }
  const xrayUp = data.ext.running.xray
  return (
    <>
      <PageHeader title="代理" desc={`Xray ${data.ext.version} · ${xrayUp ? '运行中' : data.nodes.some((n) => n.enabled) ? '未运行' : '没有启用的节点'}${data.ext.running.front ? ` · ${data.front.share_port ?? 443} 分流运行中` : ''}`}>
        <Tabs value={tab} onValueChange={(v) => pick(String(v))}>
          <TabsList>{tabs.map(([k, l]) => <TabsTrigger key={k} value={k} className="px-3">{l}</TabsTrigger>)}</TabsList>
        </Tabs>
      </PageHeader>
      {tab === 'overview' && <Overview data={data} />}
      {tab === 'nodes' && <Nodes data={data} reload={reload} />}
      {tab === 'users' && <ProxyUsers data={data} reload={reload} />}
      {tab === 'access' && <Access data={data} />}
      {tab === 'settings' && isSuper && <ExtSettings data={data} reload={reload} />}
    </>
  )
}

// ---- install ----

interface Release { tag: string; prerelease: boolean; published: string; url: string; supported: boolean }

function VersionPicker({ value, onChange, current }: { value: string; onChange: (t: string) => void; current?: string }) {
  const { data, error, reload } = useApi<{ releases: Release[] | null; min: string }>('/proxy/versions')
  const list = (data?.releases ?? []).filter((r) => r.supported)
  const stable = list.find((r) => !r.prerelease)
  useEffect(() => { if (!value && stable) onChange(stable.tag) }, [stable, value, onChange])
  if (error) return <ErrorBox>读取 Xray 版本列表失败：{error} <button type="button" className="underline" onClick={reload}>重试</button></ErrorBox>
  if (!data) return <p className="text-sm text-muted-foreground"><Loader2 className="mr-1 inline size-4 animate-spin" />正在从 GitHub 读取 Xray 官方版本…</p>
  return (
    <div className="grid gap-1.5">
      {list.slice(0, 10).map((r) => (
        <button key={r.tag} type="button" onClick={() => onChange(r.tag)}
          className={cn('flex items-center gap-3 rounded-lg border px-3 py-2 text-left text-sm', value === r.tag ? 'border-primary bg-accent' : 'hover:bg-muted')}>
          <span className="font-mono font-medium">{r.tag}</span>
          {r.prerelease ? <Pill tone="amber">预发布</Pill> : <Pill tone="green">正式版</Pill>}
          {r.tag === stable?.tag && <Pill tone="blue">推荐</Pill>}
          {r.tag === current && <Pill>正在使用</Pill>}
          <span className="ml-auto text-xs text-muted-foreground">{r.published.slice(0, 10)}</span>
        </button>
      ))}
      <p className="text-xs text-muted-foreground">只列出 {data.min} 及更新的版本（面板生成的配置需要）。预发布版带来新功能，但可能有兼容问题；切换前面板会先用新版本检查现有配置，启动失败会自动退回。</p>
    </div>
  )
}

function JobLog({ ext }: { ext: Ext }) {
  const log = ext.job.log ?? []
  if (!log.length) return null
  return (
    <div className="max-h-56 overflow-auto rounded-lg bg-muted/60 p-3 font-mono text-[11px] leading-5">
      {log.map((l, i) => <div key={i}>{l}</div>)}
      {ext.job.running && <div className="text-muted-foreground"><Loader2 className="mr-1 inline size-3 animate-spin" />进行中…</div>}
    </div>
  )
}

function useJobWatch(ext: Ext | undefined, reload: () => void) {
  const running = !!ext?.job.running
  useEffect(() => {
    if (!running) return
    const t = window.setInterval(reload, 1500)
    return () => clearInterval(t)
  }, [running, reload])
}

function Install({ data, reload }: { data: ProxyResp; reload: () => void }) {
  const { isSuper } = useAuth()
  const [tag, setTag] = useState('')
  const [busy, setBusy] = useState(false)
  useJobWatch(data.ext, reload)
  const ext = data.ext
  useEffect(() => {
    // the core is in place: push the stored nodes (if any) to it
    if (ext.installed && !ext.job.running && ext.job.action === 'install' && !ext.job.error && data.nodes.length && !ext.configured) {
      post('/proxy/activate').then(reload).catch(() => {})
    }
  }, [ext.installed, ext.job.running, ext.job.action, ext.job.error, ext.configured, data.nodes.length, reload])
  if (!isSuper) return <Section title="代理扩展还没有安装"><Empty>请超级管理员在这里安装代理扩展后再使用。</Empty></Section>
  const install = async () => {
    setBusy(true)
    try { await post('/proxy/ext', { action: 'install', tag }); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <div className="grid items-start gap-4 lg:grid-cols-[1fr_22rem]">
      <Section title="安装代理扩展" desc="一键在路由器上运行 Xray 服务端：VLESS / REALITY / XTLS / Trojan / Hysteria 2 / Shadowsocks 2022 都支持">
        <div className="grid gap-4 p-4">
          <VersionPicker value={tag} onChange={setTag} />
          <JobLog ext={ext} />
          {ext.job.error && !ext.job.running && <ErrorBox>{ext.job.error}</ErrorBox>}
          <div className="flex items-center gap-3">
            <Button onClick={install} disabled={!tag || busy || ext.job.running}>{ext.job.running ? <Loader2 className="animate-spin" /> : <Download />} 安装 Xray {tag}</Button>
            <span className="text-xs text-muted-foreground">约 13 MB · 从 XTLS/Xray-core 官方 GitHub 下载并校验</span>
          </div>
        </div>
      </Section>
      <Section title="它是怎么装的">
        <ul className="grid gap-2.5 p-4 text-sm text-muted-foreground">
          <li><b className="text-foreground">不改动系统。</b>内核装在 <code className="text-xs">{ext.dir}</code>，以无特权的 nobody 用户运行；系统里 PassWall / OpenClash 自带的 xray{ext.system_xray ? `（${ext.system_xray.replace(/\s*\(.*$/, '')}）` : ''}不受影响。</li>
          <li><b className="text-foreground">官方原版。</b>直接下载 XTLS/Xray-core 发布的文件，用官方的 SHA-256 校验，不经第三方。</li>
          <li><b className="text-foreground">防火墙联动。</b>建节点时自动放行端口并检查冲突；也可以让多个节点共用公网 443，按域名（SNI）分流。</li>
          <li><b className="text-foreground">随时卸载。</b>卸载扩展或卸载面板时，内核、配置、防火墙规则全部清除。</li>
        </ul>
      </Section>
    </div>
  )
}

// ---- overview (big screen) ----

function Overview({ data }: { data: ProxyResp }) {
  const { data: live } = useApi<Live>('/proxy/live', 3000)
  const [range, setRange] = useState('24h')
  const { data: stats } = useApi<Stats>(`/proxy/stats?range=${range}`, 60000)
  const [hist, setHist] = useState<{ t: number; up: number; down: number }[]>([])
  useEffect(() => {
    if (!live) return
    setHist((h) => (h.length && h[h.length - 1].t === live.ts ? h : [...h.slice(-119), { t: live.ts, up: live.total.up, down: live.total.down }]))
  }, [live])
  const nodes = data.nodes
  const userName = (id: number) => data.users.find((u) => u.id === id)?.name ?? `#${id}`
  const nodeName = (id: number) => nodes.find((n) => n.id === id)?.name ?? `#${id}`
  const onlineUsers = Object.entries(live?.online ?? {})
  const onlineIPs = onlineUsers.reduce((a, [, ips]) => a + ips.length, 0)
  const series = useMemo(() => {
    const hours = new Map<number, Rate>()
    for (const pts of Object.values(stats?.series ?? {})) for (const p of pts) {
      const r = hours.get(p.hour) ?? { up: 0, down: 0 }
      r.up += p.up; r.down += p.down; hours.set(p.hour, r)
    }
    return [...hours.entries()].sort((a, b) => a[0] - b[0])
  }, [stats])
  const topUsers = Object.entries(stats?.users ?? {}).map(([id, r]) => ({ id: Number(id), total: r.up + r.down, ...r })).sort((a, b) => b.total - a.total).slice(0, 8)
  const maxUser = Math.max(1, ...topUsers.map((u) => u.total))

  return (
    <div className="grid gap-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Kpi label="当前下行" icon={<ArrowDown className="size-3.5" />} value={live ? bitrate(live.total.down) : '–'} sub="所有节点合计" accent />
        <Kpi label="当前上行" icon={<ArrowUp className="size-3.5" />} value={live ? bitrate(live.total.up) : '–'} sub="所有节点合计" />
        <Kpi label="今日用量" value={stats ? bytes(stats.today.up + stats.today.down) : '–'} sub={stats ? `↓ ${bytes(stats.today.down)} · ↑ ${bytes(stats.today.up)}` : ''} />
        <Kpi label="本月用量" value={stats ? bytes(stats.month.up + stats.month.down) : '–'} sub={stats ? `↓ ${bytes(stats.month.down)} · ↑ ${bytes(stats.month.up)}` : ''} />
        <Kpi label="在线" value={`${onlineUsers.length} 人`} sub={`${onlineIPs} 个 IP · ${nodes.filter((n) => n.enabled).length}/${nodes.length} 个节点启用`} />
      </div>

      <Section title="实时速率" desc="最近 6 分钟，每 3 秒一次">
        <div className="p-4">
          {hist.length > 1 ? (
            <AreaChart height={150} times={hist.map((h) => h.t)} format={(v) => bitrate(v)}
              series={[{ label: '下行', color: 'var(--chart-1)', values: hist.map((h) => h.down) }, { label: '上行', color: 'var(--chart-2)', values: hist.map((h) => h.up) }]} />
          ) : <div className="flex h-[150px] items-center justify-center text-sm text-muted-foreground">正在采集…</div>}
        </div>
      </Section>

      <Section title="节点" desc="每个节点当前的上下行速率与所选时段用量">
        {!nodes.length ? <Empty>还没有节点。到「节点」里添加第一个。</Empty> : (
          <div className="grid gap-px bg-border sm:grid-cols-2 xl:grid-cols-3">
            {nodes.map((n) => {
              const r = live?.nodes[n.id], used = stats?.nodes[n.id]
              const users = new Set(Object.entries(live?.online ?? {}).filter(([, ips]) => ips.some((ip) => ip.nodes?.includes(n.id))).map(([u]) => u)).size
              return (
                <div key={n.id} className="bg-card p-4">
                  <div className="flex items-center gap-2">
                    <Dot tone={!n.enabled ? 'off' : data.ext.running.xray ? 'ok' : 'bad'} />
                    <span className="truncate font-medium">{n.name}</span>
                    {users > 0 && <Pill tone="green">{users} 人在线</Pill>}
                  </div>
                  <div className="mt-0.5 truncate text-xs text-muted-foreground">{nodeDesc(n)} · {entryDesc(n)}</div>
                  <div className="mt-3 grid grid-cols-3 gap-2 text-xs tabular-nums">
                    <div><div className="text-muted-foreground">↓ 下行</div><div className="text-sm font-semibold">{r ? bitrate(r.down) : '0 bps'}</div></div>
                    <div><div className="text-muted-foreground">↑ 上行</div><div className="text-sm font-semibold">{r ? bitrate(r.up) : '0 bps'}</div></div>
                    <div><div className="text-muted-foreground">{range} 用量</div><div className="text-sm font-semibold">{used ? bytes(used.up + used.down) : '0 B'}</div></div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Section>

      <div className="grid items-start gap-4 xl:grid-cols-2">
        <Section title="用量趋势" action={
          <Tabs value={range} onValueChange={(v) => setRange(String(v))}>
            <TabsList>{[['24h', '24 小时'], ['7d', '7 天'], ['30d', '30 天']].map(([k, l]) => <TabsTrigger key={k} value={k} className="px-3">{l}</TabsTrigger>)}</TabsList>
          </Tabs>
        }>
          <div className="p-4">
            {series.length > 1 ? (
              <AreaChart height={170} times={series.map(([h]) => h)} format={(v) => bytes(v)}
                series={[{ label: '下行', color: 'var(--chart-1)', values: series.map(([, r]) => r.down) }, { label: '上行', color: 'var(--chart-2)', values: series.map(([, r]) => r.up) }]} />
            ) : <Empty>这段时间还没有流量</Empty>}
            {topUsers.length > 0 && (
              <div className="mt-4 grid gap-2">
                <div className="text-xs font-medium text-muted-foreground">用量最多的用户</div>
                {topUsers.map((u) => (
                  <div key={u.id} className="grid grid-cols-[7rem_1fr_5rem] items-center gap-2 text-xs">
                    <span className="truncate">{userName(u.id)}</span>
                    <div className="h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary/70" style={{ width: `${(u.total / maxUser) * 100}%` }} /></div>
                    <span className="text-right tabular-nums text-muted-foreground">{bytes(u.total)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Section>

        <Section title="正在连接" desc="谁在用、从哪里连进来">
          {!onlineUsers.length ? <Empty>现在没有人在用</Empty> : (
            <div className="divide-y">
              {onlineUsers.map(([uid, ips]) => {
                const r = live?.users[uid]
                return (
                  <div key={uid} className="px-4 py-3">
                    <div className="flex items-center gap-2 text-sm">
                      <Dot tone="ok" /><span className="font-medium">{userName(Number(uid))}</span>
                      <span className="ml-auto text-xs tabular-nums text-muted-foreground">{r ? `↓ ${bitrate(r.down)} · ↑ ${bitrate(r.up)}` : ''}</span>
                    </div>
                    <div className="mt-1.5 grid gap-1">
                      {ips.map((ip) => (
                        <div key={ip.ip} className="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
                          <span className="font-mono text-foreground">{ip.ip}</span>
                          <span><MapPin className="mr-0.5 inline size-3" />{[ip.city, ip.country].filter(Boolean).join(' · ') || '未知位置'}</span>
                          {ip.as_org && <span className="truncate">{ip.as_org}</span>}
                          <span className="ml-auto">{(ip.nodes ?? []).map(nodeName).join('、')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </Section>
      </div>
    </div>
  )
}

function Kpi({ label, value, sub, icon, accent }: { label: string; value: string; sub?: string; icon?: React.ReactNode; accent?: boolean }) {
  return (
    <div className={cn('rounded-xl border bg-card p-3.5', accent && 'border-primary/30')}>
      <div className="flex items-center gap-1 text-xs text-muted-foreground">{icon}{label}</div>
      <div className="mt-1 text-xl font-semibold tabular-nums tracking-tight">{value}</div>
      {sub && <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  )
}

// ---- nodes ----

type NodeForm = Omit<PNode, 'id' | 'owner_id' | 'created' | 'updated'> & { id?: number }

const PRESETS: { key: string; label: string; desc: string; v: Partial<NodeForm> }[] = [
  { key: 'reality', label: 'VLESS + REALITY + Vision', desc: '推荐。不需要域名和证书，伪装成访问大网站', v: { protocol: 'vless', transport: 'raw', security: 'reality', entry: 'sni' } },
  { key: 'reality-xhttp', label: 'VLESS + REALITY + XHTTP', desc: '另一种流量形态，适合 Vision 被干扰时', v: { protocol: 'vless', transport: 'xhttp', security: 'reality', entry: 'port', port: 8443 } },
  { key: 'tls', label: 'VLESS + TLS + Vision', desc: '用你自己的域名和正规证书（自动申请）', v: { protocol: 'vless', transport: 'raw', security: 'tls', entry: 'sni' } },
  { key: 'ws', label: 'VLESS + WebSocket + TLS', desc: '可以套 Cloudflare 等 CDN', v: { protocol: 'vless', transport: 'ws', security: 'tls', entry: 'port', port: 2053 } },
  { key: 'trojan', label: 'Trojan + TLS', desc: '兼容性最好的客户端协议之一', v: { protocol: 'trojan', transport: 'raw', security: 'tls', entry: 'sni' } },
  { key: 'hy2', label: 'Hysteria 2', desc: 'UDP（QUIC），弱网和高丢包线路更快', v: { protocol: 'hysteria', transport: 'hysteria', security: 'tls', entry: 'port', port: 8443 } },
  { key: 'ss', label: 'Shadowsocks 2022', desc: '最简单，适合不太懂的朋友，也支持 UDP', v: { protocol: 'shadowsocks', transport: 'raw', security: 'none', entry: 'port', port: 8388 } },
  { key: 'vmess', label: 'VMess + WebSocket + TLS', desc: '给只支持 VMess 的老客户端', v: { protocol: 'vmess', transport: 'ws', security: 'tls', entry: 'port', port: 2083 } },
]

const blankNode: NodeForm = { name: '', enabled: true, protocol: 'vless', transport: 'raw', security: 'reality', entry: 'sni', port: 443, wan: '', domain: '', params: { fingerprint: 'chrome' }, note: '' }

function Nodes({ data, reload }: { data: ProxyResp; reload: () => void }) {
  const [edit, setEdit] = useState<NodeForm | null>(null)
  const { confirm, dialog } = useConfirm()
  const { isSuper, user } = useAuth()
  const mine = data.nodes
  const full = data.quota.nodes >= 0 && data.nodes.filter((n) => n.owner_id === user?.id).length >= data.quota.nodes
  const toggle = async (n: PNode, on: boolean) => {
    try { await runAction('proxy.node.toggle', { id: n.id, enabled: on }) } catch (e) { toast.error((e as Error).message) } finally { reload() }
  }
  const del = async (n: PNode) => {
    const used = data.users.filter((u) => u.nodes.includes(n.id)).length
    if (!(await confirm(`删除节点「${n.name}」？`, used ? `有 ${used} 个用户在用这个节点，删除后他们的这条线路会失效。` : '对应的防火墙端口也会关闭。', { danger: true, ok: '删除' }))) return
    try { await runAction('proxy.node.delete', { id: n.id }) } catch (e) { toast.error((e as Error).message) } finally { reload() }
  }
  return (
    <>
      <Section title="节点" desc={`每个节点就是一个对外的入口。用户在「用户」里选择能用哪些节点。${data.quota.nodes >= 0 ? ` · 上限 ${data.quota.nodes} 个` : ''}`}
        action={<Button size="sm" disabled={full} onClick={() => setEdit({ ...blankNode, params: { ...blankNode.params } })}><Plus /> 添加节点</Button>}>
        {!mine.length ? <Empty>还没有节点。推荐先建一个「VLESS + REALITY + Vision」，不需要域名。</Empty> : (
          <div className="divide-y">
            {mine.map((n) => {
              const users = data.users.filter((u) => u.nodes.includes(n.id)).length
              return (
                <div key={n.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                  <Switch size="sm" checked={n.enabled} onCheckedChange={(c) => toggle(n, !!c)} />
                  <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setEdit({ ...n, params: { ...n.params } })}>
                    <div className="flex items-center gap-1.5 text-sm font-medium">
                      <span className="truncate">{n.name}</span>
                      {n.entry === 'sni' ? <Pill tone="blue">{n.port} 分流</Pill> : <Pill>端口 {n.port}</Pill>}
                      {isSuper && n.owner_id !== user?.id && n.owner_name && <Pill>{n.owner_name}</Pill>}
                    </div>
                    <div className="truncate text-xs text-muted-foreground">{nodeDesc(n)} · {entryDesc(n)}{n.note ? ` · ${n.note}` : ''}</div>
                  </button>
                  <span className="text-xs text-muted-foreground"><UsersIcon className="mr-1 inline size-3.5" />{users} 个用户</span>
                  <div className="flex">
                    <Button variant="ghost" size="icon-sm" title="修改" onClick={() => setEdit({ ...n, params: { ...n.params } })}><Pencil /></Button>
                    <Button variant="ghost" size="icon-sm" title="删除" onClick={() => del(n)}><Trash2 /></Button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Section>
      <NodeEditor value={edit} onChange={setEdit} data={data} onSaved={() => { setEdit(null); reload() }} />
      {dialog}
    </>
  )
}

function Choice<T extends string>({ value, options, onChange, disabled }: { value: T; options: [T, string][]; onChange: (v: T) => void; disabled?: (v: T) => boolean }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map(([k, l]) => (
        <button key={k} type="button" disabled={disabled?.(k)} onClick={() => onChange(k)}
          className={cn('rounded-md border px-2.5 py-1 text-xs disabled:opacity-40', value === k ? 'border-primary bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted')}>{l}</button>
      ))}
    </div>
  )
}

function NodeEditor({ value: v, onChange, data, onSaved }: { value: NodeForm | null; onChange: (v: NodeForm | null) => void; data: ProxyResp; onSaved: () => void }) {
  const [busy, setBusy] = useState(false)
  const set = (p: Partial<NodeForm>) => v && onChange({ ...v, ...p })
  const setP = (p: Partial<Params>) => v && onChange({ ...v, params: { ...v.params, ...p } })
  const sharePort = data.front.share_port ?? 443
  const save = async () => {
    if (!v) return
    setBusy(true)
    // off 443 Let's Encrypt cannot validate: TLS nodes use a self-signed (pinned) certificate
    const body = sharePort !== 443 && v.security === 'tls' && v.params.cert !== 'self' ? { ...v, params: { ...v.params, cert: 'self' as const } } : v
    try { if (await runAction('proxy.node.save', body)) onSaved() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  if (!v) return <HalfPanel open={false} onOpenChange={() => {}} title=""><div /></HalfPanel>
  const p = v.params
  const reality = v.security === 'reality', tls = v.security === 'tls'
  const ss = v.protocol === 'shadowsocks', hy = v.protocol === 'hysteria'
  const canSNI = !ss && !hy && v.security !== 'none'
  const transports: [string, string][] = hy ? [['hysteria', 'QUIC']] : ss ? [['raw', 'RAW (TCP)']] : reality ? [['raw', 'RAW (TCP)'], ['xhttp', 'XHTTP'], ['grpc', 'gRPC']] : [['raw', 'RAW (TCP)'], ['xhttp', 'XHTTP'], ['ws', 'WebSocket'], ['grpc', 'gRPC'], ['httpupgrade', 'HTTPUpgrade']]
  const securities: [string, string][] = hy ? [['tls', 'TLS']] : ss ? [['none', '协议自带加密']] : [['reality', 'REALITY'], ['tls', 'TLS'], ...(v.protocol === 'vmess' || v.protocol === 'vless' ? [['none', '无（仅内网 / 套 CDN）'] as [string, string]] : [])]
  const fixProto = (protocol: string) => {
    const n: Partial<NodeForm> = { protocol }
    if (protocol === 'hysteria') Object.assign(n, { transport: 'hysteria', security: 'tls', entry: 'port' })
    else if (protocol === 'shadowsocks') Object.assign(n, { transport: 'raw', security: 'none', entry: 'port' })
    else if (v.transport === 'hysteria') Object.assign(n, { transport: 'raw' })
    if ((protocol === 'vmess') && v.security === 'reality') n.security = 'tls'
    if (protocol === 'trojan' && v.security === 'none') n.security = 'tls'
    set(n)
  }
  return (
    <HalfPanel open={!!v} onOpenChange={(o) => { if (!o) onChange(null) }} title={v.id ? `修改节点「${v.name}」` : '添加节点'}
      desc="保存时面板会生成配置交给 Xray 检查，通过后才生效，并同步防火墙"
      footer={<><Button variant="outline" onClick={() => onChange(null)}>取消</Button><Button disabled={!v.name || busy} onClick={save}>{busy && <Loader2 className="animate-spin" />}保存</Button></>}>
      <div className="grid gap-5">
        {!v.id && (
          <Field label="从模板开始">
            <div className="grid gap-1.5 sm:grid-cols-2">
              {PRESETS.map((t) => (
                <button key={t.key} type="button" onClick={() => onChange({ ...blankNode, name: v.name, ...t.v, params: { fingerprint: 'chrome' } } as NodeForm)}
                  className={cn('rounded-lg border px-3 py-2 text-left', v.protocol === t.v.protocol && v.transport === t.v.transport && v.security === t.v.security ? 'border-primary bg-accent' : 'hover:bg-muted')}>
                  <div className="text-sm font-medium">{t.label}</div>
                  <div className="text-[11px] text-muted-foreground">{t.desc}</div>
                </button>
              ))}
            </div>
          </Field>
        )}
        <Field label="名称"><Input value={v.name} maxLength={40} onChange={(e) => set({ name: e.target.value })} placeholder="例如 家里-Reality、给朋友的节点" /></Field>
        <Field label="协议"><Choice value={v.protocol} options={Object.entries(PROTO) as [string, string][]} onChange={fixProto} /></Field>
        <Field label="安全层"><Choice value={v.security} options={securities} onChange={(s) => set({ security: s, entry: s === 'none' ? 'port' : v.entry })} /></Field>
        <Field label="传输方式"><Choice value={v.transport} options={transports} onChange={(t) => set({ transport: t })} /></Field>

        <Field label="入口" hint={v.entry === 'sni' ? `公网 ${sharePort} 端口由面板的分流器按域名（SNI）分给各个节点，不认识的访问会看到一个普通网站。不影响路由器自己的网页（内网 443 照常）。` : '节点单独占用一个公网端口，防火墙会自动放行'}>
          <Choice value={v.entry} options={[['sni', `共用 ${sharePort}（按域名分流）`], ['port', '独立端口']]} onChange={(e) => set({ entry: e as 'sni' | 'port' })} disabled={(e) => e === 'sni' && !canSNI} />
        </Field>
        {v.entry === 'port' && (
          <div className="flex flex-wrap gap-3">
            <Field label={`公网端口${hy ? '（UDP）' : ''}`} className="w-32"><Input value={v.port || ''} inputMode="numeric" onChange={(e) => set({ port: Number(e.target.value.replace(/\D/g, '')) || 0 })} /></Field>
          </div>
        )}

        {reality && (
          <div className="grid gap-4 rounded-xl border p-4">
            <div className="text-sm font-medium">REALITY</div>
            <Field label="伪装目标" hint="一个真实存在、支持 TLS 1.3 和 HTTP/2 的网站。最好选离你近、和你的 IP 同地区的；不要选 Apple / Microsoft / iCloud 等（Xray 官方提示容易被封）。">
              <Input value={p.target ?? ''} onChange={(e) => setP({ target: e.target.value.trim() })} placeholder="www.cloudflare.com:443" />
            </Field>
            <Field label="SNI（可多个，用逗号分开）" hint={v.entry === 'sni' ? '443 分流按这里的名字把连接交给这个节点，不能和其他节点重复' : '客户端里填写的 serverName，通常和伪装目标的域名一样'}>
              <Input value={(p.server_names ?? []).join(', ')} onChange={(e) => setP({ server_names: e.target.value.split(/[,，\s]+/).filter(Boolean) })} placeholder="留空 = 使用伪装目标的域名" />
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Short ID" hint="留空自动生成"><Input value={(p.short_ids ?? []).join(', ')} onChange={(e) => setP({ short_ids: e.target.value.split(/[,，\s]+/).filter(Boolean) })} className="font-mono" /></Field>
              <Field label="客户端指纹"><Choice value={p.fingerprint ?? 'chrome'} options={[['chrome', 'Chrome'], ['firefox', 'Firefox'], ['safari', 'Safari'], ['ios', 'iOS'], ['edge', 'Edge'], ['random', '随机']]} onChange={(f) => setP({ fingerprint: f })} /></Field>
            </div>
            {p.public_key && <Field label="公钥（客户端填写）"><CopyText text={p.public_key} /></Field>}
            {v.id && <button type="button" className="w-fit text-xs text-muted-foreground underline" onClick={() => setP({ private_key: '', public_key: '' })}>重新生成密钥对（所有客户端需要更新）</button>}
          </div>
        )}
        {(tls || hy) && (
          <div className="grid gap-4 rounded-xl border p-4">
            <div className="text-sm font-medium">TLS 证书</div>
            <Field label="域名" hint={`需要解析到路由器的公网 IP（${data.host || '未知'}）。可以在「DDNS」里自动维护。`}>
              <Input value={v.domain} onChange={(e) => set({ domain: e.target.value.trim().toLowerCase() })} placeholder="proxy.example.com" />
            </Field>
            <Field label="证书">
              <Choice value={sharePort !== 443 ? 'self' : p.cert ?? 'acme'} options={[['acme', "自动申请 Let's Encrypt"], ['self', '自签名（客户端需允许不安全证书）']]} onChange={(c) => setP({ cert: c as 'acme' | 'self' })}
                disabled={(c) => c === 'acme' && sharePort !== 443} />
            </Field>
            {sharePort !== 443 && <p className="text-xs text-muted-foreground">分流端口是 {sharePort}，Let's Encrypt 只在 443 上验证，所以只能用自签证书；导入链接会带上证书指纹，客户端照样能校验。</p>}
            {p.cert !== 'self' && sharePort === 443 && <p className="text-xs text-muted-foreground">证书通过公网 443 端口自动验证和续期（TLS-ALPN），不需要开放 80 端口。第一次申请通常 1 分钟内完成；完成前会先用临时证书。</p>}
          </div>
        )}
        {['ws', 'xhttp', 'httpupgrade', 'grpc'].includes(v.transport) && (
          <Field label={v.transport === 'grpc' ? 'gRPC 服务名' : '路径'} hint="留空自动生成随机值">
            <Input value={p.path ?? ''} onChange={(e) => setP({ path: e.target.value.trim() })} className="font-mono" placeholder={v.transport === 'grpc' ? 'a1b2c3' : '/a1b2c3'} />
          </Field>
        )}
        {ss && (
          <Field label="加密方式">
            <Choice value={p.ss_method ?? '2022-blake3-aes-128-gcm'} options={[['2022-blake3-aes-128-gcm', 'AES-128-GCM'], ['2022-blake3-aes-256-gcm', 'AES-256-GCM'], ['2022-blake3-chacha20-poly1305', 'ChaCha20-Poly1305']]} onChange={(m) => setP({ ss_method: m, ss_key: '' })} />
          </Field>
        )}
        <Field label="备注"><Input value={v.note} maxLength={200} onChange={(e) => set({ note: e.target.value })} /></Field>
        <label className="flex items-center gap-2 text-sm"><Switch checked={v.enabled} onCheckedChange={(c) => set({ enabled: c })} />启用</label>
      </div>
    </HalfPanel>
  )
}

// ---- users ----

type UserForm = Omit<PUser, 'id' | 'owner_id' | 'secret' | 'sub_token' | 'used_up' | 'used_down' | 'period_at' | 'created' | 'stopped'> & { id?: number; regenerate?: boolean; reset_usage?: boolean }

const blankUser: UserForm = { name: '', nodes: [], limit_bytes: 0, reset_day: 0, expire_at: 0, ip_limit: 0, allow_lan: false, enabled: true, note: '' }

function ProxyUsers({ data, reload }: { data: ProxyResp; reload: () => void }) {
  const [edit, setEdit] = useState<UserForm | null>(null)
  const [links, setLinks] = useState<PUser | null>(null)
  const [ips, setIPs] = useState<PUser | null>(null)
  const { data: live } = useApi<Live>('/proxy/live', 10000)
  const { confirm, dialog } = useConfirm()
  const { isSuper, user } = useAuth()
  const fullUsers = data.quota.users >= 0 && data.users.filter((u) => u.owner_id === user?.id).length >= data.quota.users
  const del = async (u: PUser) => {
    if (!(await confirm(`删除用户「${u.name}」？`, '他的所有链接和订阅立即失效。访问记录会保留到期满。', { danger: true, ok: '删除' }))) return
    try { await runAction('proxy.user.delete', { id: u.id }) } catch (e) { toast.error((e as Error).message) } finally { reload() }
  }
  return (
    <>
      <Section title="用户" desc={`每个用户有自己的密钥、订阅链接、流量上限和到期时间。${data.quota.users >= 0 ? ` · 上限 ${data.quota.users} 个` : ''}`}
        action={<Button size="sm" disabled={!data.nodes.length || fullUsers} onClick={() => setEdit({ ...blankUser, nodes: data.nodes.filter((n) => n.enabled).map((n) => n.id) })}><Plus /> 添加用户</Button>}>
        {!data.users.length ? <Empty>{data.nodes.length ? '还没有用户。添加一个，就能拿到导入链接和二维码。' : '先在「节点」里添加一个节点。'}</Empty> : (
          <div className="divide-y">
            {data.users.map((u) => {
              const [st, tone] = userState(u)
              const used = u.used_up + u.used_down
              const online = live?.online[u.id]?.length ?? 0
              return (
                <div key={u.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                  <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setEdit({ ...u })}>
                    <div className="flex items-center gap-1.5 text-sm font-medium">
                      {online > 0 && <Dot tone="ok" />}
                      <span className="truncate">{u.name}</span><Pill tone={tone}>{st}</Pill>
                      {u.allow_lan && <Pill tone="amber">可访问内网</Pill>}
                      {isSuper && u.owner_id !== user?.id && u.owner_name && <Pill>{u.owner_name}</Pill>}
                    </div>
                    <div className="truncate text-xs text-muted-foreground">
                      {u.nodes.map((id) => data.nodes.find((n) => n.id === id)?.name).filter(Boolean).join('、') || '没有节点'}
                      {u.expire_at ? ` · ${new Date(u.expire_at * 1000).toLocaleDateString()} 到期` : ''}{u.ip_limit ? ` · 限 ${u.ip_limit} 个 IP` : ''}
                      {online ? ` · ${online} 个 IP 在线` : ''}
                    </div>
                  </button>
                  <div className="w-44">
                    <div className="flex justify-between text-[11px] tabular-nums text-muted-foreground"><span>{bytes(used)}</span><span>{u.limit_bytes ? bytes(u.limit_bytes) : '不限'}</span></div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                      <div className={cn('h-full rounded-full', u.limit_bytes && used / u.limit_bytes > 0.9 ? 'bg-destructive' : 'bg-primary/70')} style={{ width: `${u.limit_bytes ? Math.min(100, (used / u.limit_bytes) * 100) : used ? 100 : 0}%`, opacity: u.limit_bytes ? 1 : 0.35 }} />
                    </div>
                    {u.reset_day > 0 && <div className="mt-0.5 text-[10px] text-muted-foreground">每月 {u.reset_day} 日清零</div>}
                  </div>
                  <div className="flex">
                    <Button variant="ghost" size="icon-sm" title="链接与二维码" onClick={() => setLinks(u)}><QrCode /></Button>
                    <Button variant="ghost" size="icon-sm" title="来源 IP" onClick={() => setIPs(u)}><Globe2 /></Button>
                    <Button variant="ghost" size="icon-sm" title="修改" onClick={() => setEdit({ ...u })}><Pencil /></Button>
                    <Button variant="ghost" size="icon-sm" title="删除" onClick={() => del(u)}><Trash2 /></Button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Section>
      <UserEditor value={edit} onChange={setEdit} data={data} onSaved={() => { setEdit(null); reload() }} />
      <LinksDialog user={links} onClose={() => setLinks(null)} />
      <IPsPanel user={ips} onClose={() => setIPs(null)} />
      {dialog}
    </>
  )
}

const toDate = (ts: number) => (ts ? new Date(ts * 1000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 10) : '')

function UserEditor({ value: v, onChange, data, onSaved }: { value: UserForm | null; onChange: (v: UserForm | null) => void; data: ProxyResp; onSaved: () => void }) {
  const [busy, setBusy] = useState(false)
  const { isSuper } = useAuth()
  const set = (p: Partial<UserForm>) => v && onChange({ ...v, ...p })
  const save = async () => {
    if (!v) return
    setBusy(true)
    try { if (await runAction('proxy.user.save', v)) onSaved() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const cur = v?.id ? data.users.find((u) => u.id === v.id) : undefined
  return (
    <HalfPanel open={!!v} onOpenChange={(o) => { if (!o) onChange(null) }} title={v?.id ? `修改用户「${v.name}」` : '添加用户'}
      footer={<><Button variant="outline" onClick={() => onChange(null)}>取消</Button><Button disabled={!v?.name || busy} onClick={save}>{busy && <Loader2 className="animate-spin" />}保存</Button></>}>
      {v && (
        <div className="grid gap-5">
          <Field label="名称"><Input value={v.name} maxLength={40} onChange={(e) => set({ name: e.target.value })} placeholder="例如 小明、爸爸的手机" /></Field>
          <Field label="可以使用的节点">
            <div className="grid gap-1.5">
              {data.nodes.map((n) => (
                <label key={n.id} className="flex items-center gap-2.5 rounded-lg border px-3 py-2 text-sm">
                  <input type="checkbox" className="size-4 accent-[var(--primary)]" checked={v.nodes.includes(n.id)}
                    onChange={(e) => set({ nodes: e.target.checked ? [...v.nodes, n.id] : v.nodes.filter((x) => x !== n.id) })} />
                  <span className="font-medium">{n.name}</span>
                  <span className="truncate text-xs text-muted-foreground">{nodeDesc(n)}</span>
                  {!n.enabled && <Pill>已停用</Pill>}
                </label>
              ))}
            </div>
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="流量上限（GB）" hint="0 = 不限；上下行合计，用完自动暂停">
              <Input value={v.limit_bytes ? +(v.limit_bytes / GB).toFixed(2) : ''} inputMode="decimal" placeholder="不限"
                onChange={(e) => set({ limit_bytes: Math.round((parseFloat(e.target.value) || 0) * GB) })} />
            </Field>
            <Field label="每月清零日" hint="0 = 不自动清零">
              <Input value={v.reset_day || ''} inputMode="numeric" placeholder="不清零" onChange={(e) => set({ reset_day: Math.min(28, Number(e.target.value.replace(/\D/g, '')) || 0) })} />
            </Field>
            <Field label="到期日期" hint="留空 = 永不到期">
              <Input type="date" value={toDate(v.expire_at)} onChange={(e) => set({ expire_at: e.target.value ? Math.floor(new Date(e.target.value + 'T23:59:59').getTime() / 1000) : 0 })} />
            </Field>
            <Field label="同时在线 IP 数" hint="0 = 不限；超出时拒绝新出现的 IP 并告警">
              <Input value={v.ip_limit || ''} inputMode="numeric" placeholder="不限" onChange={(e) => set({ ip_limit: Number(e.target.value.replace(/\D/g, '')) || 0 })} />
            </Field>
          </div>
          {isSuper && (
            <label className="flex items-start gap-2 text-sm">
              <Switch checked={v.allow_lan} onCheckedChange={(c) => set({ allow_lan: c })} />
              <span>允许访问家里的局域网<span className="block text-xs text-muted-foreground">默认禁止，代理用户只能上外网，碰不到家里的 NAS、路由器和其他设备</span></span>
            </label>
          )}
          <Field label="备注"><Input value={v.note} maxLength={200} onChange={(e) => set({ note: e.target.value })} /></Field>
          <label className="flex items-center gap-2 text-sm"><Switch checked={v.enabled} onCheckedChange={(c) => set({ enabled: c })} />启用</label>
          {cur && (
            <div className="grid gap-2 rounded-xl border p-4 text-sm">
              <div className="text-xs text-muted-foreground">本期已用 {bytes(cur.used_up + cur.used_down)}（↓ {bytes(cur.used_down)} · ↑ {bytes(cur.used_up)}），从 {datetime(cur.period_at)} 起</div>
              <label className="flex items-center gap-2"><input type="checkbox" className="size-4" checked={!!v.reset_usage} onChange={(e) => set({ reset_usage: e.target.checked })} />保存时清零用量</label>
              <label className="flex items-center gap-2"><input type="checkbox" className="size-4" checked={!!v.regenerate} onChange={(e) => set({ regenerate: e.target.checked })} />重新生成密钥和订阅地址<span className="text-xs text-muted-foreground">（旧链接立即失效）</span></label>
            </div>
          )}
        </div>
      )}
    </HalfPanel>
  )
}

function QR({ text, size = 200 }: { text: string; size?: number }) {
  const svg = useMemo(() => {
    const q = qrcode(0, 'M')
    q.addData(text)
    q.make()
    return q.createSvgTag({ cellSize: 4, margin: 2, scalable: true })
  }, [text])
  return <div className="rounded-lg bg-white p-1" style={{ width: size, height: size }} dangerouslySetInnerHTML={{ __html: svg }} />
}

function LinksDialog({ user, onClose }: { user: PUser | null; onClose: () => void }) {
  const { data } = useApi<{ links: { node_id: number; node: string; link: string; note?: string }[]; subscription: string; self_signed_sub: boolean }>(user ? `/proxy/users/${user.id}/links` : null)
  const [qr, setQR] = useState('')
  useEffect(() => { setQR(data?.subscription || data?.links[0]?.link || '') }, [data])
  return (
    <Dialog open={!!user} onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader><DialogTitle>「{user?.name}」的导入方式</DialogTitle></DialogHeader>
        {!data ? <Empty>加载中…</Empty> : (
          <div className="grid gap-4 sm:grid-cols-[200px_1fr]">
            <div className="grid justify-items-center gap-2">
              {qr && <QR text={qr} />}
              <span className="text-center text-[11px] text-muted-foreground">用 v2rayN / Shadowrocket / Clash Verge / Hiddify / sing-box 扫码</span>
            </div>
            <div className="grid min-w-0 content-start gap-3">
              {data.subscription && (
                <div className="grid gap-1">
                  <div className="flex items-center gap-1.5 text-xs font-medium"><Link2 className="size-3.5" />订阅链接（推荐：节点变化时客户端自动更新）
                    <button type="button" className={cn('ml-auto text-[11px] underline', qr === data.subscription ? 'text-primary' : 'text-muted-foreground')} onClick={() => setQR(data.subscription)}>{qr === data.subscription ? '正在显示' : '二维码'}</button></div>
                  <CopyText text={data.subscription} />
                  {data.self_signed_sub && <p className="text-[11px] text-muted-foreground">还没有为网站设置域名，订阅地址用的是 IP + 自签证书；在「扩展设置」里填上网站域名后会自动换成正规证书。</p>}
                </div>
              )}
              {data.links.map((l) => (
                <div key={l.node_id} className="grid gap-1">
                  <div className="flex items-center gap-1.5 text-xs font-medium"><KeyRound className="size-3.5" />{l.node}{l.note && <Pill>{l.note}</Pill>}
                    <button type="button" className={cn('ml-auto text-[11px] underline', qr === l.link ? 'text-primary' : 'text-muted-foreground')} onClick={() => setQR(l.link)}>{qr === l.link ? '正在显示' : '二维码'}</button></div>
                  <CopyText text={l.link} />
                </div>
              ))}
              {!data.links.length && <Empty>这个用户还没有可用的节点</Empty>}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function IPsPanel({ user, onClose }: { user: PUser | null; onClose: () => void }) {
  const { data } = useApi<{ items: { ip: string; first: number; last: number; country: string; region: string; city: string; asn: number; as_org: string }[] }>(user ? `/proxy/users/${user.id}/ips` : null)
  return (
    <HalfPanel open={!!user} onOpenChange={(o) => { if (!o) onClose() }} title={`「${user?.name}」的来源 IP`} desc="这个用户从哪些地址连接过（最近 200 个）">
      {!data ? <Empty>加载中…</Empty> : !data.items.length ? <Empty>还没有连接记录</Empty> : (
        <div className="divide-y rounded-xl border">
          {data.items.map((x) => (
            <div key={x.ip} className="grid gap-0.5 px-3 py-2 text-sm">
              <div className="flex items-center gap-2"><span className="font-mono">{x.ip}</span><span className="ml-auto text-xs text-muted-foreground">{ago(x.last)}</span></div>
              <div className="text-xs text-muted-foreground">{[x.city, x.region, x.country].filter(Boolean).join(' · ') || '未知位置'}{x.as_org ? ` · AS${x.asn} ${x.as_org}` : ''} · 首次 {datetime(x.first)}</div>
            </div>
          ))}
        </div>
      )}
    </HalfPanel>
  )
}

// ---- access log ----

interface AccessRec { id: number; ts: number; last: number; user_id: number; user: string; node_id: number; node: string; ip: string; country: string; city: string; dest: string; port: number; net: string; status: string; count: number; service?: string }

function Access({ data }: { data: ProxyResp }) {
  const [user, setUser] = useState('')
  const [node, setNode] = useState('')
  const [q, setQ] = useState('')
  const [qq, setQQ] = useState('')
  const [rej, setRej] = useState(false)
  const [more, setMore] = useState<AccessRec[]>([])
  useEffect(() => { const t = setTimeout(() => setQQ(q), 400); return () => clearTimeout(t) }, [q])
  const base = `/proxy/access?user=${user}&node=${node}&q=${encodeURIComponent(qq)}${rej ? '&status=rejected' : ''}`
  const { data: page } = useApi<{ items: AccessRec[] }>(base, 30000)
  useEffect(() => setMore([]), [base])
  const items = [...(page?.items ?? []), ...more]
  const loadMore = async () => {
    const last = items[items.length - 1]
    if (!last) return
    try { const r = await api<{ items: AccessRec[] }>('GET', `${base}&before=${last.id}`); setMore((m) => [...m, ...r.items]) } catch (e) { toast.error((e as Error).message) }
  }
  return (
    <Section title="访问记录" desc={`代理用户访问了哪些网站（按分钟合并）。保留 ${data.settings?.access_days ?? 30} 天，用于说清楚每一笔流量是谁的。`} action={
      <div className="flex flex-wrap items-center gap-2">
        <select value={user} onChange={(e) => setUser(e.target.value)} className="h-8 rounded-md border bg-background px-2 text-sm">
          <option value="">全部用户</option>{data.users.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}
        </select>
        <select value={node} onChange={(e) => setNode(e.target.value)} className="h-8 rounded-md border bg-background px-2 text-sm">
          <option value="">全部节点</option>{data.nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground"><Switch size="sm" checked={rej} onCheckedChange={(c) => setRej(!!c)} />只看被拦截</label>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="网站 / IP" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-40 pl-8" />
        </div>
      </div>
    }>
      {!items.length ? <Empty>{page ? '没有记录' : '加载中…'}</Empty> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b text-left text-xs text-muted-foreground">
              <th className="px-4 py-2 font-medium">时间</th><th className="px-2 py-2 font-medium">用户</th><th className="px-2 py-2 font-medium">来源</th>
              <th className="px-2 py-2 font-medium">访问目标</th><th className="px-2 py-2 text-right font-medium">次数</th><th className="px-4 py-2 font-medium">节点</th>
            </tr></thead>
            <tbody>
              {items.map((x) => (
                <tr key={x.id} className="border-b last:border-0">
                  <td className="whitespace-nowrap px-4 py-1.5 text-xs tabular-nums text-muted-foreground">{datetime(x.ts)}</td>
                  <td className="whitespace-nowrap px-2 py-1.5">{x.user || `#${x.user_id}`}</td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-xs"><span className="font-mono">{x.ip}</span> <span className="text-muted-foreground">{[x.city, x.country].filter(Boolean).join(' · ')}</span></td>
                  <td className="max-w-80 px-2 py-1.5">
                    <div className="flex items-center gap-1.5">
                      {x.status !== 'accepted' && <span title={x.status === 'blocked' ? '被规则拦截（局域网 / BT / 禁止的端口或网站）' : 'Xray 拒绝'}><Ban className="size-3.5 shrink-0 text-destructive" /></span>}
                      <span className="truncate font-mono text-xs">{x.dest}:{x.port}</span>
                      {x.net === 'udp' && <Pill>UDP</Pill>}
                      {x.service && <Pill tone="blue">{x.service}</Pill>}
                    </div>
                  </td>
                  <td className="px-2 py-1.5 text-right text-xs tabular-nums">{x.count}</td>
                  <td className="whitespace-nowrap px-4 py-1.5 text-xs text-muted-foreground">{x.node || `#${x.node_id}`}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {(page?.items.length ?? 0) >= 200 && <div className="p-3 text-center"><Button variant="outline" size="sm" onClick={loadMore}>加载更早的记录</Button></div>}
        </div>
      )}
    </Section>
  )
}

// ---- extension settings (super) ----

function ExtSettings({ data, reload }: { data: ProxyResp; reload: () => void }) {
  const [s, setS] = useState<Settings | null>(null)
  const [html, setHTML] = useState('')
  const [tag, setTag] = useState('')
  const [busy, setBusy] = useState(false)
  const [showLog, setShowLog] = useState(false)
  const { confirm, dialog } = useConfirm()
  useJobWatch(data.ext, reload)
  useEffect(() => { if (data.settings && !s) { setS(data.settings); setHTML(data.site_html ?? '') } }, [data.settings, data.site_html, s])
  const { data: log } = useApi<{ error: string[] | null }>(showLog ? '/proxy/log' : null, 10000)
  if (!s) return null
  const set = (p: Partial<Settings>) => setS({ ...s, ...p })
  const save = async () => {
    setBusy(true)
    try { if (await runAction('proxy.settings', { settings: s, site_html: s.site.mode === 'html' ? html : undefined })) reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const switchTo = async () => {
    if (!(await confirm(`把 Xray 切换到 ${tag}？`, '面板会先用新版本检查现有配置；切换时所有连接会断开几秒，失败会自动退回当前版本。'))) return
    try { await post('/proxy/ext', { action: 'install', tag }); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const uninstall = async () => {
    if (!(await confirm('卸载代理扩展？', '会停止 Xray、关闭所有节点的端口并删除下载的内核和证书。节点和用户的设置保留在面板里，重新安装后可以直接恢复。', { danger: true, ok: '卸载' }))) return
    try { await post('/proxy/ext', { action: 'uninstall' }); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const ext = data.ext
  return (
    <div className="grid items-start gap-4 xl:grid-cols-2">
      <div className="grid min-w-0 gap-4">
        <Section title="内核" desc={`Xray ${ext.version}${ext.previous ? ` · 可回退到 ${ext.previous}` : ''} · ${ext.asset} · 剩余空间 ${ext.free_mb} MB`}
          action={<Button variant="outline" size="sm" onClick={uninstall}><Trash2 /> 卸载扩展</Button>}>
          <div className="grid gap-3 p-4">
            <div className="flex flex-wrap gap-2 text-xs">
              <Pill tone={ext.running.xray ? 'green' : 'muted'}><Server className="size-3" />Xray {ext.running.xray ? '运行中' : '未运行'}</Pill>
              <Pill tone={ext.running.front ? 'green' : 'muted'}><Zap className="size-3" />{data.front.share_port ?? 443} 分流 {ext.running.front ? '运行中' : '未运行'}</Pill>
              <button type="button" className="text-muted-foreground underline" onClick={() => setShowLog(!showLog)}>{showLog ? '收起日志' : '查看错误日志'}</button>
            </div>
            {showLog && <div className="max-h-56 overflow-auto rounded-lg bg-muted/60 p-3 font-mono text-[11px] leading-5">{(log?.error ?? []).length ? log!.error!.map((l, i) => <div key={i}>{l}</div>) : '（没有错误）'}</div>}
            <VersionPicker value={tag} onChange={setTag} current={ext.version} />
            <JobLog ext={ext} />
            {ext.job.error && !ext.job.running && <ErrorBox>{ext.job.error}</ErrorBox>}
            <div><Button size="sm" disabled={!tag || tag === ext.version || ext.job.running} onClick={switchTo}><RefreshCw /> 切换到 {tag || '…'}</Button></div>
          </div>
        </Section>
        <SNIRoutes data={data} />
        {!!data.certs?.length && (
          <Section title="证书">
            <div className="divide-y">
              {data.certs.map((c) => (
                <div key={c.domain} className="flex flex-wrap items-center gap-2 px-4 py-2.5 text-sm">
                  <ShieldCheck className={cn('size-4', c.self_signed ? 'text-muted-foreground' : 'text-success')} />
                  <span className="font-mono">{c.domain}</span>
                  {c.self_signed ? <Pill tone="amber">临时 / 自签</Pill> : <Pill tone="green">{c.issuer}</Pill>}
                  <span className="ml-auto text-xs text-muted-foreground">{c.not_after ? `有效期至 ${new Date(c.not_after * 1000).toLocaleDateString()}` : ''}</span>
                  {c.status?.startsWith('error') && <div className="w-full text-xs text-destructive">申请失败：{c.status.slice(7)}</div>}
                </div>
              ))}
            </div>
          </Section>
        )}
      </div>
      <Section title="设置" action={<Button size="sm" disabled={busy} onClick={save}>{busy && <Loader2 className="animate-spin" />}保存</Button>}>
        <div className="grid gap-5 p-4">
          {data.port443 && (
            <div className="grid gap-3 rounded-xl border border-warning/50 p-4">
              <div className="text-sm font-medium">公网 {data.front.share_port ?? 443} 已经转发给「{data.port443.forward}」（{data.port443.target}）</div>
              <p className="text-xs text-muted-foreground">想让节点也用 443（按域名分流）时，选择和这条转发怎么共处。只有存在「共用 443」的节点时才会生效。</p>
              <div className="grid gap-2">
                {([
                  ['cloudflare', '共用 443（推荐）', `原来的转发规则一条不改，${data.port443.target} 上的网站和配置也不用动。来自 Cloudflare 的访问照旧直达；其他来源先经过分流器：节点的域名交给 Xray，其余域名原样转给 ${data.port443.target}，而且用访客自己的 IP 去连——网站看到的来源和以前完全一样。`],
                  ...((s.share_443 === 'takeover' || s.takeover_443) ? [['takeover', '完全接管（旧方式）', `所有来源的 443 都先到分流器，原来的转发暂停。${data.port443.target} 看到的来源会变成路由器，除非它接受 PROXY 协议。建议改用「共用 443」。`] as const] : []),
                  ['', '不共用', '443 只给原来的转发；节点使用独立端口。'],
                ] as const).map(([k, l, d]) => (
                  <label key={k} className={cn('flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-2 text-sm', (s.share_443 || (s.takeover_443 ? 'takeover' : '')) === k ? 'border-primary bg-accent' : 'hover:bg-muted')}>
                    <input type="radio" className="mt-1" checked={(s.share_443 || (s.takeover_443 ? 'takeover' : '')) === k} onChange={() => set({ share_443: k, takeover_443: false })} />
                    <span>{l}<span className="block text-xs text-muted-foreground">{d}</span></span>
                  </label>
                ))}
              </div>
              {s.share_443 === 'cloudflare' && (
                <Field label="另外直达原转发的来源（可选）" hint="一行一个 IPv4 地址或网段。一般不需要：经过分流器的访问，网站也能看到真实 IP">
                  <Textarea rows={2} value={(s.share_skip ?? []).join('\n')} onChange={(e) => set({ share_skip: e.target.value.split(/\n/).map((x) => x.trim()) })} className="font-mono text-xs" />
                </Field>
              )}
              {s.share_443 === 'takeover' && (
                <label className="flex items-start gap-2 text-sm">
                  <Switch checked={s.takeover_proxy} onCheckedChange={(c) => set({ takeover_proxy: c })} />
                  <span>向 {data.port443.target} 发送 PROXY 协议
                    <span className="block text-xs text-muted-foreground">服务器必须配置为接受 PROXY 协议（例如 nginx 的 listen 443 ssl proxy_protocol），否则网站会打不开。</span>
                  </span>
                </label>
              )}
              <OnePanelCard target={data.port443.target} />
            </div>
          )}
          <Field label="对外地址" hint={`客户端连接用的地址（域名或 IP）。留空 = 当前 WAN IP（${data.host || '未知'}）。有 DDNS 域名就填域名，IP 变了链接也不用换。`}>
            <Input value={s.address} onChange={(e) => set({ address: e.target.value.trim() })} placeholder={data.host} />
          </Field>
          <Field label="分流端口" hint="多个节点按域名（SNI）共用的公网端口，默认 443。宽带运营商封了 443，或者想把 443 完全留给别的服务时，可以换成 8443、2053 这类端口——证书会改用自签（导入链接自带指纹），订阅链接也会带上端口。">
            <div className="flex flex-wrap items-center gap-2">
              <Input className="w-28" inputMode="numeric" value={s.share_port || 443}
                onChange={(e) => { const n = parseInt(e.target.value.replace(/\D/g, ''), 10); set({ share_port: Number.isFinite(n) ? n : 443 }) }} />
              {[443, 8443, 2053, 2083].map((p) => (
                <button key={p} type="button" onClick={() => set({ share_port: p })}
                  className={cn('rounded-md border px-2 py-1 text-xs', (s.share_port || 443) === p ? 'border-primary bg-accent' : 'text-muted-foreground hover:bg-muted')}>{p}</button>
              ))}
            </div>
          </Field>
          <div className="grid gap-4 rounded-xl border p-4">
            <div className="text-sm font-medium">伪装网站</div>
            <p className="text-xs text-muted-foreground">有人直接访问 443 端口、扫描你的 IP，或者用不认识的域名连接时，看到的是这个网站。订阅链接也由它提供。</p>
            <Field label="网站域名" hint="可选。填了会自动申请正规证书，订阅链接用这个域名（需解析到路由器公网 IP）">
              <Input value={s.site.domain} onChange={(e) => set({ site: { ...s.site, domain: e.target.value.trim().toLowerCase() } })} placeholder="home.example.com" />
            </Field>
            <Field label="内容">
              <Choice value={s.site.mode} options={[['builtin', '内置的个人主页'], ['html', '我自己的 HTML'], ['proxy', '反向代理一个网站']]} onChange={(m) => set({ site: { ...s.site, mode: m } })} />
            </Field>
            {s.site.mode === 'builtin' && <Field label="标题"><Input value={s.site.title} onChange={(e) => set({ site: { ...s.site, title: e.target.value } })} placeholder="Welcome" /></Field>}
            {s.site.mode === 'html' && <Field label="页面 HTML（最大 512 KB）"><Textarea rows={8} value={html} onChange={(e) => setHTML(e.target.value)} className="font-mono text-xs" placeholder="<!doctype html>…" /></Field>}
            {s.site.mode === 'proxy' && <Field label="反向代理到" hint="例如家里 NAS 的网页 http://192.168.1.10:5000，或者一个公开网站"><Input value={s.site.proxy} onChange={(e) => set({ site: { ...s.site, proxy: e.target.value.trim() } })} placeholder="https://example.org" /></Field>}
          </div>
          <Field label="证书通知邮箱" hint="可选；Let's Encrypt 只在证书快到期而没续上时发邮件"><Input value={s.acme_email} onChange={(e) => set({ acme_email: e.target.value })} /></Field>
          <div className="grid gap-3 rounded-xl border p-4">
            <div className="text-sm font-medium">所有代理用户都不能做的事</div>
            <label className="flex items-center gap-2 text-sm"><Switch checked={s.block_bt} onCheckedChange={(c) => set({ block_bt: c })} />禁止 BT 下载<span className="text-xs text-muted-foreground">（版权投诉会落到你的 IP 上）</span></label>
            <Field label="禁止的目标端口" hint="默认禁止 25（发垃圾邮件）"><Input value={(s.block_ports ?? []).join(', ')} onChange={(e) => set({ block_ports: e.target.value.split(/[,，\s]+/).map(Number).filter((n) => n > 0 && n < 65536) })} /></Field>
            <Field label="禁止的网站（域名，含子域名）"><Textarea rows={3} value={(s.block_hosts ?? []).join('\n')} onChange={(e) => set({ block_hosts: e.target.value.split(/\n/).map((x) => x.trim()) })} placeholder="example.com" /></Field>
          </div>
          <Field label="访问记录保留天数"><Input className="w-24" value={s.access_days} inputMode="numeric" onChange={(e) => set({ access_days: Number(e.target.value.replace(/\D/g, '')) || 30 })} /></Field>
        </div>
      </Section>
      {dialog}
    </div>
  )
}

interface OnePanelSite { id: number; domain: string; domains: string[] | null; alias: string; status: string; protocol: string; remark: string }
interface OnePanelState { url: string; key: string; sites: OnePanelSite[]; error: string; api: string; fetched?: number }

// 1Panel: read-only API access to list the websites behind the 443 forward
function OnePanelCard({ target }: { target: string }) {
  const { data, reload } = useApi<OnePanelState>('/proxy/onepanel')
  const [form, setForm] = useState<{ url: string; key: string } | null>(null)
  const [busy, setBusy] = useState(false)
  if (!data) return null
  const sites = data.sites ?? []
  const f = form ?? { url: data.url || `http://${target.replace(/:\d+$/, '')}:8888`, key: data.key }
  const save = async (disconnect = false) => {
    setBusy(true)
    try {
      await post('/proxy/onepanel', disconnect ? { url: '', key: '' } : f)
      toast.success(disconnect ? '已断开 1Panel' : '已连接 1Panel')
      setForm(null); reload()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <div className="grid gap-3 rounded-lg border p-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        {target} 是 1Panel？
        {data.url && !data.error && <Pill tone="green">已连接 · {sites.length} 个网站</Pill>}
      </div>
      <p className="text-xs text-muted-foreground">
        连接后面板会读出 1Panel 上的网站，显示在这里，并防止节点用到和网站相同的域名（只读，不会改 1Panel 的任何东西）。
        在 1Panel「面板设置 → API 接口」开启，复制密钥，并把路由器的局域网地址加入 IP 白名单。
      </p>
      <div className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
        <Input value={f.url} onChange={(e) => setForm({ ...f, url: e.target.value.trim() })} placeholder="http://192.168.1.10:8888" className="font-mono text-xs" />
        <Input value={f.key} onChange={(e) => setForm({ ...f, key: e.target.value.trim() })} placeholder="API 密钥" type="password" autoComplete="off" className="font-mono text-xs" />
        <div className="flex gap-1.5">
          <Button size="sm" variant="outline" disabled={busy || !f.url || !f.key} onClick={() => save()}>{busy && <Loader2 className="animate-spin" />}{data.url ? '保存' : '连接'}</Button>
          {data.url && <Button size="sm" variant="ghost" disabled={busy} onClick={() => save(true)}>断开</Button>}
        </div>
      </div>
      {data.error && <ErrorBox>{data.error}</ErrorBox>}
      {!!sites.length && (
        <div className="divide-y rounded-lg border text-xs">
          {sites.map((x) => (
            <div key={x.id} className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2">
              <Dot tone={x.status === 'Running' ? 'ok' : 'off'} />
              <span className="font-mono">{x.domain}</span>
              {x.protocol === 'HTTPS' && <Pill tone="green">HTTPS</Pill>}
              {(x.remark || x.alias) && <span className="text-muted-foreground">{x.remark || x.alias}</span>}
              {(x.domains ?? []).length > 1 && <span className="w-full truncate pl-4 font-mono text-muted-foreground">{(x.domains ?? []).filter((d) => d !== x.domain).join(' · ')}</span>}
            </div>
          ))}
          <div className="px-3 py-2 text-muted-foreground">这些域名的访问一律交给 1Panel 处理，节点请用别的子域名。</div>
        </div>
      )}
    </div>
  )
}

// SNIRoutes: who gets which name on the shared port, in the front's order of priority.
function SNIRoutes({ data }: { data: ProxyResp }) {
  const nodes = data.nodes.filter((n) => n.enabled && n.entry === 'sni')
  const b = data.berth_sni
  if (!b?.domains.length) return null // without Berth the node list already shows this
  return (
    <Section title={`${data.front.share_port ?? 443} 分流去向`} desc="同一个名字只归一方，优先级：代理节点 > Berth > 1Panel 网站 > 伪装站点。">
      <div className="divide-y text-sm">
        {nodes.map((n) => (
          <div key={n.id} className="flex flex-wrap items-center gap-2 px-4 py-2">
            <Pill tone="blue">代理节点</Pill><span className="font-mono">{n.security === 'reality' ? (n.params.server_names ?? []).join(', ') : n.domain}</span>
            <span className="ml-auto text-xs text-muted-foreground">{n.name}</span>
          </div>
        ))}
        <div className="flex flex-wrap items-center gap-2 px-4 py-2">
          <Pill tone="blue"><Anchor className="size-3" />Berth</Pill>
          <span className="font-mono">{b.domains.join(', ')}</span>
          <span className="ml-auto text-xs text-muted-foreground">原样转给 {b.target}{b.proxy_protocol ? '（带 PROXY 协议）' : ''} · 证书由 Berth 负责</span>
        </div>
      </div>
    </Section>
  )
}
