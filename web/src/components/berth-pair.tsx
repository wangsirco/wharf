import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { AlertTriangle, Globe, Home, Loader2, Radar, ShieldCheck, Waypoints, X } from 'lucide-react'
import { get, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { datetime } from '@/lib/format'
import { berthStatus } from '@/lib/berth'
import { cn } from '@/lib/utils'
import { useReauth, type PasskeyList } from '@/components/login-mode'
import { Pill } from '@/components/common'
import { CopyText } from '@/pages/diag'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

const fpText = (s: string) => s.match(/.{1,4}/g)?.join(' ') ?? s

interface Names { local: string; port: string; names: { name: string }[]; via_443: boolean; via_port: boolean; proxied: string[] | null; cert_expires?: number; cert_issuer?: string }

// PairAddresses: what to type into Berth. On the LAN, Berth sees Wharf's own CA and should
// show the same fingerprint; on a public name it sees a public certificate (Let's Encrypt),
// checks it by name, and there is no fingerprint to compare.
export function PairAddresses({ selfFP }: { selfFP?: string }) {
  const { data: n } = useApi<Names>('/panel/names')
  const port = n?.port && n.port !== '443' ? ':' + n.port : ''
  const lan = `https://${n?.local || 'wharf.lan'}${port}`
  const ip = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(location.hostname) ? `https://${location.hostname}${port}` : ''
  const proxied = new Set(n?.proxied ?? [])
  const outside = n && (n.via_443 || n.via_port) ? n.names.map((x) => x.name) : []
  const pubURL = (name: string) => `https://${name}${n?.via_443 || proxied.has(name) ? '' : port}`
  return (
    <div className="grid gap-3">
      <div className="grid gap-1.5 rounded-lg border border-primary/40 bg-accent/30 p-3">
        <div className="flex items-center gap-2 text-sm font-medium"><Home className="size-4 text-primary" />同一个局域网 <Pill tone="blue">推荐</Pill></div>
        <CopyText text={lan} />
        {ip && ip !== lan && <CopyText text={ip} />}
        {selfFP && <p className="text-xs text-muted-foreground">Berth 会显示它读到的本地证书指纹，应该和这串一样：<br /><span className="font-mono text-foreground">{fpText(selfFP)}</span></p>}
      </div>
      {outside.length > 0 && (
        <div className="grid gap-1.5 rounded-lg border p-3">
          <div className="flex items-center gap-2 text-sm font-medium"><Globe className="size-4 text-primary" />跨网（公网域名）</div>
          {outside.map((name) => <CopyText key={name} text={pubURL(name)} />)}
          <p className="text-xs text-muted-foreground">
            这里出示的是公网证书{n?.cert_issuer ? `（${n.cert_issuer} 签发` : ''}{n?.cert_expires ? `${n.cert_issuer ? '，' : '（'}${datetime(n.cert_expires).slice(0, 10)} 到期）` : n?.cert_issuer ? '）' : ''}，Berth 会按域名校验，<b className="text-foreground">不用核对指纹</b>；和上面那串不一样是正常的。
            {[...proxied].some((x) => outside.includes(x)) && ' 经 Cloudflare 橙色云时，Cloudflare 能看到两边的通信内容；在同一个局域网时优先用内网地址。'}
          </p>
        </div>
      )}
    </div>
  )
}

interface Ask { id: string; name: string; urls: string[]; berth_fp: string; ip: string; sas: string; created_at: number; expires_at: number }
interface Disc { open_until: number; requests: Ask[]; self_fp: string }

// BerthDiscovery: open a 10-minute window in which a Berth on the LAN may ask to pair; each
// request pops up here with the code both panels show, and is allowed or refused here.
export function BerthDiscovery() {
  const { data, reload, setData } = useApi<Disc>('/berth/discover', 2000)
  const [now, setNow] = useState(Date.now() / 1000)
  const [asking, setAsking] = useState<string | null>(null)
  useEffect(() => { const t = setInterval(() => setNow(Date.now() / 1000), 1000); return () => clearInterval(t) }, [])
  const set = async (open: boolean) => {
    try { setData(await post<Disc>('/berth/discover', { open })) } catch (e) { toast.error((e as Error).message) }
  }
  const refuse = async (id: string) => { await post(`/berth/discover/${id}/refuse`).catch(() => {}); reload() }
  const left = data ? Math.max(0, Math.round(data.open_until - now)) : 0
  const open = left > 0

  return (
    <div className="grid gap-3">
      {data?.requests.map((q) => (
        <div key={q.id} className="grid gap-2 rounded-xl border-2 border-primary bg-accent/40 p-4 shadow-sm">
          <div className="flex flex-wrap items-center gap-2">
            <img src="/berth/mark.svg" alt="" className="size-7" />
            <div className="min-w-0 flex-1">
              <div className="font-semibold">「{q.name}」（{q.ip}）申请绑定</div>
              <div className="truncate font-mono text-xs text-muted-foreground">{q.urls.join(' · ')}</div>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-sm text-muted-foreground">校验码</span>
            <span className="font-mono text-2xl font-bold tracking-widest">{q.sas}</span>
            <span className="text-xs text-muted-foreground">和 Berth 上显示的一样才允许</span>
          </div>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => setAsking(q.id)}><ShieldCheck /> 允许…</Button>
            <Button size="sm" variant="outline" onClick={() => refuse(q.id)}><X /> 拒绝</Button>
          </div>
        </div>
      ))}
      <div className={cn('flex flex-wrap items-center gap-3 rounded-lg border p-3', open && 'border-success/50 bg-success/5')}>
        <Radar className={cn('size-5 shrink-0', open ? 'animate-pulse text-success' : 'text-muted-foreground')} />
        <div className="min-w-0 flex-1 text-sm">
          {open
            ? <><b>正在等 Berth 申请</b>（还剩 {Math.floor(left / 60)}:{String(left % 60).padStart(2, '0')}）· 在 Berth 里点「面板互联 → 内网发现 → 申请绑定」</>
            : <>允许局域网里的 Berth 申请绑定。打开 10 分钟，只接受内网来的申请，到时自动关闭。</>}
        </div>
        {open ? <Button size="sm" variant="outline" onClick={() => set(false)}>关闭</Button> : <Button size="sm" onClick={() => set(true)}>允许 Berth 申请绑定（10 分钟）</Button>}
      </div>
      {asking && <AllowDialog id={asking} onClose={() => setAsking(null)} onDone={() => { setAsking(null); reload(); berthStatus(true) }} />}
    </div>
  )
}

interface Scope { key: string; label: string; desc: string }
interface Cand { ip: string; mac?: string; name?: string; online: boolean; matched: boolean }

function AllowDialog({ id, onClose, onDone }: { id: string; onClose: () => void; onDone: () => void }) {
  const { data: pk } = useApi<PasskeyList>('/me/passkeys')
  const { ensure, dialog } = useReauth(pk, true)
  const [p, setP] = useState<{ request: Ask; scopes: Scope[]; devices: Cand[] } | null>(null)
  const [scopes, setScopes] = useState<string[]>([])
  const [hosts, setHosts] = useState<string[]>([])
  const [days, setDays] = useState(0)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    get<{ request: Ask; scopes: Scope[]; devices: Cand[] }>(`/berth/discover/${id}`)
      .then((r) => { setP(r); setScopes(r.scopes.map((s) => s.key)); setHosts(r.devices.filter((d) => d.matched).map((d) => d.ip)) })
      .catch((e) => { toast.error((e as Error).message); onClose() })
  }, [id]) // eslint-disable-line react-hooks/exhaustive-deps
  const toggle = (list: string[], set: (v: string[]) => void, k: string, on: boolean) => set(on ? [...list, k] : list.filter((x) => x !== k))
  const allow = async () => {
    if (!p) return
    setBusy(true)
    try {
      await ensure()
      const targets = p.devices.filter((d) => hosts.includes(d.ip)).map(({ ip, mac, name }) => ({ ip, mac, name }))
      await post(`/berth/discover/${id}/allow`, { scopes, targets, expires_days: days })
      toast.success('已允许，Berth 会自动完成配对')
      onDone()
    } catch (e) { if ((e as Error).message !== '已取消') toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>允许「{p?.request.name ?? 'Berth'}」绑定</DialogTitle>
          <DialogDescription>校验码 <span className="font-mono font-semibold text-foreground">{p?.request.sas}</span>。勾选允许它做的事，之后只能收窄，要增加需要重新绑定。</DialogDescription>
        </DialogHeader>
        {!p ? <Loader2 className="mx-auto animate-spin" /> : (
          <div className="grid gap-4">
            <div className="grid gap-2 sm:grid-cols-2">
              {p.scopes.map((s) => (
                <label key={s.key} className={cn('flex cursor-pointer items-start gap-2 rounded-lg border p-2.5', scopes.includes(s.key) && 'border-primary/50 bg-accent/40')}>
                  <Checkbox className="mt-0.5" checked={scopes.includes(s.key)} onCheckedChange={(c) => toggle(scopes, setScopes, s.key, !!c)} />
                  <span><span className="block text-sm font-medium">{s.label}</span><span className="text-xs text-muted-foreground">{s.desc}</span></span>
                </label>
              ))}
            </div>
            <div className="grid gap-1.5">
              <div className="text-sm font-medium">Berth 主机 <span className="text-xs font-normal text-muted-foreground">端口映射、443 分流、本地域名只能指向这里选中的设备。已按申请来源自动选好。</span></div>
              <div className="grid max-h-48 gap-1 overflow-y-auto">
                {p.devices.map((d) => (
                  <label key={d.ip} className={cn('flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-1.5 text-sm', hosts.includes(d.ip) && 'border-primary/50 bg-accent/40')}>
                    <Checkbox checked={hosts.includes(d.ip)} onCheckedChange={(c) => toggle(hosts, setHosts, d.ip, !!c)} />
                    <span className="min-w-0 flex-1 truncate">{d.name || d.ip}</span>
                    <span className="font-mono text-xs text-muted-foreground">{d.ip}</span>
                    {d.matched && <Pill tone="blue">申请来源</Pill>}
                  </label>
                ))}
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm">有效期
              <select className="h-8 rounded-md border bg-background px-2 text-sm" value={days} onChange={(e) => setDays(Number(e.target.value))}>
                <option value={0}>永久</option><option value={30}>30 天</option><option value={90}>90 天</option><option value={365}>365 天</option>
              </select>
            </label>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>取消</Button>
          <Button disabled={busy || !p || scopes.length === 0} onClick={allow}>{busy ? <Loader2 className="animate-spin" /> : <ShieldCheck />} 允许</Button>
        </DialogFooter>
        {dialog}
      </DialogContent>
    </Dialog>
  )
}

interface Conn { kind: 'lan' | 'tailscale' | 'public'; via: string; url: string; ip: string; country?: string; latency_ms: number; jitter_ms: number; at: number; error?: string }

const VIA: Record<string, string> = { direct: '直连', cloudflare: '经 Cloudflare', cloudfront: '经 CloudFront', fastly: '经 Fastly', proxy: '经代理' }
const zhRegion = typeof Intl !== 'undefined' && 'DisplayNames' in Intl ? new Intl.DisplayNames(['zh-CN'], { type: 'region' }) : null

// BerthConn: how Wharf reaches Berth right now, measured every 30 s while shown.
export function BerthConn() {
  const { data } = useApi<{ conn: Conn | null; urls: string[]; key_auth: boolean }>('/berth/conn', 30000)
  const c = data?.conn
  if (!data) return <span className="text-xs text-muted-foreground">正在测量…</span>
  if (!c) return null
  if (c.error) return <span className="flex items-center gap-1 text-sm text-destructive"><AlertTriangle className="size-4" />{c.error}</span>
  const tag = c.kind === 'lan' ? <Pill tone="green"><Home className="mr-0.5 inline size-3" />内网互联</Pill>
    : c.kind === 'tailscale' ? <Pill tone="green"><Waypoints className="mr-0.5 inline size-3" />Tailscale 互联（加密）</Pill>
    : <Pill tone={c.via === 'direct' ? 'blue' : 'amber'}><Globe className="mr-0.5 inline size-3" />公网互联 · {VIA[c.via] ?? c.via}</Pill>
  return (
    <div className="grid gap-1.5">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {tag}
        <span>延迟 {c.latency_ms} ms{c.jitter_ms > 0 && <span className="text-muted-foreground"> · 抖动 {c.jitter_ms} ms</span>}</span>
        {c.kind !== 'lan' && <span className="font-mono text-xs text-muted-foreground">{c.ip}{c.country && ` · ${zhRegion?.of(c.country) ?? c.country}`}</span>}
        <span className={cn('text-xs', data.key_auth ? 'text-success' : 'text-muted-foreground')}>{data.key_auth ? '· 签名不带令牌' : '· 旧版签名（Berth 升级后自动切换）'}</span>
      </div>
      {c.kind === 'public' && c.via !== 'direct' && (
        <p className="text-xs text-muted-foreground">加密在{VIA[c.via]?.replace('经 ', '') ?? '代理'}处解开，它能看到两边通信的内容。要端到端加密，请用 Tailscale 或直连端口；如果代理是你自己服务器上的反向代理，可以忽略。</p>
      )}
      {data.urls.length > 1 && <p className="text-xs text-muted-foreground">Berth 的地址（连不上时按顺序自动换）：{data.urls.map((u) => <span key={u} className={cn('mr-2 font-mono', u === c.url && 'text-foreground')}>{u}{u === c.url && ' ✓'}</span>)}</p>}
    </div>
  )
}
