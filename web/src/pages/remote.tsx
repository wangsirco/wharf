import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { AlertTriangle, ArrowRight, Check, Cloud, Earth, Home, KeyRound, Loader2, Lock, Network, ShieldHalf, Waypoints, Zap } from 'lucide-react'
import { del, get, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Pill, Section, useConfirm } from '@/components/common'
import { PanelNames } from '@/components/panel-names'
import { regionLabel } from '@/components/pickers'
import type { PasskeyList } from '@/components/login-mode'
import { TokenSteps, type Caps, type CFState } from '@/pages/cloudflare'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'

// Opening the panel from outside (Wharf ⇄ Berth §1–5): what the line allows, four ways —
// the recommended one marked — and the chosen one's steps right here, the Cloudflare tunnel
// from token to "open" in this card. Then who may come in, and passkeys on the new name.

const zhRegion = typeof Intl !== 'undefined' && 'DisplayNames' in Intl ? new Intl.DisplayNames(['zh-CN'], { type: 'region' }) : null
const placeName = (k: string) => {
  const [cc, sub] = k.split('-')
  const name = /^[A-Z]{2}$/.test(cc) ? zhRegion?.of(cc) ?? cc : regionLabel(k)
  return sub ? `${name} ${sub}` : name
}

interface Names { local: string; port: string; names: { name: string }[]; via_443: boolean; via_port: boolean; proxied: string[] | null }
interface TunnelResp { conf: { routes: { hostname: string; kind: string }[] }; router?: { installed: boolean; running: boolean; ready: number; job?: { running: boolean; error?: string } } }
interface Pub { verdict: string; external: string; wan_ip: string }
interface AccessResp { apps: { domain: string; mine: boolean }[] }
interface Tailscale { installed: boolean; running?: boolean; ips?: string[]; version?: string }
type Way = 'direct' | 'tunnel' | 'tailscale' | 'lan'

function lineSays(p?: Pub | null): { text: string; rec: Way } {
  if (!p) return { text: '正在检测家里的网络…', rec: 'lan' }
  const ip = p.wan_ip || '（没有）'
  switch (p.verdict) {
    case 'public': return { text: `WAN 口拿到的是公网 IP（${ip}），外面可以直接连进来。`, rec: 'direct' }
    case 'public_unverified': return { text: `WAN 口地址 ${ip} 看起来是公网 IP（外部服务没有确认）。`, rec: 'direct' }
    case 'cgnat': return { text: `WAN 口地址 ${ip} 是运营商内网地址（CGNAT），外面直接连不进来，建议用 Cloudflare 隧道或 Tailscale。`, rec: 'tunnel' }
    case 'modem': return { text: `路由器在光猫或上级路由后面（WAN 口 ${ip} 是内网地址），外面直接连不进来，建议用 Cloudflare 隧道或 Tailscale。`, rec: 'tunnel' }
    case 'mismatch': return { text: `WAN 口是公网地址 ${ip}，但外面看到的是 ${p.external}（中间可能有代理或二层 NAT），直连不一定通，建议用 Cloudflare 隧道。`, rec: 'tunnel' }
    case 'none': return { text: 'WAN 口没有 IPv4 地址，外面直接连不进来，建议用 Cloudflare 隧道或 Tailscale。', rec: 'tunnel' }
  }
  return { text: `WAN 口地址 ${ip}。`, rec: 'tunnel' }
}

export default function RemotePage() {
  const { data: names } = useApi<Names>('/panel/names')
  const { data: cf, reload: reloadCF } = useApi<CFState>('/cloudflare')
  const { data: tun, reload: reloadTun } = useApi<TunnelResp>(cf?.connected ? '/cloudflare/tunnel' : null)
  const { data: acc, reload: reloadAcc } = useApi<AccessResp>(cf?.connected ? '/cloudflare/access' : null)
  const { data: pub } = useApi<Pub>('/net/public?iface=wan')
  const { data: ts } = useApi<Tailscale>('/remote/tailscale')
  const { data: s } = useApi<Record<string, string>>('/settings')

  const proxied = new Set(names?.proxied ?? [])
  const tunnelNames = (tun?.conf.routes ?? []).filter((r) => r.kind === 'panel').map((r) => r.hostname)
  const open443 = !!(names?.via_443 || names?.via_port)
  const direct = open443 ? (names?.names ?? []).map((n) => n.name) : []
  const outside: [string, string][] = [...tunnelNames.map((n): [string, string] => [n, '隧道']), ...direct.map((n): [string, string] => [n, proxied.has(n) ? '橙色云' : '直连'])]
  const protectedNames = new Set((acc?.apps ?? []).map((a) => a.domain))

  const wanMode = s?.['access.wan.mode']
  let regions: string[] = []
  try { regions = JSON.parse(s?.['access.wan.regions'] || '[]') } catch { /* empty */ }
  const who = wanMode === 'all' ? '所有地区都能打开登录页' : regions.length ? `只允许 ${regions.map(placeName).join('、')}` : '公网访问已关闭'

  const line = lineSays(pub)
  const rec: Way = ts?.installed && line.rec === 'tunnel' && !cf?.connected ? 'tailscale' : line.rec
  const active: Way | null = tunnelNames.length ? 'tunnel' : direct.length ? 'direct' : ts?.running ? 'tailscale' : null
  const [way, setWay] = useState<Way | null>(null)
  const cur: Way = way ?? active ?? (pub ? rec : 'lan')

  const WAYS: [Way, typeof Zap, string, string][] = [
    ['direct', Zap, '公网直连', '用公网名字打开，路由器开放端口（可加橙色云）'],
    ['tunnel', Waypoints, 'Cloudflare 隧道', '用自己的域名，不开放任何端口，不暴露 IP'],
    ['tailscale', Network, 'Tailscale', '只有自己的设备能连上，最省心'],
    ['lan', Home, '只在局域网', '默认；以后随时能改'],
  ]
  const recOf = (w: Way) => !!pub && (w === rec || (w === 'tailscale' && !!ts?.installed && line.rec === 'tunnel'))

  return (
    <div className="grid gap-4">
      <PageHeader title="外网访问" desc="从家外面打开这个面板：现在的情况、选一种方式、谁能进来。" />

      <section className="flex flex-wrap items-start gap-3 rounded-2xl border bg-card p-4">
        <span className={cn('grid size-10 shrink-0 place-items-center rounded-xl', outside.length ? 'bg-success/12 text-success' : 'bg-muted text-muted-foreground')}>
          {outside.length ? <Earth className="size-5" /> : <Home className="size-5" />}
        </span>
        <div className="grid min-w-0 flex-1 gap-1">
          <div className="font-semibold">{outside.length ? '外面可以打开面板' : '现在只能在家里打开'}</div>
          <div className="text-sm text-muted-foreground">
            {outside.length
              ? <>通过 {outside.map(([n, how], i) => <span key={n}>{i > 0 && '、'}<span className="font-mono text-foreground">{n}</span>（{how}{protectedNames.has(n) ? ' · 有邮箱验证' : ''}）</span>)}。{who}。</>
              : <>在家里用 <span className="font-mono text-foreground">{names ? `https://${names.local}` : 'wharf.lan'}</span> 打开。</>}
          </div>
          <div className="text-sm">{line.text}</div>
        </div>
      </section>

      <Section title="选一种方式">
        <div className="grid gap-2 p-4 sm:grid-cols-2 xl:grid-cols-4">
          {WAYS.map(([k, Icon, t, d]) => (
            <button key={k} type="button" onClick={() => setWay(k)}
              className={cn('grid content-start gap-1 rounded-xl border p-3 text-left transition-colors hover:border-primary/50', cur === k && 'border-primary bg-accent/40 ring-2 ring-primary/20')}>
              <span className="flex items-center gap-2">
                <Icon className="size-4 text-primary" /><span className="text-sm font-medium">{t}</span>
                {recOf(k) && <Pill tone="blue">推荐</Pill>}
                {active === k && <Pill tone="green"><Check className="mr-0.5 inline size-3" />在用</Pill>}
              </span>
              <span className="text-xs text-muted-foreground">{d}</span>
            </button>
          ))}
        </div>
        <div className="border-t p-4">
          {cur === 'direct' && <DirectWay pub={pub} />}
          {cur === 'tunnel' && <TunnelWay cf={cf} tun={tun} access={acc} reload={() => { reloadCF(); reloadTun(); reloadAcc() }} />}
          {cur === 'tailscale' && <TailscaleWay ts={ts} />}
          {cur === 'lan' && <LanWay outside={outside} />}
        </div>
      </Section>

      <PasskeysOutside names={outside.map(([n]) => n)} />

      <Section title="谁能进来" desc="不管哪种方式，从外面来的访问都要先过这几道">
        <div className="grid gap-3 p-4 md:grid-cols-2">
          <div className="grid content-start gap-2 rounded-xl border p-3">
            <div className="flex items-center gap-2 text-sm font-medium"><ShieldHalf className="size-4 text-primary" />面板访问控制</div>
            <p className="text-sm text-muted-foreground">{who}。经隧道或橙色云来的访客按真实 IP 判断。也可以按 IP 放行或拉黑、检查浏览器时区。</p>
            <Button size="sm" variant="outline" className="justify-self-start" render={<Link to="/access" />}>修改 <ArrowRight /></Button>
          </div>
          <div className="grid content-start gap-2 rounded-xl border p-3">
            <div className="flex items-center gap-2 text-sm font-medium"><Lock className="size-4 text-primary" />Cloudflare Access 邮箱验证（可选）</div>
            <p className="text-sm text-muted-foreground">
              {!cf?.connected ? '经 Cloudflare 打开时（隧道或橙色云），先过一道邮箱验证码。需要先连接 Cloudflare。'
                : protectedNames.size ? <>已保护：{[...protectedNames].map((n) => <Pill key={n}>{n}</Pill>)}。Berth 调用面板的接口自动放行（接口自带签名）。</> : '经 Cloudflare 打开时，先过一道邮箱验证码，陌生人连登录页都看不到。'}
            </p>
            <Button size="sm" variant="outline" className="justify-self-start" render={<Link to={cf?.connected ? '/cloudflare?tab=access' : '/cloudflare'} />}>{cf?.connected ? '设置' : '连接 Cloudflare'} <ArrowRight /></Button>
          </div>
        </div>
      </Section>
    </div>
  )
}

function Steps({ items }: { items: ReactNode[] }) {
  return <ol className="ml-4 list-decimal space-y-1 text-sm text-muted-foreground">{items.map((x, i) => <li key={i}>{x}</li>)}</ol>
}

function DirectWay({ pub }: { pub?: Pub | null }) {
  const noPublic = pub && !['public', 'public_unverified'].includes(pub.verdict)
  return (
    <div className="grid gap-3">
      {noPublic && <p className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />家里现在不是公网 IP，直连多半连不上；除非开了橙色云（经 Cloudflare 回源也需要公网 IP）。建议改用 Cloudflare 隧道。</p>}
      <Steps items={['添加一个公网名字（例如 wharf.example.com），面板自动申请证书', '选经 443（不带端口）还是面板端口；想藏起家里 IP 就给名字开橙色云', '家里 IP 会变的话，给名字加上 DDNS']} />
      <PanelNames />
    </div>
  )
}

function TailscaleWay({ ts }: { ts?: Tailscale | null }) {
  if (!ts) return <Loader2 className="animate-spin" />
  if (!ts.installed) return (
    <div className="grid gap-2 text-sm">
      <p>路由器上还没有装 Tailscale。装好以后，只有登录了你的 Tailscale 账号的设备能连进来，不用开端口、不用域名。</p>
      <Steps items={['在「插件 → 插件商店」搜 tailscale 安装', '在路由器上运行 tailscale up，用浏览器登录你的 Tailscale 账号', '在 Tailscale 后台把路由器设为子网路由（advertise routes 家里的网段），手机电脑装上 Tailscale 就能用 https://wharf.lan 打开']} />
      <Button size="sm" variant="outline" className="justify-self-start" render={<Link to="/plugins?tab=store&q=tailscale" />}>去插件商店 <ArrowRight /></Button>
    </div>
  )
  return (
    <div className="grid gap-2 text-sm">
      <p className="flex flex-wrap items-center gap-2">Tailscale {ts.version && <span className="text-muted-foreground">{ts.version}</span>}{ts.running ? <Pill tone="green">在运行</Pill> : <Pill tone="amber">没在运行</Pill>}{ts.ips?.map((ip) => <span key={ip} className="font-mono text-xs">{ip}</span>)}</p>
      <Steps items={['手机电脑装上 Tailscale，登录同一个账号', '路由器作为子网路由时，在外面也能直接用 https://wharf.lan 打开（Tailscale 后台把 lan 域名的 DNS 指向路由器）', `否则用路由器的 Tailscale 地址打开：${ts.ips?.[0] ? `https://${ts.ips[0]}:7080` : '（还没有地址）'}，这时 Passkey 用不了`]} />
      <p className="text-xs text-muted-foreground">Wharf 只显示 Tailscale 的状态，不替你管理它；经 Tailscale 来的访问算家里的访问。</p>
    </div>
  )
}

function LanWay({ outside }: { outside: [string, string][] }) {
  return (
    <div className="grid gap-2 text-sm">
      <p>只在家里用 https://wharf.lan 打开，外面谁也连不进来。</p>
      {outside.length ? <p className="text-muted-foreground">现在还开着：{outside.map(([n, how]) => `${n}（${how}）`).join('、')}。要关掉，选上面对应的方式，在那里停止。</p> : <p className="text-muted-foreground">现在就是这样。</p>}
    </div>
  )
}

// ---- Cloudflare tunnel, start to finish in this card ----

function TunnelWay({ cf, tun, access, reload }: { cf?: CFState | null; tun?: TunnelResp | null; access?: AccessResp | null; reload: () => void }) {
  const { data: capsResp, reload: reloadCaps } = useApi<{ connected: boolean; caps?: Caps }>(cf?.connected ? '/cloudflare/caps' : null)
  const [tokenOpen, setTokenOpen] = useState(false)
  if (!cf) return <Loader2 className="animate-spin" />
  const tokenDialog = (
    <Dialog open={tokenOpen} onOpenChange={setTokenOpen}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogTitle>{cf.connected ? '更换 Cloudflare 令牌' : '连接 Cloudflare'}</DialogTitle>
        <p className="text-xs text-muted-foreground">隧道必须的权限：区域 · Zone · 读取、区域 · DNS · 编辑、账户 · Cloudflare Tunnel · 编辑；推荐再加账户 · Access: Apps and Policies · 编辑（邮箱验证）。域名要托管在 Cloudflare。</p>
        <TokenSteps createUrl={cf.create_url} replace={cf.connected} onDone={() => { setTokenOpen(false); reload(); reloadCaps() }} />
      </DialogContent>
    </Dialog>
  )
  if (!cf.connected) return (
    <div className="grid gap-3">
      <Steps items={['在 Cloudflare 创建一个 API 令牌（下面会列出要勾的权限）', '粘贴到这里', '选一个名字，一键开放']} />
      <p className="text-xs text-muted-foreground">域名要托管在 Cloudflare（免费方案即可）。</p>
      <Button className="justify-self-start" onClick={() => setTokenOpen(true)}><Cloud /> 连接 Cloudflare</Button>
      {tokenDialog}
    </div>
  )
  const caps = capsResp?.caps
  if (!caps) return <Loader2 className="animate-spin" />
  const missing = [!caps.zones && '区域 · Zone · 读取（看不到任何域名）', !caps.dns && '区域 · DNS · 编辑', !caps.tunnel && '账户 · Cloudflare Tunnel · 编辑'].filter(Boolean) as string[]
  const opened = (tun?.conf.routes ?? []).filter((r) => r.kind === 'panel').map((r) => r.hostname)
  return (
    <div className="grid gap-4">
      {missing.length > 0 && (
        <div className="flex flex-wrap items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-destructive" />
          <span className="min-w-0 flex-1">这个令牌缺少：{missing.join('、')}。在 Cloudflare 编辑令牌补上后点「再检查一次」，或者换一个令牌。</span>
          <Button size="sm" variant="outline" onClick={() => get('/cloudflare/caps?fresh=1').then(reloadCaps)}>再检查一次</Button>
          <Button size="sm" onClick={() => setTokenOpen(true)}>更换令牌</Button>
        </div>
      )}
      {opened.map((h) => <OpenedTunnel key={h} host={h} access={!!access?.apps.some((a) => a.domain === h)} reload={reload} />)}
      {missing.length === 0 && !opened.length && <OpenTunnelForm caps={caps} zones={cf.zones} router={tun?.router} onDone={reload} />}
      {missing.length === 0 && opened.length > 0 && <p className="text-xs text-muted-foreground">要用别的名字，先停止当前这个；家里其他服务经隧道公开，在「Cloudflare → 隧道」里加。</p>}
      <p className="text-xs text-muted-foreground">路由器不想跑 cloudflared？以后可以借 Berth 服务器上已有的隧道开放面板（和 Berth 一起设计中）。</p>
      {tokenDialog}
    </div>
  )
}

function OpenTunnelForm({ caps, zones, router, onDone }: { caps: Caps; zones: { id: string; name: string }[]; router?: TunnelResp['router']; onDone: () => void }) {
  const { data: sys } = useApi<{ mem_total: number }>('/system')
  const [label, setLabel] = useState('wharf')
  const [zone, setZone] = useState(zones[0]?.id ?? '')
  const accessOK = caps.access === 'ok'
  const [useAccess, setUseAccess] = useState(accessOK)
  const [emails, setEmails] = useState('')
  const [step, setStep] = useState('')
  const { confirm, dialog } = useConfirm()
  const zoneName = zones.find((z) => z.id === zone)?.name ?? ''
  const host = `${label}.${zoneName}`
  const memMB = sys ? Math.round(sys.mem_total / 1048576) : 0

  const run = async () => {
    try {
      if (!router?.installed) {
        setStep('在路由器上安装 cloudflared（从 Cloudflare 官方发布页下载并校验）…')
        try { await post('/cloudflare/tunnel/router', { action: 'install' }) } catch (e) {
          if (!((e as { data?: { mem_low?: boolean } }).data?.mem_low)) throw e
          if (!(await confirm('路由器内存不多', (e as Error).message, { ok: '仍然安装' }))) { setStep(''); return }
          await post('/cloudflare/tunnel/router', { action: 'install', force: true })
        }
        for (let i = 0; i < 90; i++) {
          await new Promise((r) => setTimeout(r, 2000))
          const t = await get<TunnelResp>('/cloudflare/tunnel')
          if (t.router?.job?.error) throw new Error('cloudflared 安装失败：' + t.router.job.error)
          if (t.router?.installed && !t.router.job?.running) break
          if (i === 89) throw new Error('cloudflared 3 分钟还没装好，请稍后到「Cloudflare → 隧道」看看')
        }
      }
      setStep('建隧道、加 DNS 记录、设路由' + (useAccess ? '、设邮箱验证' : '') + '…')
      const body = { label, zone_id: zone, access: useAccess, emails: emails.split(/[\s,，]+/).filter(Boolean) }
      try { await post('/remote/tunnel', body) } catch (e) {
        if (!((e as { data?: { conflict?: boolean } }).data?.conflict)) throw e
        if (!(await confirm('名字已经有解析记录', (e as Error).message + ' 要换成指向隧道吗？', { ok: '替换' }))) { setStep(''); return }
        await post('/remote/tunnel', { ...body, replace: true })
      }
      toast.success(`已开放：https://${host}`)
      onDone()
    } catch (e) { toast.error((e as Error).message) } finally { setStep('') }
  }

  return (
    <div className="grid gap-3">
      <div className="grid gap-1">
        <div className="text-sm font-medium">名字</div>
        <div className="flex flex-wrap items-center gap-1">
          <Input className="h-9 w-36 font-mono" value={label} onChange={(e) => setLabel(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))} />
          <span>.</span>
          <select className="h-9 rounded-md border bg-background px-2 text-sm" value={zone} onChange={(e) => setZone(e.target.value)}>
            {zones.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
          </select>
        </div>
        <div className="font-mono text-sm text-muted-foreground">https://{host}</div>
      </div>
      <label className={cn('flex items-start gap-2 rounded-lg border p-3', !accessOK && 'opacity-60')}>
        <Checkbox className="mt-0.5" disabled={!accessOK} checked={useAccess} onCheckedChange={(c) => setUseAccess(!!c)} />
        <span className="grid gap-1">
          <span className="text-sm font-medium">打开前先验证邮箱（Cloudflare Access） <Pill tone="blue">推荐</Pill></span>
          <span className="text-xs text-muted-foreground">{accessOK ? '只有下面这些邮箱能收到验证码；Berth 调用面板的接口会自动放行。' : caps.access === 'not_enabled' ? 'Cloudflare 账户还没开通 Zero Trust（免费方案即可），开通后再回来。' : '令牌缺少「账户 · Access: Apps and Policies · 编辑」权限。'}</span>
          {useAccess && <Input className="h-8" placeholder="you@example.com，多个用逗号隔开；@example.com 表示整个域名" value={emails} onChange={(e) => setEmails(e.target.value)} />}
        </span>
      </label>
      {!useAccess && <p className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />任何人打开这个地址都能看到登录页（「面板访问控制」仍按地区和 IP 拦）。建议给账号用 Passkey 或「密码 + Passkey」。</p>}
      <div className="rounded-lg bg-muted/30 p-3">
        <div className="mb-1 text-xs font-medium">点下面的按钮后会：</div>
        <Steps items={[
          router?.installed ? '用路由器上已装的 cloudflared' : `在路由器上安装 cloudflared（约 30–50 MB 内存${memMB ? `；这台有 ${memMB} MB` : ''}，令牌只存在 root 能读的地方）`,
          '在 Cloudflare 建一条隧道（已有就共用），加一条指向它的橙色云 DNS 记录',
          '证书由 Cloudflare 边缘提供，路由器不用申请；访客经本机 cloudflared 进来，按真实 IP 判断访问控制',
          useAccess ? '建邮箱验证，并放行 Berth 调用面板的接口' : '不加邮箱验证',
          '告诉 Berth 面板的公网名字变了',
        ]} />
        <p className="mt-1 text-xs text-muted-foreground">任何一步失败，都会撤回已做的改动；以后点「停止」一次删干净。</p>
      </div>
      <Button className="justify-self-start" disabled={!!step || !label || !zone || (useAccess && !emails.trim())} onClick={run}>{step ? <Loader2 className="animate-spin" /> : <Waypoints />} 通过隧道开放面板</Button>
      {step && <p className="text-sm text-muted-foreground">{step}</p>}
      {dialog}
    </div>
  )
}

function OpenedTunnel({ host, access, reload }: { host: string; access: boolean; reload: () => void }) {
  const { confirm, dialog } = useConfirm()
  const [busy, setBusy] = useState(false)
  const stop = async () => {
    if (!(await confirm(`停止经隧道开放 ${host}？`, '删除这个名字的 DNS 记录、隧道路由和邮箱验证。外面就打不开面板了（家里不受影响）。', { danger: true, ok: '停止' }))) return
    setBusy(true)
    try { await del(`/remote/tunnel?hostname=${encodeURIComponent(host)}`); toast.success('已停止'); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <div className="grid gap-2 rounded-xl border border-success/40 bg-success/5 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Waypoints className="size-4 text-success" /><a className="font-mono text-primary hover:underline" href={`https://${host}`} target="_blank" rel="noreferrer">https://{host}</a>
        <Pill tone={access ? 'green' : 'amber'}>邮箱验证：{access ? '有' : '无'}</Pill>
        <Button size="sm" variant="outline" className="ml-auto text-destructive" disabled={busy} onClick={stop}>停止经隧道开放</Button>
      </div>
      <PasskeyHint host={host} />
      {dialog}
    </div>
  )
}

// ---- passkeys follow names ----

/** "No passkey of yours on this name yet" + carry the sign-in there to add one. */
export function PasskeyHint({ host }: { host: string }) {
  const { data } = useApi<PasskeyList>('/me/passkeys')
  if (!data || data.passkeys.some((p) => p.rp_id === host)) return null
  const elsewhere = [...new Set(data.passkeys.map((p) => p.rp_id))]
  const go = async () => {
    const w = window.open('about:blank', '_blank')
    try { const r = await post<{ url: string }>('/me/hop', { to: host, path: '/account?passkey=add' }); if (w) w.location.href = r.url; else location.href = r.url }
    catch (e) { w?.close(); toast.error((e as Error).message) }
  }
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg bg-amber-500/10 px-3 py-2 text-sm">
      <KeyRound className="size-4 shrink-0 text-amber-600" />
      <span className="min-w-0 flex-1">{host} 上还没有你的 Passkey{elsewhere.length ? `。你的 Passkey 在 ${elsewhere.join('、')} 上，Passkey 跟着名字走` : ''}。趁现在在家、登录着，加上一个，以后在外面也能用。</span>
      <Button size="sm" onClick={go}>去 {host} 添加 Passkey</Button>
    </div>
  )
}

function PasskeysOutside({ names }: { names: string[] }) {
  if (!names.length) return null
  return (
    <Section title="在外面用的名字上添加 Passkey" desc="Passkey 只在添加它的名字上有效。点按钮会带着现在的登录状态打开那个名字，直接停在添加 Passkey 的地方（链接 60 秒内有效，只能用一次）。">
      <div className="grid gap-2 p-4">{names.map((n) => <PasskeyHint key={n} host={n} />)}<AllSet names={names} /></div>
    </Section>
  )
}

function AllSet({ names }: { names: string[] }) {
  const { data } = useApi<PasskeyList>('/me/passkeys')
  if (!data || !names.every((n) => data.passkeys.some((p) => p.rp_id === n))) return null
  return <p className="flex items-center gap-1.5 text-sm text-success"><Check className="size-4" />每个在外面用的名字上都有你的 Passkey。</p>
}
