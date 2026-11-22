import { useEffect, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import {
  BarChart3, Check, Cloud, Download, ExternalLink, Globe, Loader2, Lock, Plus, RefreshCw, ShieldAlert, ShieldCheck, Trash2, Waypoints, X,
} from 'lucide-react'
import { del, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { bytes } from '@/lib/format'
import { useBerth } from '@/lib/berth'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Dot, Empty, Field, Pill, Section, useConfirm } from '@/components/common'
import { AreaChart } from '@/components/chart'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

interface CFState { connected: boolean; token: string; create_url: string; zones: { id: string; name: string }[]; error?: string }
interface Caps {
  account?: { id: string; name: string }; zones: boolean; dns: boolean; tunnel: boolean; access: 'ok' | 'denied' | 'not_enabled'
  settings: boolean; analytics: boolean; errors?: Record<string, string>; checked: number
}

const TOKEN_PAGE = 'https://dash.cloudflare.com/profile/api-tokens'

// [what Cloudflare calls it, what it is for here, required]
const PERMS: [string, string, boolean][] = [
  ['区域 · 区域 · 读取（Zone · Zone · Read）', '看到你的域名', true],
  ['区域 · DNS · 编辑（Zone · DNS · Edit）', '解析记录、DDNS、证书验证', true],
  ['区域 · SSL 和证书 · 编辑（Zone · SSL and Certificates · Edit）', '橙色云时的回源证书', false],
  ['账户 · Cloudflare Tunnel · 编辑（Account · Cloudflare Tunnel · Edit）', '隧道', false],
  ['账户 · Access: 应用和策略 · 编辑（Account · Access: Apps and Policies · Edit）', 'Access 登录保护', false],
  ['区域 · 区域设置 · 编辑（Zone · Zone Settings · Edit）', '受攻击模式', false],
  ['区域 · 缓存清除 · 清除（Zone · Cache Purge · Purge）', '清除缓存', false],
  ['区域 · Analytics · 读取（Zone · Analytics · Read）', '流量统计', false],
  ['区域 · Origin Rules · 编辑（Zone · Origin Rules · Edit）', '面板域名走橙色云', false],
]

const TABS = [['', '连接与令牌'], ['tunnel', '隧道'], ['zones', '域名与防攻击'], ['access', 'Access 登录保护']] as const

export default function CloudflarePage() {
  const { data, reload } = useApi<CFState>('/cloudflare')
  const [q, setQ] = useSearchParams()
  const tab = q.get('tab') ?? ''
  const berth = useBerth()
  if (!data) return <PageHeader title="Cloudflare" />
  if (!data.connected) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Cloudflare" desc="域名解析、隧道、防攻击、登录保护，在面板里一键完成。" />
        <Welcome createUrl={data.create_url} onDone={reload} />
      </div>
    )
  }
  return (
    <div className="grid gap-4">
      <PageHeader title="Cloudflare" desc={`已连接 · ${data.zones.length} 个域名`}>
        <Tabs value={tab} onValueChange={(v) => setQ(v ? { tab: String(v) } : {})}>
          <TabsList>{TABS.map(([k, l]) => <TabsTrigger key={k} value={k} className="px-3">{l}</TabsTrigger>)}</TabsList>
        </Tabs>
      </PageHeader>
      {berth.paired && (
        <p className="flex items-start gap-2 rounded-lg border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
          <Cloud className="mt-0.5 size-3.5 shrink-0" />
          Berth「{berth.name}」也可以管理 Cloudflare。这里显示的都是 Cloudflare 上的实时状态，两边看到的是同一份；Wharf 只改自己建的东西（它的隧道、指向隧道的记录、名为「Wharf · …」的 Access 应用），Berth 建的会标出来、只读。
        </p>
      )}
      {tab === '' && <Account data={data} reload={reload} />}
      {tab === 'tunnel' && <Tunnel zones={data.zones} />}
      {tab === 'zones' && <Zones />}
      {tab === 'access' && <Access />}
    </div>
  )
}

// ---- before connecting ----

const WHAT = [
  [Waypoints, 'Cloudflare 隧道', '不开端口、不暴露家里 IP，没有公网 IP 也能从外面打开面板和家里的服务'],
  [Globe, '自动解析与 DDNS', '选域名就能建记录、接管已有记录，家里 IP 变了自动更新'],
  [Lock, 'Access 登录保护', '打开面板前先过一道 Cloudflare 邮箱验证码，陌生人连登录页都看不到'],
  [ShieldAlert, '防攻击', '一键开「我正受到攻击」模式、清缓存'],
  [BarChart3, '边缘统计', '最近 7 天的请求、流量、拦截的威胁'],
  [ShieldCheck, '真实访客 IP', '经 Cloudflare 来的访客，访问控制和记录都按真实 IP'],
] as const

function Welcome({ createUrl, onDone }: { createUrl: string; onDone: () => void }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="grid gap-4">
      <Section title="连接 Cloudflare">
        <div className="grid gap-4 p-4">
          <p className="text-sm">把你的 Cloudflare 账号接进来，域名解析、隧道、防攻击、登录保护都能在面板里一键完成，不用在两个后台之间来回切。</p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {WHAT.map(([Icon, t, d]) => (
              <div key={t} className="flex gap-2.5 rounded-xl border p-3">
                <Icon className="mt-0.5 size-4 shrink-0 text-primary" />
                <div><div className="text-sm font-medium">{t}</div><div className="text-xs text-muted-foreground">{d}</div></div>
              </div>
            ))}
          </div>
          {!open && <div><Button onClick={() => setOpen(true)}>开始连接</Button></div>}
          <p className="text-xs text-muted-foreground">Cloudflare 免费版就够用。令牌只保存在路由器上的面板数据库里，界面和审计里都打码，随时可以在 Cloudflare 撤销。</p>
        </div>
      </Section>
      {open && <TokenSteps createUrl={createUrl} onDone={onDone} />}
    </div>
  )
}

function TokenSteps({ createUrl, onDone, replace }: { createUrl: string; onDone: () => void; replace?: boolean }) {
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try { await post('/cloudflare', { token }); toast.success(replace ? '令牌已更换' : '已连接 Cloudflare'); onDone() }
    catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <Section title={replace ? '更换令牌' : '两步连上'}>
      <div className="grid gap-4 p-4 text-sm">
        <div className="grid gap-2">
          <div className="font-medium">① 在 Cloudflare 创建一个 API 令牌（不是 Global API Key）</div>
          <p className="text-muted-foreground">
            点下面的按钮，Cloudflare 会打开创建页面，必需的权限已经选好。要用隧道、登录保护等功能，再按表格「添加更多」对应的权限；「账户资源」选你的账户，「区域资源」选「所有区域」。滚到最下面点「继续」→「创建令牌」。
          </p>
          <div className="flex flex-wrap gap-2">
            <Button render={<a href={createUrl} target="_blank" rel="noreferrer" />}><ExternalLink /> 打开 Cloudflare 创建令牌</Button>
            <Button variant="ghost" render={<a href={TOKEN_PAGE} target="_blank" rel="noreferrer" />}>令牌列表</Button>
          </div>
          <div className="overflow-hidden rounded-lg border">
            {PERMS.map(([p, d, req]) => (
              <div key={p} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 border-b px-3 py-1.5 text-xs last:border-b-0">
                <span className="min-w-0 flex-1 font-mono">{p}</span>
                <span className="text-muted-foreground">{d}</span>
                <Pill tone={req ? 'blue' : 'muted'}>{req ? '必需' : '可选'}</Pill>
              </div>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">可选的权限不勾也能用，对应的功能会提示「缺少权限」，以后随时可以在 Cloudflare 编辑这个令牌补上，不用重新粘贴。</p>
        </div>
        <div className="grid gap-2">
          <div className="font-medium">② 把令牌粘贴到这里</div>
          <div className="flex gap-2">
            <Input type="password" autoComplete="off" placeholder="Cloudflare API 令牌" value={token} onChange={(e) => setToken(e.target.value.trim())} />
            <Button disabled={busy || !token} onClick={save}>{busy && <Loader2 className="animate-spin" />}保存并检查</Button>
          </div>
          <p className="text-xs text-muted-foreground">保存后马上检查这个令牌能做什么，缺的权限会列出来。</p>
        </div>
      </div>
    </Section>
  )
}

// ---- account & token ----

function CapRow({ ok, label, hint, warn }: { ok: boolean; label: string; hint: ReactNode; warn?: ReactNode }) {
  return (
    <div className="flex items-start gap-3 border-b px-4 py-2.5 last:border-b-0">
      {ok ? <Check className="mt-0.5 size-4 shrink-0 text-success" /> : <X className="mt-0.5 size-4 shrink-0 text-muted-foreground" />}
      <div className="min-w-0 flex-1">
        <div className={cn('text-sm', !ok && 'text-muted-foreground')}>{label}</div>
        <div className="text-xs text-muted-foreground">{ok ? hint : warn ?? hint}</div>
      </div>
    </div>
  )
}

function Account({ data, reload }: { data: CFState; reload: () => void }) {
  const [fresh, setFresh] = useState(0)
  const { data: c, loading } = useApi<{ connected: boolean; caps?: Caps }>(`/cloudflare/caps${fresh ? `?fresh=1&n=${fresh}` : ''}`)
  const [replace, setReplace] = useState(false)
  const { confirm, dialog } = useConfirm()
  const caps = c?.caps
  const disconnect = async () => {
    if (!(await confirm('断开 Cloudflare？', '令牌会从面板里删掉。已经建好的 DNS 记录、隧道和 Access 应用都留在 Cloudflare 上不动。', { danger: true, ok: '断开' }))) return
    try { await post('/cloudflare', { token: '' }); toast.success('已断开'); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const need = (p: string) => <>缺少权限：在 Cloudflare 编辑这个令牌，加上「{p}」</>
  return (
    <div className="grid items-start gap-4 xl:grid-cols-2">
      {dialog}
      <Section title="令牌能做什么" desc={caps?.account ? `账户：${caps.account.name}` : undefined}
        action={<Button size="sm" variant="ghost" disabled={loading} onClick={() => setFresh((n) => n + 1)}>{loading ? <Loader2 className="animate-spin" /> : <RefreshCw />} 重新检查</Button>}>
        {!caps ? <div className="p-4 text-sm text-muted-foreground">正在检查…</div> : (
          <div>
            <CapRow ok={caps.zones} label={`看到域名（${data.zones.length} 个）`} hint={data.zones.map((z) => z.name).join('、')} warn="令牌看不到任何域名：「区域资源」请选「所有区域」" />
            <CapRow ok={caps.dns} label="解析记录、DDNS、证书验证" hint="可以建、改、删解析记录" warn={need('区域 · DNS · 编辑')} />
            <CapRow ok={caps.tunnel} label="隧道" hint="可以建隧道、配置路由" warn={need('账户 · Cloudflare Tunnel · 编辑')} />
            <CapRow ok={caps.access === 'ok'} label="Access 登录保护" hint="可以给面板加邮箱验证码"
              warn={caps.access === 'not_enabled' ? '令牌有权限，但这个账户还没开通 Zero Trust：Cloudflare 后台左侧「Zero Trust」→ 选免费方案 → 起一个团队名' : need('账户 · Access: Apps and Policies · 编辑')} />
            <CapRow ok={caps.settings} label="受攻击模式" hint="可以切换安全级别" warn={need('区域 · Zone Settings · 编辑')} />
            <CapRow ok={caps.analytics} label="流量统计" hint="可以看最近 7 天的边缘统计" warn={need('区域 · Analytics · 读取')} />
            {caps.errors && Object.keys(caps.errors).length > 0 && (
              <div className="px-4 py-2 text-xs text-destructive">{Object.values(caps.errors).join('；')}</div>
            )}
          </div>
        )}
      </Section>
      <Section title="令牌" desc={`当前令牌：${data.token}`}>
        <div className="grid gap-3 p-4 text-sm">
          <p className="text-muted-foreground">在 Cloudflare 给这个令牌补权限后，点左边「重新检查」就生效，不用重新粘贴。令牌泄露或想换账户时再更换。</p>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => setReplace(!replace)}>更换令牌</Button>
            <Button variant="ghost" render={<a href={TOKEN_PAGE} target="_blank" rel="noreferrer" />}><ExternalLink /> 在 Cloudflare 编辑令牌</Button>
            <Button variant="ghost" className="text-destructive" onClick={disconnect}>断开</Button>
          </div>
          <p className="text-xs text-muted-foreground">DDNS 记录的快速添加和接管在「动态域名 DDNS」页；面板的公网域名在「系统设置 → 面板域名」。</p>
        </div>
      </Section>
      {replace && <div className="xl:col-span-2"><TokenSteps createUrl={data.create_url} replace onDone={() => { setReplace(false); reload(); setFresh((n) => n + 1) }} /></div>}
    </div>
  )
}

// ---- tunnel ----

interface Route { hostname: string; kind: 'panel' | 'lan'; service: string; no_verify?: boolean; zone_id: string; created: number }
interface RouterTunnel { installed: boolean; version: string; asset: string; free_mb: number; has_token: boolean; running: boolean; ready: number; job: { running: boolean; action: string; log: string[] | null; error?: string }; log?: string[] }
interface CFTunnel { id: string; name: string; status: string; connections: { colo_name: string }[] | null }
interface TunnelResp {
  conf: { account_id: string; id: string; name: string; routes: Route[] }; default_name: string
  router?: RouterTunnel; router_error?: string; tunnels?: CFTunnel[]; tunnels_error?: string; tunnels_denied?: boolean
}

function Tunnel({ zones }: { zones: { id: string; name: string }[] }) {
  const { data, reload } = useApi<TunnelResp>('/cloudflare/tunnel')
  const [busy, setBusy] = useState(false)
  const { confirm, dialog } = useConfirm()
  const [form, setForm] = useState({ sub: 'wharf', zone: '', kind: 'panel' as 'panel' | 'lan', service: '', no_verify: false })
  const rt = data?.router
  useEffect(() => { if (rt?.job.running) { const t = setTimeout(reload, 1500); return () => clearTimeout(t) } }, [rt, reload])
  useEffect(() => { if (!form.zone && zones.length) setForm((f) => ({ ...f, zone: zones[0].name })) }, [zones, form.zone])
  if (!data) return <div className="text-sm text-muted-foreground">加载中…</div>

  const router = async (action: string) => {
    setBusy(true)
    try { await post('/cloudflare/tunnel/router', { action }); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const host = (form.sub ? form.sub + '.' : '') + form.zone
  const add = async (replace = false) => {
    setBusy(true)
    try {
      await post('/cloudflare/tunnel/routes', { hostname: host, kind: form.kind, service: form.service, no_verify: form.no_verify, replace })
      toast.success(`${host} 已经接到隧道上，一两分钟后生效`); reload()
    } catch (e) {
      const msg = (e as Error).message
      if (/替换成指向隧道/.test(msg) && (await confirm('替换已有的解析记录？', msg, { ok: '替换' }))) { setBusy(false); return add(true) }
      toast.error(msg)
    } finally { setBusy(false) }
  }
  const remove = async (r: Route) => {
    if (!(await confirm(`从隧道撤下 ${r.hostname}？`, '对应的 DNS 记录也会删除，外面就打不开这个名字了。', { danger: true, ok: '撤下' }))) return
    try { await del(`/cloudflare/tunnel/routes?hostname=${encodeURIComponent(r.hostname)}`); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const removeTunnel = async () => {
    if (!(await confirm('删除这条隧道？', 'Cloudflare 上的隧道和路由器上的令牌都会删除；cloudflared 程序保留，可以在上面单独删。', { danger: true, ok: '删除' }))) return
    try { await del('/cloudflare/tunnel'); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const others = (data.tunnels ?? []).filter((t) => t.id !== data.conf.id)
  const mine = (data.tunnels ?? []).find((t) => t.id === data.conf.id)
  const healthy = !!rt?.running && rt.ready > 0

  return (
    <div className="grid gap-4">
      {dialog}
      <Section title="什么时候用隧道" desc="三种从外面打开面板的方式，按家里的情况选">
        <div className="grid gap-3 p-4 text-sm sm:grid-cols-3">
          <div className="rounded-xl border border-primary/40 bg-accent/30 p-3"><div className="font-medium">隧道（这里）</div><div className="text-xs text-muted-foreground">没有公网 IP、运营商封了端口、不想暴露家里 IP 时用。不开任何端口；访客 IP、访问控制照常。</div></div>
          <div className="rounded-xl border p-3"><div className="font-medium">橙色云</div><div className="text-xs text-muted-foreground">有公网 IP，想藏起家里 IP、要 Cloudflare 防护。在「系统设置 → 面板域名」里设。</div></div>
          <div className="rounded-xl border p-3"><div className="font-medium">直连</div><div className="text-xs text-muted-foreground">有公网 IP，图最快最简单。同样在「系统设置 → 面板域名」，配合 DDNS。</div></div>
        </div>
      </Section>

      <Section title="路由器上的 cloudflared" desc="从 Cloudflare 官方 GitHub 下载最新版，放在数据盘，以 nobody 身份运行；卸载 Wharf 时一并删除。"
        action={rt?.installed && <div className="flex gap-1.5">
          <Button size="sm" variant="ghost" disabled={busy || rt.job.running} onClick={() => router('update')}><Download /> 检查更新</Button>
          {rt.has_token && <Button size="sm" variant="ghost" disabled={busy} onClick={() => router('restart')}><RefreshCw /> 重启</Button>}
          {!data.conf.routes.length && <Button size="sm" variant="ghost" className="text-destructive" disabled={busy || rt.job.running} onClick={() => router('uninstall')}><Trash2 /> 删除</Button>}
        </div>}>
        <div className="grid gap-3 p-4 text-sm">
          {data.router_error && <p className="text-destructive">{data.router_error}</p>}
          {rt && !rt.installed && !rt.job.running && (
            <div className="flex flex-wrap items-center gap-3">
              <Button disabled={busy} onClick={() => router('install')}><Download /> 安装 cloudflared</Button>
              <span className="text-xs text-muted-foreground">约 40 MB（{rt.asset}），数据盘剩余 {rt.free_mb} MB</span>
            </div>
          )}
          {rt?.installed && (
            <div className="flex flex-wrap items-center gap-2">
              <Dot tone={healthy ? 'ok' : rt.running ? 'warn' : 'off'} />
              <span>cloudflared {rt.version}</span>
              <span className="text-muted-foreground">·</span>
              <span className="text-muted-foreground">{!rt.has_token ? '还没有隧道，添加第一个名字时自动创建' : healthy ? `已连上 Cloudflare（${rt.ready} 条连接）` : rt.running ? '正在连接 Cloudflare…' : '没有运行'}</span>
            </div>
          )}
          {rt?.log?.length ? <pre className="overflow-x-auto rounded-lg bg-muted/50 p-2 text-xs">{rt.log.join('\n')}</pre> : null}
          {rt && (rt.job.running || rt.job.log?.length) ? (
            <pre className="max-h-40 overflow-y-auto rounded-lg bg-muted/50 p-2 text-xs">{(rt.job.log ?? []).join('\n')}{rt.job.running ? '\n…' : ''}</pre>
          ) : null}
        </div>
      </Section>

      <Section title="经隧道公开的名字" desc={mine ? `隧道 ${mine.name} · Cloudflare 那边：${{ healthy: '正常', degraded: '部分连接', down: '断开', inactive: '还没连上过' }[mine.status] ?? mine.status}` : '第一次添加时会在你的 Cloudflare 账户里建一条隧道'}
        action={data.conf.id && !data.conf.routes.length ? <Button size="sm" variant="ghost" className="text-destructive" onClick={removeTunnel}><Trash2 /> 删除隧道</Button> : undefined}>
        <div className="divide-y">
          {data.conf.routes.map((r) => (
            <div key={r.hostname} className="flex flex-wrap items-center gap-3 px-4 py-3 text-sm">
              <Globe className="size-4 text-primary" />
              <a href={`https://${r.hostname}`} target="_blank" rel="noreferrer" className="font-mono hover:underline">{r.hostname}</a>
              <span className="text-muted-foreground">→</span>
              {r.kind === 'panel' ? <Pill tone="blue">这个面板</Pill> : <span className="font-mono text-xs">{r.service}</span>}
              <span className="flex-1" />
              <Button size="icon-sm" variant="ghost" title="撤下" onClick={() => remove(r)}><Trash2 /></Button>
            </div>
          ))}
          {!data.conf.routes.length && <Empty>还没有。下面添加一个，比如 wharf.你的域名 → 这个面板。</Empty>}
        </div>
        {data.tunnels_denied ? (
          <p className="border-t px-4 py-3 text-sm text-muted-foreground">令牌缺少「账户 · Cloudflare Tunnel · 编辑」权限，补上后才能添加。</p>
        ) : (
          <div className="grid gap-3 border-t p-4">
            <div className="grid gap-3 sm:grid-cols-[1fr_1fr]">
              <Field label="名字">
                <div className="flex items-center gap-1">
                  <Input className="font-mono" value={form.sub} placeholder="wharf" onChange={(e) => setForm({ ...form, sub: e.target.value.trim().toLowerCase() })} />
                  <span className="text-muted-foreground">.</span>
                  <select className="h-9 rounded-md border bg-background px-2 text-sm" value={form.zone} onChange={(e) => setForm({ ...form, zone: e.target.value })}>
                    {zones.map((z) => <option key={z.id} value={z.name}>{z.name}</option>)}
                  </select>
                </div>
              </Field>
              <Field label="公开什么">
                <div className="flex gap-1">
                  {([['panel', '这个面板'], ['lan', '家里的其他服务']] as const).map(([k, l]) => (
                    <button key={k} type="button" onClick={() => setForm({ ...form, kind: k })} className={cn('h-9 flex-1 rounded-md border px-3 text-sm', form.kind === k ? 'border-primary bg-accent' : 'text-muted-foreground')}>{l}</button>
                  ))}
                </div>
              </Field>
            </div>
            {form.kind === 'lan' && (
              <div className="grid gap-2">
                <Field label="服务地址" hint="家里设备上的网页服务，例如 NAS 的 http://192.168.1.10:5000"><Input className="font-mono" value={form.service} placeholder="http://192.168.1.10:8080" onChange={(e) => setForm({ ...form, service: e.target.value.trim() })} /></Field>
                {form.service.startsWith('https://') && (
                  <label className="flex items-center gap-2 text-xs text-muted-foreground"><Switch size="sm" checked={form.no_verify} onCheckedChange={(c) => setForm({ ...form, no_verify: !!c })} />它用的是自签证书（不校验证书）</label>
                )}
                <p className="text-xs text-amber-700 dark:text-warning">公开出去的服务谁都能访问，最好它自己有登录，或者在「Access 登录保护」里给它加一道验证。</p>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Button disabled={busy || !form.zone || !rt?.installed || (form.kind === 'lan' && !form.service)} onClick={() => add()}>{busy ? <Loader2 className="animate-spin" /> : <Plus />} 接到隧道上</Button>
              <span className="text-xs text-muted-foreground">会在 Cloudflare 建一条指向隧道的 {host} 记录（开着橙色云）。{!rt?.installed && '先装 cloudflared。'}</span>
            </div>
            {form.kind === 'panel' && <p className="text-xs text-muted-foreground">经隧道打开时，Passkey、面板访问控制、访问记录都照常，按访客的真实 IP 判断。</p>}
          </div>
        )}
      </Section>

      {others.length > 0 && (
        <Section title="账户里的其他隧道" desc="不是这个 Wharf 建的，只显示，不会改动">
          <div className="divide-y">
            {others.map((t) => (
              <div key={t.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5 text-sm">
                <Dot tone={t.status === 'healthy' ? 'ok' : t.status === 'down' ? 'bad' : 'off'} />
                <span className="font-medium">{t.name}</span>
                {t.name.startsWith('berth') && <Pill tone="blue">Berth</Pill>}
                {t.name.startsWith('wharf') && <Pill>另一台 Wharf</Pill>}
                <span className="text-xs text-muted-foreground">{t.connections?.length ? `${t.connections.length} 条连接 · ${[...new Set(t.connections.map((c) => c.colo_name))].join('、')}` : '没有连接'}</span>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  )
}

// ---- zones ----

interface Zone { id: string; name: string; status: string; plan: string; paused: boolean; security_level?: string; used_by: string[]; berth?: string[] }
interface Day { date: string; requests: number; bytes: number; cached: number; threats: number; uniques: number }

const LEVEL: Record<string, string> = { essentially_off: '基本关闭', low: '低', medium: '中', high: '高', under_attack: '受攻击模式' }

function Zones() {
  const { data, error, reload } = useApi<Zone[]>('/cloudflare/zones')
  const [open, setOpen] = useState<string | null>(null)
  const [busy, setBusy] = useState('')
  const { confirm, dialog } = useConfirm()
  const attack = async (z: Zone, on: boolean) => {
    const berthNote = z.berth?.length ? `\n\n这个域名下还有 Berth 的网站（${z.berth.join('、')}），它们也会一起受影响。` : ''
    if (on && !(await confirm(`对 ${z.name} 开启受攻击模式？`, `所有访客先过 Cloudflare 的浏览器检查（约 5 秒），API、DDNS 不受影响，但程序和手机 App 访问这个域名下的网站可能会失败。攻击过去后记得关掉。${berthNote}`, { ok: '开启' }))) return
    setBusy(z.id)
    try { await post(`/cloudflare/zones/${z.id}/attack`, { on }); toast.success(on ? '已开启受攻击模式' : '已恢复'); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy('') }
  }
  const purge = async (z: Zone) => {
    if (!(await confirm(`清除 ${z.name} 的全部缓存？`, '之后一段时间访客都要回源取内容，会慢一些。', { ok: '清除' }))) return
    setBusy(z.id)
    try { await post(`/cloudflare/zones/${z.id}/purge`, {}); toast.success('缓存已清除') } catch (e) { toast.error((e as Error).message) } finally { setBusy('') }
  }
  if (error) return <Section title="域名"><p className="p-4 text-sm text-destructive">{error}</p></Section>
  if (!data) return <div className="text-sm text-muted-foreground">加载中…</div>
  return (
    <Section title="域名" desc="受攻击模式和缓存是整个域名的设置，Cloudflare 后台和 Berth 里看到的是同一份">
      {dialog}
      <div className="divide-y">
        {data.map((z) => (
          <div key={z.id} className="grid gap-2 px-4 py-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Dot tone={z.status === 'active' && !z.paused ? 'ok' : 'warn'} />
              <span className="font-medium">{z.name}</span>
              <Pill>{z.plan}</Pill>
              {z.status !== 'active' && <Pill tone="amber">{z.status === 'pending' ? '等待改 NS' : z.status}</Pill>}
              {z.security_level && <Pill tone={z.security_level === 'under_attack' ? 'red' : 'muted'}>安全级别：{LEVEL[z.security_level] ?? z.security_level}</Pill>}
              <span className="flex-1" />
              {z.security_level !== undefined && (
                <label className="flex items-center gap-2 text-xs text-muted-foreground">受攻击模式<Switch size="sm" disabled={busy === z.id} checked={z.security_level === 'under_attack'} onCheckedChange={(c) => attack(z, !!c)} /></label>
              )}
              <Button size="sm" variant="ghost" disabled={busy === z.id} onClick={() => purge(z)}>清缓存</Button>
              <Button size="sm" variant="ghost" onClick={() => setOpen(open === z.id ? null : z.id)}><BarChart3 /> 统计</Button>
            </div>
            {(z.used_by.length > 0 || (z.berth?.length ?? 0) > 0) && (
              <div className="flex flex-wrap gap-1.5 text-xs">
                {z.used_by.map((u) => <Pill key={u} tone="blue">{u}</Pill>)}
                {z.berth?.map((n) => <Pill key={n}>Berth · {n}</Pill>)}
              </div>
            )}
            {open === z.id && <ZoneStats id={z.id} />}
          </div>
        ))}
        {!data.length && <Empty>令牌看不到任何域名</Empty>}
      </div>
    </Section>
  )
}

function ZoneStats({ id }: { id: string }) {
  const { data, error } = useApi<Day[]>(`/cloudflare/zones/${id}/stats`)
  if (error) return <p className="text-xs text-destructive">{error}</p>
  if (!data) return <p className="text-xs text-muted-foreground">正在读取…</p>
  if (!data.length) return <p className="text-xs text-muted-foreground">最近 7 天没有数据</p>
  const sum = (k: keyof Day) => data.reduce((n, d) => n + (d[k] as number), 0)
  const req = sum('requests')
  return (
    <div className="grid gap-3 rounded-xl border p-3">
      <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-5">
        <div><div className="text-xs text-muted-foreground">请求</div><div className="font-semibold tabular-nums">{req.toLocaleString()}</div></div>
        <div><div className="text-xs text-muted-foreground">流量</div><div className="font-semibold tabular-nums">{bytes(sum('bytes'))}</div></div>
        <div><div className="text-xs text-muted-foreground">缓存命中</div><div className="font-semibold tabular-nums">{req ? Math.round((sum('cached') / req) * 100) : 0}%</div></div>
        <div><div className="text-xs text-muted-foreground">拦下的威胁</div><div className="font-semibold tabular-nums">{sum('threats').toLocaleString()}</div></div>
        <div><div className="text-xs text-muted-foreground">独立访客（日均）</div><div className="font-semibold tabular-nums">{Math.round(sum('uniques') / data.length).toLocaleString()}</div></div>
      </div>
      <AreaChart height={120} times={data.map((d) => Date.parse(d.date) / 1000)} format={(v) => v.toLocaleString()} timeLabel={(t) => new Date(t * 1000).toLocaleDateString()}
        series={[{ label: '请求', color: 'var(--chart-1)', values: data.map((d) => d.requests) }, { label: '威胁', color: 'var(--chart-5, var(--destructive))', values: data.map((d) => d.threats) }]} />
    </div>
  )
}

// ---- Access ----

interface AccessApp { id: string; name: string; domain: string; session_duration: string; emails?: string[] | null; mine: boolean }
interface AccessResp { apps: AccessApp[]; names?: string[] | null; error?: string; denied?: boolean; account?: { name: string } }

function Access() {
  const { data, reload } = useApi<AccessResp>('/cloudflare/access')
  const [form, setForm] = useState({ hostname: '', emails: '', hours: 24 })
  const [busy, setBusy] = useState(false)
  const { confirm, dialog } = useConfirm()
  const berth = useBerth()
  if (!data) return <div className="text-sm text-muted-foreground">加载中…</div>
  const save = async () => {
    const msg = `之后从外面打开 ${form.hostname}，要先在 Cloudflare 的页面输入邮箱、收验证码，通过后才看得到面板登录页。${berth.paired ? '\n\n如果 Berth 是通过这个名字访问 Wharf 的，配对调用会被挡住：请让 Berth 用局域网地址连 Wharf。' : ''}`
    if (!(await confirm(`保护 ${form.hostname}？`, msg, { ok: '保存' }))) return
    setBusy(true)
    try {
      await post('/cloudflare/access', { hostname: form.hostname, emails: form.emails.split(/[\s,，]+/).filter(Boolean), hours: form.hours })
      toast.success('已保存，一两分钟后生效'); setForm({ hostname: '', emails: '', hours: 24 }); reload()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const remove = async (a: AccessApp) => {
    if (!(await confirm(`取消 ${a.domain} 的登录保护？`, '之后打开它就直接到面板登录页。', { danger: true, ok: '取消保护' }))) return
    try { await del(`/cloudflare/access?id=${a.id}`); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const edit = (a: AccessApp) => setForm({ hostname: a.domain, emails: (a.emails ?? []).join('\n'), hours: parseInt(a.session_duration) || 24 })
  const names = (data.names ?? []).filter((n) => !data.apps.some((a) => a.domain === n && !a.mine))
  return (
    <div className="grid gap-4">
      {dialog}
      <Section title="Access 登录保护" desc="经 Cloudflare 打开面板（橙色云或隧道）时，先过一道邮箱验证码：只有你指定的邮箱能收到，陌生人连登录页都看不到。">
        <div className="grid gap-3 p-4 text-sm">
          {data.error && <p className={data.denied ? 'text-muted-foreground' : 'text-destructive'}>{data.error}</p>}
          <div className="divide-y rounded-lg border">
            {data.apps.map((a) => (
              <div key={a.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
                <Lock className="size-4 text-primary" />
                <span className="font-mono">{a.domain}</span>
                {!a.mine && <Pill>{/berth/i.test(a.name) ? 'Berth 建的' : '别处建的'} · 只读</Pill>}
                {a.mine && <span className="text-xs text-muted-foreground">{(a.emails ?? []).join('、')} · 每 {a.session_duration} 验证一次</span>}
                <span className="flex-1" />
                {a.mine && <Button size="sm" variant="ghost" onClick={() => edit(a)}>修改</Button>}
                {a.mine && <Button size="icon-sm" variant="ghost" title="取消保护" onClick={() => remove(a)}><Trash2 /></Button>}
              </div>
            ))}
            {!data.apps.length && <Empty>还没有受保护的名字</Empty>}
          </div>
        </div>
      </Section>
      {!data.error && (
        <Section title={form.hostname && data.apps.some((a) => a.mine && a.domain === form.hostname) ? `修改 ${form.hostname}` : '保护一个名字'}>
          <div className="grid gap-3 p-4">
            <Field label="名字" hint={names.length ? '面板的公网域名和隧道名字都在这里' : '先在「隧道」或「系统设置 → 面板域名」给面板一个公网名字'}>
              <div className="flex flex-wrap gap-1.5">
                {names.map((n) => (
                  <button key={n} type="button" onClick={() => setForm({ ...form, hostname: n })} className={cn('rounded-full border px-3 py-1 font-mono text-xs', form.hostname === n ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted')}>{n}</button>
                ))}
                <Input className="h-8 w-56 font-mono text-xs" placeholder="或者输入其他名字" value={names.includes(form.hostname) ? '' : form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value.trim().toLowerCase() })} />
              </div>
            </Field>
            <Field label="允许谁" hint="每行一个邮箱；写 @example.com 表示这个域名下的所有邮箱">
              <textarea className="min-h-20 rounded-md border bg-background px-3 py-2 font-mono text-sm" value={form.emails} onChange={(e) => setForm({ ...form, emails: e.target.value })} placeholder={'me@example.com\n@family.example'} />
            </Field>
            <Field label="多久验证一次">
              <div className="flex gap-1">
                {[[24, '每天'], [168, '每周'], [720, '每月']].map(([h, l]) => (
                  <button key={h} type="button" onClick={() => setForm({ ...form, hours: h as number })} className={cn('h-8 rounded-md border px-3 text-xs', form.hours === h ? 'border-primary bg-accent' : 'text-muted-foreground')}>{l}</button>
                ))}
              </div>
            </Field>
            <div><Button disabled={busy || !form.hostname || !form.emails.trim()} onClick={save}>{busy && <Loader2 className="animate-spin" />}保存</Button></div>
            <p className="text-xs text-muted-foreground">只对经 Cloudflare 的访问生效；在家里用 wharf.lan 或 IP 打开不受影响。手机上装成 App 的面板，过期后会先跳到 Cloudflare 验证页。</p>
          </div>
        </Section>
      )}
    </div>
  )
}


