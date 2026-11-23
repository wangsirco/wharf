import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { ArrowRight, CheckCircle2, ChevronDown, Download, Globe, Home, Loader2, Pencil, ShieldAlert, X, XCircle } from 'lucide-react'
import { get, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { Pill, Section } from '@/components/common'
import { CopyText } from '@/pages/diag'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

// One name at home, one outside, no ports (Wharf ⇄ Berth v3 §1–2). Passkeys only work on
// the name they were added on, so everyone should open the panel by the same name.

export interface AccessInfo {
  lan: string; lan_name: string; lan_host: string; domain: string; lan443: boolean
  public: string; public_names: string[] | null; fallback: string; port: string
  splitter: { enabled: boolean; listening: boolean; redirect: boolean; other: boolean; error?: string }
  splitter_error?: string
}

/** Can this browser open url (name resolves, certificate trusted, panel answers)? */
export async function probe(url: string, ms = 2500): Promise<boolean> {
  const c = new AbortController()
  const t = setTimeout(() => c.abort(), ms)
  try {
    await fetch(url.replace(/\/$/, '') + '/api/panel/primary', { mode: 'no-cors', cache: 'no-store', signal: c.signal })
    return true
  } catch { return false } finally { clearTimeout(t) }
}

const here = () => location.origin

function useProbe(url?: string) {
  const [s, setS] = useState<'checking' | 'ok' | 'fail' | ''>('')
  const run = () => { if (!url) return; setS('checking'); probe(url).then((ok) => setS(ok ? 'ok' : 'fail')) }
  useEffect(run, [url]) // eslint-disable-line react-hooks/exhaustive-deps
  return [s, run] as const
}

const OS = [
  ['mac', 'Mac', ['点上面的「下载证书」，双击下载的 ca.crt，选「系统」钥匙串加入。', '在「钥匙串访问」里双击「Wharf 本地证书 …」，展开「信任」，「使用此证书时」选「始终信任」，关掉窗口并输入开机密码。']],
  ['ios', 'iPhone / iPad', ['用 Safari 点「下载证书」，选「允许」。', '打开「设置」，最上面点「已下载描述文件」→「安装」。', '再到「设置 → 通用 → 关于本机 → 证书信任设置」，打开「Wharf 本地证书」的开关。']],
  ['win', 'Windows', ['点「下载证书」，双击 ca.crt →「安装证书」。', '选「本地计算机」→「将所有的证书都放入下列存储」→「受信任的根证书颁发机构」→ 完成。', '重新打开浏览器。']],
  ['android', '安卓', ['点「下载证书」。', '「设置 → 安全 → 更多安全设置 → 加密与凭据 → 安装证书 → CA 证书」，选下载的 ca.crt（不同品牌菜单名字略有差别，可以在设置里搜「证书」）。']],
  ['linux', 'Linux', ['下载证书后运行：sudo cp ca.crt /usr/local/share/ca-certificates/wharf.crt && sudo update-ca-certificates', 'Firefox 用自己的证书库：设置 → 隐私与安全 → 证书 → 查看证书 → 导入。']],
] as const

function guessOS() {
  const ua = navigator.userAgent
  if (/iPhone|iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'ios'
  if (/Android/.test(ua)) return 'android'
  if (/Windows/.test(ua)) return 'win'
  if (/Mac OS X/.test(ua)) return 'mac'
  return 'linux'
}

/** How to trust the panel's certificate on this device, the device's own system first. */
export function CertSteps() {
  const [os, setOS] = useState<string>(guessOS())
  const cur = OS.find(([k]) => k === os) ?? OS[0]
  return (
    <div className="grid gap-2 rounded-lg border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">让这台设备信任面板的证书</span>
        <Button size="xs" variant="outline" render={<a href="/ca.crt" download="wharf-ca.crt" />}><Download /> 下载证书</Button>
      </div>
      <div className="flex flex-wrap gap-1">
        {OS.map(([k, l]) => (
          <button key={k} type="button" onClick={() => setOS(k)} className={cn('rounded-full border px-2.5 py-0.5 text-xs', os === k ? 'border-primary bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground')}>{l}</button>
        ))}
      </div>
      <ol className="ml-4 list-decimal space-y-1 text-xs text-muted-foreground">{cur[2].map((s) => <li key={s}>{s}</li>)}</ol>
      <p className="text-xs text-muted-foreground">每台设备做一次。证书只用于家里的面板名字，有效期很长，续期也不用重装。</p>
    </div>
  )
}

function Status({ s, okText, failText }: { s: string; okText: string; failText: string }) {
  if (s === 'checking') return <span className="flex items-center gap-1 text-xs text-muted-foreground"><Loader2 className="size-3.5 animate-spin" />正在检查…</span>
  if (s === 'ok') return <span className="flex items-center gap-1 text-xs text-success"><CheckCircle2 className="size-3.5" />{okText}</span>
  if (s === 'fail') return <span className="flex items-center gap-1 text-xs text-destructive"><XCircle className="size-3.5" />{failText}</span>
  return null
}

/** Settings → 外网与联动 → 访问地址. */
export function AccessAddressCard() {
  const { data, reload, setData } = useApi<AccessInfo>('/panel/access')
  const [s, recheck] = useProbe(data?.lan)
  const [editing, setEditing] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [fallbackOpen, setFallbackOpen] = useState(false)
  if (!data) return <Section title="访问地址"><p className="p-4 text-sm text-muted-foreground">加载中…</p></Section>
  const save = async (body: Record<string, unknown>, ok: string) => {
    setBusy(true)
    try { setData(await put<AccessInfo>('/panel/access', body)); toast.success(ok); setEditing(null); setTimeout(recheck, 1500) } catch (e) { toast.error((e as Error).message); reload() } finally { setBusy(false) }
  }
  const onLan = here() === data.lan
  return (
    <Section title="访问地址" desc="在家用一个名字、在外用一个名字，都不带端口。Passkey 只认名字，在哪个名字上添加就只能在哪个名字上用。" className="xl:col-span-2">
      <div className="grid gap-4 p-4">
        <div className="grid gap-2 rounded-xl border p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Home className="size-4 text-primary" /><span className="text-sm font-medium">内网地址</span>
            {onLan && <Pill tone="green">你现在就在用</Pill>}
            <Status s={s} okText="这台设备能打开，证书已信任" failText="这台设备打不开：多半是证书还没信任，或这台设备没用路由器做 DNS" />
          </div>
          {editing === null ? (
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-base">{data.lan}</span>
              <Button size="xs" variant="ghost" onClick={() => setEditing(data.lan_host)}><Pencil /> 改名</Button>
              {!onLan && s === 'ok' && <Button size="xs" render={<a href={data.lan + location.pathname + location.search} />}>转到这个地址 <ArrowRight /></Button>}
            </div>
          ) : (
            <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); save({ lan_host: editing }, '已改名') }}>
              <span className="font-mono text-sm">https://</span>
              <Input className="h-8 w-40 font-mono" autoFocus value={editing} onChange={(e) => setEditing(e.target.value.toLowerCase())} />
              <span className="font-mono text-sm">.{data.domain}</span>
              <Button size="sm" type="submit" disabled={busy || !editing}>保存</Button>
              <Button size="sm" variant="ghost" type="button" onClick={() => setEditing(null)}><X /></Button>
              <p className="w-full text-xs text-amber-600 dark:text-amber-400">改名后，旧名字上添加的 Passkey 不能再用，需要在新名字上重新添加；每台设备也要换成新地址打开。</p>
            </form>
          )}
          <label className="flex items-start justify-between gap-4 rounded-lg bg-muted/30 px-3 py-2">
            <span>
              <span className="block text-sm">不带端口（推荐）</span>
              <span className="block text-xs text-muted-foreground">
                用 https://{data.lan_name} 打开，不用记 :{data.port}。路由器自己的 LuCI 页面不受影响：用 IP 打开的照样是 LuCI。
                {data.splitter_error && <span className="block text-destructive">{data.splitter_error}</span>}
                {data.lan443 && !data.splitter.redirect && !data.splitter_error && <span className="block text-destructive">路由器上的转发规则不在了，关掉再打开一次</span>}
                {data.lan443 && !data.splitter.other && <span className="block text-amber-600">路由器 443 端口上没有 LuCI；其他名字会打不开，不影响面板</span>}
              </span>
            </span>
            <Switch checked={data.lan443} disabled={busy || !!data.splitter_error} onCheckedChange={(c) => save({ lan443: !!c }, c ? '已开启：现在可以不带端口打开' : '已关闭')} />
          </label>
          {s === 'fail' && <CertSteps />}
        </div>

        <div className="grid gap-2 rounded-xl border p-3">
          <div className="flex items-center gap-2"><Globe className="size-4 text-primary" /><span className="text-sm font-medium">公网地址</span></div>
          {data.public
            ? <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-base">{data.public}</span><Button size="xs" variant="ghost" render={<Link to="/remote" />}>设置 <ArrowRight /></Button></div>
            : <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">还没有。在外面也想打开，去「外网访问」选一种方式。<Button size="xs" variant="outline" render={<Link to="/remote" />}>去设置 <ArrowRight /></Button></div>}
        </div>

        {data.fallback && (
          <div className="rounded-xl border px-3 py-2">
            <button type="button" className="flex w-full items-center gap-2 text-left text-sm text-muted-foreground" onClick={() => setFallbackOpen(!fallbackOpen)}>
              <ChevronDown className={cn('size-4 transition-transform', fallbackOpen && 'rotate-180')} />后备地址（名字打不开时用）
            </button>
            {fallbackOpen && <div className="mt-2 grid gap-1"><CopyText text={data.fallback} /><p className="text-xs text-muted-foreground">用 IP 打开时证书会报不安全，Passkey 也用不了，只在名字出问题时应急。</p></div>}
          </div>
        )}
      </div>
    </Section>
  )
}

/** The wizard step: the LAN name, on by default. */
export function LanNameStep({ on, setOn }: { on: boolean; setOn: (v: boolean) => void }) {
  const { data } = useApi<AccessInfo>('/panel/access')
  const [s, recheck] = useProbe(data?.lan443 ? data.lan : undefined)
  if (!data) return <Loader2 className="mx-auto animate-spin" />
  const name = `https://${data.lan_name}`
  return (
    <div className="grid gap-3">
      <label className={cn('flex items-start gap-3 rounded-xl border p-3', on && 'border-primary bg-accent/40')}>
        <Switch checked={on} onCheckedChange={(c) => setOn(!!c)} className="mt-0.5" />
        <span>
          <span className="flex items-center gap-2 text-sm font-medium">用 {name} 打开面板 <Pill tone="blue">推荐</Pill></span>
          <span className="block text-xs text-muted-foreground">以后不用记 IP 和端口；想用指纹 / 面容（Passkey）登录也必须用名字。路由器自己的 LuCI 页面不受影响。</span>
        </span>
      </label>
      {on && (data.lan443 ? (
        <>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Status s={s} okText="这台设备已经能打开" failText="这台设备还打不开，先让它信任证书" />
            {s === 'fail' && <Button size="xs" variant="outline" onClick={recheck}>再检查一次</Button>}
            {s === 'ok' && here() !== data.lan && <Button size="xs" render={<a href={data.lan + '/'} />}>现在转到 {name} <ArrowRight /></Button>}
          </div>
          {s !== 'ok' && <CertSteps />}
        </>
      ) : <p className="text-xs text-muted-foreground">点「下一步」开启。{data.splitter_error && <span className="text-destructive">（{data.splitter_error}）</span>}</p>)}
      {!on && <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><ShieldAlert className="size-3.5" />跳过也行，概览页会留一条提醒，「系统设置 → 外网与联动 → 访问地址」随时可以开。</p>}
    </div>
  )
}

/** Opened by IP or an old name: move to the LAN name when this device can open it,
 *  otherwise say how to fix it. Mounted once at the top of the app. */
export function PrimaryHostGuard() {
  const [hint, setHint] = useState<string | null>(null)
  useEffect(() => {
    if (/^(localhost|127\.|\[::1\])/.test(location.hostname) || location.pathname.startsWith('/sso/')) return
    if (sessionStorage.getItem('owp-primary-dismiss')) return
    let alive = true
    get<{ lan: string; known: boolean }>('/panel/primary').then(async (p) => {
      if (!alive || p.known || !p.lan || p.lan === location.origin) return
      if (await probe(p.lan)) location.replace(p.lan + location.pathname + location.search + location.hash)
      else if (alive) setHint(p.lan)
    }).catch(() => {})
    return () => { alive = false }
  }, [])
  if (!hint) return null
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-warning/40 bg-warning/10 px-4 py-2 text-sm">
      <ShieldAlert className="size-4 shrink-0 text-warning" />
      <span className="min-w-0 flex-1">建议用 <b className="font-mono">{hint}</b> 打开：Passkey 只认名字。这台设备现在还打不开它，通常是证书还没信任，或这台设备没用路由器做 DNS。</span>
      <Button size="xs" variant="outline" render={<a href="/ca.crt" download="wharf-ca.crt" />}><Download /> 下载证书</Button>
      <Button size="xs" variant="ghost" onClick={() => { sessionStorage.setItem('owp-primary-dismiss', '1'); setHint(null) }}><X /></Button>
    </div>
  )
}
