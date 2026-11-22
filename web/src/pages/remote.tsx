import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Check, Cloud, Earth, Home, Lock, ShieldHalf, Waypoints, Zap } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Pill, Section } from '@/components/common'
import { PanelNames } from '@/components/panel-names'
import { regionLabel } from '@/components/pickers'

const zhRegion = typeof Intl !== 'undefined' && 'DisplayNames' in Intl ? new Intl.DisplayNames(['zh-CN'], { type: 'region' }) : null
const placeName = (k: string) => {
  const [cc, sub] = k.split('-')
  const name = /^[A-Z]{2}$/.test(cc) ? zhRegion?.of(cc) ?? cc : regionLabel(k)
  return sub ? `${name} ${sub}` : name
}
import { Button } from '@/components/ui/button'

// Opening the panel from outside, in one place: how it is reachable now, the three
// ways (tunnel / orange cloud / direct) with the one that suits this line, the names,
// and who may come in. The pieces live where they always did (Cloudflare page, panel
// names, access control); this page ties them together.

interface Names { local: string; port: string; names: { name: string }[]; via_443: boolean; via_port: boolean; proxied: string[] | null }
interface TunnelResp { conf: { routes: { hostname: string; kind: string }[] }; router?: { installed: boolean; running: boolean; ready: number } }
interface Pub { verdict: string; external: string }
interface CFState { connected: boolean }
interface AccessResp { apps: { domain: string; mine: boolean }[] }

export default function RemotePage() {
  const { data: names } = useApi<Names>('/panel/names')
  const { data: cf } = useApi<CFState>('/cloudflare')
  const { data: tun } = useApi<TunnelResp>(cf?.connected ? '/cloudflare/tunnel' : null)
  const { data: acc } = useApi<AccessResp>(cf?.connected ? '/cloudflare/access' : null)
  const { data: pub } = useApi<Pub>('/net/public?iface=wan')
  const { data: s } = useApi<Record<string, string>>('/settings')

  const proxied = new Set(names?.proxied ?? [])
  const tunnelNames = (tun?.conf.routes ?? []).filter((r) => r.kind === 'panel').map((r) => r.hostname)
  const direct = (names?.names ?? []).map((n) => n.name).filter((n) => !proxied.has(n))
  const orange = (names?.names ?? []).map((n) => n.name).filter((n) => proxied.has(n))
  const outside = [...tunnelNames.map((n) => [n, '隧道']), ...orange.map((n) => [n, '橙色云']), ...(names?.via_443 || names?.via_port ? direct.map((n) => [n, '直连']) : [])]
  const protectedNames = new Set((acc?.apps ?? []).map((a) => a.domain))

  const wanMode = s?.['access.wan.mode']
  let regions: string[] = []
  try { regions = JSON.parse(s?.['access.wan.regions'] || '[]') } catch { /* empty */ }
  const who = wanMode === 'all' ? '所有地区都能打开登录页' : regions.length ? `只允许 ${regions.map(placeName).join('、')}` : '公网访问已关闭'

  const publicIP = pub?.verdict === 'public' || pub?.verdict === 'public_unverified'
  const rec: 'tunnel' | 'direct' | null = !pub ? null : publicIP ? 'direct' : 'tunnel'

  return (
    <div className="grid gap-4">
      <PageHeader title="外网访问" desc="从家外面打开这个面板：现在的情况、三种方式、用哪个名字、谁能进来。" />

      {/* now */}
      <section className="flex flex-wrap items-start gap-3 rounded-2xl border bg-card p-4">
        <span className={cn('grid size-10 shrink-0 place-items-center rounded-xl', outside.length ? 'bg-success/12 text-success' : 'bg-muted text-muted-foreground')}>
          {outside.length ? <Earth className="size-5" /> : <Home className="size-5" />}
        </span>
        <div className="grid min-w-0 flex-1 gap-1">
          <div className="font-semibold">{outside.length ? '外面可以打开面板' : '现在只能在家里打开'}</div>
          <div className="text-sm text-muted-foreground">
            {outside.length
              ? <>通过 {outside.map(([n, how], i) => <span key={n}>{i > 0 && '、'}<span className="font-mono text-foreground">{n}</span>（{how}{protectedNames.has(n) ? ' · 有 Access 保护' : ''}）</span>)}。{who}。</>
              : <>在家里用 <span className="font-mono text-foreground">{names ? `https://${names.local}${names.port && names.port !== '443' ? ':' + names.port : ''}` : 'wharf.lan'}</span> 或路由器 IP 打开。想在外面也能打开，按下面选一种方式。</>}
          </div>
        </div>
      </section>

      {/* ways */}
      <Section title="选一种方式" desc={pub ? `公网检测：${publicIP ? `家里是公网 IP（${pub.external}）` : '家里不是公网 IP，或在光猫后面'}，所以推荐「${rec === 'tunnel' ? '隧道' : '直连或橙色云'}」` : '正在检测家里是不是公网 IP…'}>
        <div className="grid gap-3 p-4 md:grid-cols-3">
          <Way icon={<Waypoints className="size-5" />} title="Cloudflare 隧道" best={rec === 'tunnel'} on={tunnelNames.length > 0}
            desc="不开端口、不暴露家里 IP，没有公网 IP 也行。需要域名托管在 Cloudflare。"
            state={!cf?.connected ? '还没连接 Cloudflare' : tunnelNames.length ? `在用：${tunnelNames.join('、')}` : tun?.router?.installed ? '已装好 cloudflared，还没添加名字' : '还没设置'}
            action={<Button size="sm" variant={rec === 'tunnel' ? 'default' : 'outline'} render={<Link to={cf?.connected ? '/cloudflare?tab=tunnel' : '/cloudflare'} />}>{cf?.connected ? '去设置隧道' : '先连接 Cloudflare'} <ArrowRight /></Button>} />
          <Way icon={<Cloud className="size-5" />} title="橙色云" on={orange.length > 0}
            desc="有公网 IP，想藏起家里 IP、要 Cloudflare 的防护。访客经 Cloudflare 回源到家里。"
            state={orange.length ? `在用：${orange.join('、')}` : '下面的「面板域名」里给名字打开橙色云'}
            action={<Button size="sm" variant="outline" render={<a href="#panel-names" />}>去设置 <ArrowRight /></Button>} />
          <Way icon={<Zap className="size-5" />} title="直连" best={rec === 'direct'} on={direct.length > 0 && !!(names?.via_443 || names?.via_port)}
            desc="有公网 IP，最快最简单。配合 DDNS，家里 IP 变了域名自动跟上；国内家宽一般封了 443，可以用面板端口。"
            state={direct.length && (names?.via_443 || names?.via_port) ? `在用：${direct.join('、')}` : '下面的「面板域名」里添加名字'}
            action={<Button size="sm" variant={rec === 'direct' ? 'default' : 'outline'} render={<a href="#panel-names" />}>去设置 <ArrowRight /></Button>} />
        </div>
      </Section>

      {/* names (direct / orange) */}
      <div id="panel-names" className="grid scroll-mt-28">
        <PanelNames />
      </div>

      {/* who */}
      <Section title="谁能进来" desc="不管哪种方式，从外面来的访问都要先过这两道">
        <div className="grid gap-3 p-4 md:grid-cols-2">
          <div className="grid content-start gap-2 rounded-xl border p-3">
            <div className="flex items-center gap-2 text-sm font-medium"><ShieldHalf className="size-4 text-primary" />面板访问控制</div>
            <p className="text-sm text-muted-foreground">{who}。也可以按 IP 放行或拉黑、检查浏览器时区。</p>
            <Button size="sm" variant="outline" className="justify-self-start" render={<Link to="/access" />}>修改 <ArrowRight /></Button>
          </div>
          <div className="grid content-start gap-2 rounded-xl border p-3">
            <div className="flex items-center gap-2 text-sm font-medium"><Lock className="size-4 text-primary" />Cloudflare Access（可选）</div>
            <p className="text-sm text-muted-foreground">
              {!cf?.connected ? '经 Cloudflare 打开时（隧道或橙色云），可以再加一道邮箱验证码。需要先连接 Cloudflare。'
                : protectedNames.size ? <>已保护：{[...protectedNames].map((n) => <Pill key={n}>{n}</Pill>)}</> : '经 Cloudflare 打开时，先过一道邮箱验证码，陌生人连登录页都看不到。'}
            </p>
            <Button size="sm" variant="outline" className="justify-self-start" render={<Link to={cf?.connected ? '/cloudflare?tab=access' : '/cloudflare'} />}>{cf?.connected ? '设置' : '连接 Cloudflare'} <ArrowRight /></Button>
          </div>
        </div>
      </Section>
    </div>
  )
}

function Way({ icon, title, desc, state, action, best, on }: { icon: ReactNode; title: string; desc: string; state: string; action: ReactNode; best?: boolean; on?: boolean }) {
  return (
    <div className={cn('grid content-start gap-2 rounded-xl border p-3', best && 'border-primary/50 bg-accent/30')}>
      <div className="flex items-center gap-2">
        <span className="text-primary">{icon}</span>
        <span className="font-medium">{title}</span>
        {best && <Pill tone="blue">推荐</Pill>}
        {on && <Pill tone="green"><Check className="mr-0.5 inline size-3" />在用</Pill>}
      </div>
      <p className="text-xs text-muted-foreground">{desc}</p>
      <p className="text-xs">{state}</p>
      <div>{action}</div>
    </div>
  )
}
