import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, Globe2, Loader2, RefreshCw, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Pill } from '@/components/common'
import { Button } from '@/components/ui/button'

export interface PublicCheck {
  iface: string; proto: string; dynamic: boolean; wan_ip: string; external: string
  seen: { source: string; ip?: string; error?: string }[]
  verdict: 'public' | 'public_unverified' | 'mismatch' | 'cgnat' | 'modem' | 'none'
  next_hop?: string; next_hop_kind?: 'public' | 'cgnat' | 'private' | 'unknown'; hops?: string[]
  ipv6?: string; ipv6_external?: string
  ddns: { id: number; domain: string; rtype: string; enabled: boolean; last_ip: string; last_err?: string; points_here: boolean }[] | null
  ddns_visible: boolean; checked: number
}

const SRC: Record<string, string> = { ddnspod: 'DNSPod', ipsb: 'IP.SB', ipify: 'ipify', icanhazip: 'icanhazip', cloudflare: 'Cloudflare' }

type Tone = 'green' | 'amber' | 'red' | 'muted'

function verdictText(c: PublicCheck): { tone: Tone; title: string; body: string } {
  switch (c.verdict) {
    case 'public':
      return { tone: 'green', title: '真公网 IP', body: `外部服务看到的地址和 WAN 口一致，外面可以直接连到家里（转发端口或开放面板即可）。${c.seen.some((s) => s.ip && s.ip !== c.wan_ip) ? '有个别查询看到了别的地址，多半是代理插件接管了它，不影响判断。' : ''}` }
    case 'public_unverified':
      return { tone: 'amber', title: '看起来是公网 IP，未能外部确认', body: 'WAN 口拿到的是公网地址，但外部查询服务都没回应（可能刚断过网，或这些网站被拦了），稍后再测一次。' }
    case 'mismatch':
      return { tone: 'amber', title: '外面看到的不是 WAN 口这个地址', body: `WAN 口是 ${c.wan_ip}，外面看到的是 ${c.external}。常见原因：代理插件（OpenClash、PassWall 等）把路由器自己的流量也带去了代理出口；或运营商在你之外又做了一层转换。前者不影响外面连回家，后者会。` }
    case 'cgnat':
      return { tone: 'red', title: '运营商大内网（不是公网 IP）', body: `${c.wan_ip && c.wan_ip.startsWith('100.') ? `WAN 口地址 ${c.wan_ip} 属于运营商内网段（100.64.0.0/10）` : `光猫往外一跳是 ${c.next_hop}，属于运营商内网段`}，外面看到的 ${c.external || '地址'} 是很多用户共用的，外面连不进来，DDNS 也没用。` }
    case 'modem':
      if (c.next_hop_kind === 'public') return { tone: 'amber', title: '公网 IP 在光猫上，路由器在它后面', body: `外面看到的是 ${c.external}，这个地址多半在光猫上（光猫往外一跳 ${c.next_hop} 已是公网）。路由器拿到的是光猫分的内网地址 ${c.wan_ip}，外面要连回家得先过光猫。` }
      if (c.next_hop_kind === 'private') return { tone: 'amber', title: '路由器在内网里，公网地址在更上游', body: `路由器 WAN 是 ${c.wan_ip}，再往外一跳 ${c.next_hop} 仍是内网地址，可能是光猫后面还有一台路由，也可能是运营商的内网。外面看到的是 ${c.external || '（没测出来）'}。` }
      return { tone: 'amber', title: '路由器在光猫 / 上级路由后面', body: `路由器 WAN 是内网地址 ${c.wan_ip}，外面看到的是 ${c.external || '（没测出来）'}。沿路的几跳没有回应，判断不了上游是不是公网。` }
    default:
      return { tone: 'muted', title: 'WAN 口还没有 IPv4 地址', body: '等宽带连上后再测。' }
  }
}

function Advice({ c }: { c: PublicCheck }) {
  const reachable = c.verdict === 'public' || c.verdict === 'public_unverified' || (c.verdict === 'mismatch')
  const here = (c.ddns ?? []).filter((d) => d.points_here && d.enabled)
  const v4 = here.filter((d) => d.rtype === 'A')
  const v6 = here.filter((d) => d.rtype === 'AAAA')
  const items: React.ReactNode[] = []

  if (reachable) {
    if (!c.ddns_visible) {
      if (c.dynamic) items.push(<>这个地址会变（{c.proto === 'pppoe' ? '拨号' : '自动获取'}），可以请超级管理员设一个动态域名（DDNS）。</>)
    } else if (v4.length) {
      items.push(<>已有域名指向这里：{v4.map((d) => <span key={d.id} className="mx-1 font-mono">{d.domain}</span>)}</>)
    } else {
      items.push(
        <span className="flex flex-wrap items-center gap-2">
          {c.dynamic ? `这个地址会变（${c.proto === 'pppoe' ? '每次重新拨号都可能换' : '自动获取的'}），设一个动态域名，以后用域名就能找到家里。` : '这是固定地址，直接用 IP 也行；想记得住可以给它配个域名。'}
          <Button size="xs" render={<Link to={`/ddns?new=1&rtype=A&iface=${c.iface}`} />}>设置 DDNS</Button>
        </span>,
      )
    }
    items.push(<>国内家宽一般封了 80 / 443 和部分常见端口，对外服务换个高位端口更稳。</>)
  } else if (c.verdict !== 'none') {
    if (c.verdict === 'modem' && c.next_hop_kind !== 'private') {
      items.push(<>让光猫改成<b>桥接</b>，由路由器自己拨号，公网 IP 就到路由器上了（需要宽带账号密码，可问运营商）。</>)
      items.push(<>或者在光猫里把路由器 {c.wan_ip} 设为 <b>DMZ 主机</b>，外面的连接全部转给路由器。</>)
    }
    if (c.verdict === 'cgnat' || c.next_hop_kind === 'private') {
      items.push(<>打运营商客服申请「公网 IP」：国内电信大多免费可开，联通、移动视地区而定。</>)
    }
    if (c.ipv6) {
      items.push(
        <span className="flex flex-wrap items-center gap-2">
          家里有公网 IPv6（<span className="font-mono">{c.ipv6}</span>），手机流量、多数公司网络都能用 IPv6 直连回家。
          {c.ddns_visible && (v6.length
            ? <span>已有域名：{v6.map((d) => <span key={d.id} className="mx-1 font-mono">{d.domain}</span>)}</span>
            : <Button size="xs" variant="outline" render={<Link to={`/ddns?new=1&rtype=AAAA&iface=${c.iface}6`} />}>设置 IPv6 DDNS</Button>)}
        </span>,
      )
    }
    items.push(<>都不行的话，用 Cloudflare Tunnel、frp 这类「内网穿透」从里往外连，不需要公网 IP。</>)
  }
  if (!items.length) return null
  return (
    <ul className="grid gap-1.5 text-sm">
      {items.map((x, i) => <li key={i} className="flex gap-2"><span className="mt-2 size-1 shrink-0 rounded-full bg-muted-foreground/60" /><div className="min-w-0">{x}</div></li>)}
    </ul>
  )
}

export function PublicIPCard({ iface }: { iface: string }) {
  const [c, setC] = useState<PublicCheck | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [open, setOpen] = useState(false)
  const load = async (refresh = false) => {
    setBusy(true); setErr('')
    try { setC(await api<PublicCheck>('GET', `/net/public?iface=${encodeURIComponent(iface)}${refresh ? '&refresh=1' : ''}`)) } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  useEffect(() => { load() }, [iface]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!c) {
    return (
      <section className="flex items-center gap-3 rounded-2xl border bg-card p-4 text-sm text-muted-foreground">
        {busy ? <><Loader2 className="size-4 animate-spin" /> 正在从外部检测公网 IP…</> : <>{err || '没测出来'} <Button size="xs" variant="ghost" onClick={() => load(true)}>重试</Button></>}
      </section>
    )
  }
  const v = verdictText(c)
  const Icon = v.tone === 'green' ? ShieldCheck : v.tone === 'red' ? ShieldAlert : ShieldQuestion
  return (
    <section className="grid gap-3 rounded-2xl border bg-card p-4 sm:p-5">
      <div className="flex flex-wrap items-start gap-3">
        <span className={cn('grid size-10 shrink-0 place-items-center rounded-xl', { green: 'bg-success/12 text-success', amber: 'bg-warning/18 text-warning', red: 'bg-destructive/10 text-destructive', muted: 'bg-muted text-muted-foreground' }[v.tone])}>
          <Icon className="size-5" />
        </span>
        <div className="grid min-w-0 flex-1 gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold">公网检测</span>
            <Pill tone={v.tone === 'muted' ? 'muted' : v.tone}>{v.title}</Pill>
            {c.external && <span className="font-mono text-sm">{c.external}</span>}
          </div>
          <p className="text-sm text-muted-foreground">{v.body}</p>
        </div>
        <Button variant="ghost" size="sm" onClick={() => load(true)} disabled={busy}>{busy ? <Loader2 className="animate-spin" /> : <RefreshCw />} 重新检测</Button>
      </div>
      <Advice c={c} />
      <button type="button" className="flex w-fit items-center gap-1 text-xs text-muted-foreground hover:text-foreground" onClick={() => setOpen(!open)}>
        <ChevronDown className={cn('size-3.5 transition-transform', open && 'rotate-180')} /> 检测明细
      </button>
      {open && (
        <div className="grid gap-1 rounded-lg bg-muted/50 p-3 font-mono text-xs">
          <div><span className="text-muted-foreground">WAN 口（{c.iface}）</span> {c.wan_ip || '—'}</div>
          {c.seen.map((s) => (
            <div key={s.source} className="flex gap-2">
              <Globe2 className="mt-0.5 size-3 shrink-0 text-muted-foreground" />
              <span className="text-muted-foreground">{SRC[s.source] ?? s.source} 看到</span>
              {s.ip ? <span className={cn(s.ip !== c.external && 'text-warning')}>{s.ip}</span> : <span className="text-muted-foreground">{s.error || '没回应'}</span>}
            </div>
          ))}
          {c.hops?.length ? <div><span className="text-muted-foreground">往外几跳</span> {c.hops.map((h) => h || '*').join(' → ')}</div> : null}
          {c.ipv6 && <div><span className="text-muted-foreground">IPv6</span> {c.ipv6}{c.ipv6_external && c.ipv6_external !== c.ipv6 ? `（外面看到 ${c.ipv6_external}）` : ''}</div>}
          <div className="text-muted-foreground">检测于 {new Date(c.checked * 1000).toLocaleTimeString()}，结果缓存 10 分钟</div>
        </div>
      )}
    </section>
  )
}
