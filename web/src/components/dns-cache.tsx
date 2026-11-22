import { useState } from 'react'
import { toast } from 'sonner'
import { ArrowRight, Loader2, RefreshCw, Search } from 'lucide-react'
import { post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { ago } from '@/lib/format'
import { cn } from '@/lib/utils'
import { Pill, Section, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

interface CacheInfo {
  dnsmasq_cache: number; dnsmasq_since: number; rebind_protection: boolean
  upstreams: { addr: string; port?: number; proc?: string; kind: string; flush?: boolean }[] | null
  nextdns?: { running: boolean; profile: string; cache_size: string; cache_max_age: string; max_ttl: string; hit: number; miss: number; entries: number; since: number }
}
interface Layer { id: string; label: string; server: string; status?: string; records: string[]; addrs: string[]; ttl: number; ms: number; cached?: boolean; error?: string }
interface Trace {
  name: string; type: string; zone?: string; ns?: string; neg_ttl?: number; layers: Layer[]; rebind_protection: boolean
  verdict: 'ok' | 'stale_missing' | 'stale_answer' | 'cloud_stale' | 'missing' | 'rebind' | 'blocked' | 'unknown'; stale?: string
}
interface FlushRes { results: { target: string; ok: boolean; ms: number; error?: string }[] }

const KIND: Record<string, string> = { nextdns: 'NextDNS', smartdns: 'SmartDNS', adguardhome: 'AdGuard Home', mosdns: 'MosDNS', openclash: 'OpenClash', local: '本地程序', remote: '外部 DNS' }
const AGES = [
  { v: '0s', label: '跟随记录（默认）' }, { v: '1m', label: '1 分钟' }, { v: '5m', label: '5 分钟' }, { v: '10m', label: '10 分钟' }, { v: '15m', label: '15 分钟（折中）' }, { v: '30m', label: '30 分钟' }, { v: '1h', label: '1 小时' },
]

const dur = (s: number) => (s >= 3600 ? `${Math.round(s / 360) / 10} 小时` : s >= 60 ? `${Math.round(s / 60)} 分钟` : `${s} 秒`)
const ageLabel = (v?: string) => AGES.find((a) => a.v === (v || '0s'))?.label ?? v

function verdictOf(t: Trace, upName: string): { tone: 'green' | 'amber' | 'red' | 'muted'; title: string; body: string; flush?: boolean; rebind?: boolean } {
  const neg = t.neg_ttl ? `这个域名把「不存在」的结果允许缓存 ${dur(t.neg_ttl)}` : ''
  const where = (id?: string) => (id === 'upstream' ? upName : id === 'cloud' ? 'NextDNS 云端' : '路由器 dnsmasq')
  switch (t.verdict) {
    case 'ok':
      return { tone: 'green', title: '家里解析正常', body: '家里查到的和域名权威服务器一致。如果某台设备还打不开，是那台设备或浏览器自己的缓存，见下方提示。' }
    case 'stale_missing':
      return { tone: 'amber', title: `缓存还记着「不存在」（卡在 ${where(t.stale)}）`, flush: t.stale !== 'cloud',
        body: `域名权威服务器上已经有这条记录，但家里还在用之前查到的「没有这个域名」。${neg ? neg + '，' : ''}通常是新建记录前刚好有设备查过一次。刷新缓存就能立刻看到。` }
    case 'stale_answer':
      return { tone: 'amber', title: `家里还是旧结果（卡在 ${where(t.stale)}）`, flush: t.stale !== 'cloud',
        body: '权威服务器上的记录已经改了（或删了），家里还在用缓存里的旧地址。刷新缓存后立刻用新的。' }
    case 'cloud_stale':
      return { tone: 'amber', title: 'NextDNS 云端还没更新',
        body: `路由器上的缓存没问题，是 NextDNS 云端服务器自己还记着旧结果，路由器清不掉。${neg ? neg + '，' : ''}最多等这么久会自动好；着急可以临时让这台设备用别的 DNS（比如 1.1.1.1）。` }
    case 'missing':
      return { tone: 'red', title: '域名本身还没有这条记录', body: `连域名的权威服务器${t.ns ? `（${t.ns.replace(/\.$/, '')}）` : ''}都查不到 ${t.type} 记录。检查 DNS 服务商（如 Cloudflare）里记录是否保存成功、名字是否拼对、类型是否选对。和路由器缓存无关。` }
    case 'rebind':
      return { tone: 'amber', title: '被「防 DNS 重绑定」拦下了', rebind: true,
        body: '这个公网域名解析到的是内网地址，路由器为防攻击把它丢掉了，所以家里看起来「没有 IP」。如果这是你自己的内网服务，把它加入允许名单即可。' }
    case 'blocked':
      return { tone: 'red', title: '被 NextDNS 拦截了', body: '家里拿到的是 0.0.0.0，说明 NextDNS 的拦截规则命中了这个域名。到 NextDNS 后台的允许名单里放行它，再刷新缓存。' }
    default:
      return { tone: 'muted', title: '判断不了', body: '外部的权威服务器和 1.1.1.1 都没有回应，可能是路由器暂时连不上外网。' }
  }
}

export function DNSCacheCard({ manage, onRebindAllow }: { manage: boolean; onRebindAllow: (name: string) => Promise<void> }) {
  const { data, reload } = useApi<CacheInfo>('/net/dns/cache')
  const { confirm, dialog } = useConfirm()
  const [name, setName] = useState('')
  const [type, setType] = useState('A')
  const [trace, setTrace] = useState<Trace | null>(null)
  const [busy, setBusy] = useState<'' | 'trace' | 'flush' | 'age'>('')
  const nd = data?.nextdns
  const up = data?.upstreams?.find((u) => u.port)
  const upName = up ? KIND[up.kind] ?? up.addr : '上游'

  const lookup = async (n = name, ty = type) => {
    if (!n.trim()) return
    setBusy('trace')
    try { setTrace(await post<Trace>('/net/dns/trace', { name: n, type: ty })) } catch (e) { toast.error((e as Error).message) } finally { setBusy('') }
  }
  const flush = async (ask: boolean) => {
    if (ask && !(await confirm('刷新 DNS 缓存？', `会清空路由器 dnsmasq 的缓存${up?.flush ? `，并重启 ${upName}（约 1 秒，期间的查询会稍慢一点，不会断网）` : ''}。之后每个域名第一次访问会重新去外面查。`, { ok: '刷新' }))) return
    setBusy('flush')
    try {
      const r = await post<FlushRes>('/net/dns/flush', { targets: up?.flush ? ['upstream', 'dnsmasq'] : ['dnsmasq'], name: trace?.name })
      const bad = r.results.filter((x) => !x.ok)
      if (bad.length) toast.error(bad.map((x) => x.error).join('；'))
      else toast.success('DNS 缓存已刷新')
      reload()
      if (trace) await lookup(trace.name, trace.type)
    } catch (e) { toast.error((e as Error).message) } finally { setBusy('') }
  }
  const setAge = async (v: string) => {
    if (!(await confirm(`NextDNS 缓存最长保留：${ageLabel(v)}？`, `保存后 NextDNS 会重启一次（约 1 秒），缓存同时清空。`, { ok: '保存' }))) return
    setBusy('age')
    try { await put('/net/dns/nextdns', { cache_max_age: v }); toast.success('已保存'); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy('') }
  }

  const v = trace && verdictOf(trace, upName)
  const hitRate = nd && nd.hit + nd.miss > 0 ? Math.round((nd.hit / (nd.hit + nd.miss)) * 100) : null
  const clientTTL = nd?.max_ttl && /^\d+s$/.test(nd.max_ttl) ? Number(nd.max_ttl.slice(0, -1)) : null

  return (
    <Section title="DNS 缓存与排查" desc="新建的域名在家里打不开、改了解析还是旧地址时，查一下卡在哪一层，再一键刷新。"
      action={manage && <Button size="sm" variant="outline" disabled={!!busy} onClick={() => flush(true)}>{busy === 'flush' ? <Loader2 className="animate-spin" /> : <RefreshCw />} 刷新 DNS 缓存</Button>}>
      {dialog}
      <div className="grid gap-4 p-4">
        {/* the chain */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="rounded-md bg-muted px-2 py-1">家里设备</span>
          <ArrowRight className="size-3 text-muted-foreground" />
          <span className="rounded-md bg-muted px-2 py-1">dnsmasq · 缓存 {data?.dnsmasq_cache ?? '…'} 条{data?.dnsmasq_since ? ` · ${ago(data.dnsmasq_since)}清空` : ''}</span>
          {up && <>
            <ArrowRight className="size-3 text-muted-foreground" />
            <span className="rounded-md bg-muted px-2 py-1">
              {upName}{nd && up.kind === 'nextdns' ? ` · ${nd.entries} 条${hitRate != null ? ` · 命中 ${hitRate}%` : ''}${nd.since ? ` · ${ago(nd.since)}清空` : ''}` : ''}
            </span>
            {up.kind === 'nextdns' && <><ArrowRight className="size-3 text-muted-foreground" /><span className="rounded-md bg-muted px-2 py-1">NextDNS 云端</span></>}
          </>}
          <ArrowRight className="size-3 text-muted-foreground" />
          <span className="rounded-md bg-muted px-2 py-1">域名的权威服务器</span>
        </div>
        {up && !up.flush && <p className="text-xs text-muted-foreground">上游 {upName} 的缓存 Wharf 清不了，「刷新」只清 dnsmasq；需要时到「插件」里重启 {upName}。</p>}

        {/* lookup */}
        <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); lookup() }}>
          <Input className="min-w-56 flex-1 font-mono" placeholder="打不开的域名，如 app.example.com" value={name} onChange={(e) => setName(e.target.value)} />
          <select className="h-9 rounded-md border bg-background px-2 text-sm" value={type} onChange={(e) => setType(e.target.value)}>
            {['A', 'AAAA', 'CNAME', 'TXT', 'MX'].map((t) => <option key={t}>{t}</option>)}
          </select>
          <Button type="submit" disabled={!!busy || !name.trim()}>{busy === 'trace' ? <Loader2 className="animate-spin" /> : <Search />} 逐层查询</Button>
        </form>

        {trace && v && (
          <div className="grid gap-3">
            <div className={cn('grid gap-2 rounded-lg border p-3', { green: 'border-success/30 bg-success/5', amber: 'border-warning/40 bg-warning/5', red: 'border-destructive/30 bg-destructive/5', muted: '' }[v.tone])}>
              <div className="flex flex-wrap items-center gap-2"><Pill tone={v.tone}>{v.title}</Pill><span className="font-mono text-sm">{trace.name}</span></div>
              <p className="text-sm text-muted-foreground">{v.body}</p>
              {manage && (v.flush || v.rebind) && (
                <div className="flex flex-wrap gap-2">
                  {v.flush && <Button size="sm" disabled={!!busy} onClick={() => flush(false)}>{busy === 'flush' && <Loader2 className="animate-spin" />} 刷新缓存并重查</Button>}
                  {v.rebind && <Button size="sm" onClick={async () => { await onRebindAllow(trace.name); await flush(false) }}>允许 {trace.name} 解析到内网</Button>}
                </div>
              )}
            </div>
            <div className="overflow-x-auto rounded-lg border">
              <table className="w-full text-sm">
                <thead className="bg-muted/50 text-xs text-muted-foreground"><tr><th className="px-3 py-2 text-left font-medium">谁回答的</th><th className="px-3 py-2 text-left font-medium">结果</th><th className="px-3 py-2 text-right font-medium">TTL</th><th className="px-3 py-2 text-right font-medium">耗时</th></tr></thead>
                <tbody>
                  {trace.layers.map((l) => (
                    <tr key={l.id} className={cn('border-t align-top', trace.stale === l.id && 'bg-warning/8')}>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">{l.label}{trace.stale === l.id && <Pill tone="amber">卡在这</Pill>}</div>
                        <div className="font-mono text-xs text-muted-foreground">{l.server}{l.cached != null && ` · ${l.cached ? '查询前已在缓存里' : '查询前不在缓存里'}`}</div>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">
                        {l.error ? <span className="text-muted-foreground">{l.error}</span>
                          : l.records.length ? l.records.map((r, i) => <div key={i} className="break-all">{r}</div>)
                          : <span className={cn(l.status === 'NXDOMAIN' || l.status === 'NOERROR' ? 'text-warning' : 'text-muted-foreground')}>{l.status === 'NXDOMAIN' ? '不存在（NXDOMAIN）' : l.status === 'NOERROR' ? `没有 ${trace.type} 记录` : l.status}</span>}
                      </td>
                      <td className="px-3 py-2 text-right text-xs tabular-nums text-muted-foreground">{l.error ? '' : l.id === 'auth' ? '—' : dur(l.ttl)}</td>
                      <td className="px-3 py-2 text-right text-xs tabular-nums text-muted-foreground">{l.error ? '' : `${l.ms} ms`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-xs text-muted-foreground">
              设备自己也会缓存：{clientTTL != null ? `NextDNS 只让设备缓存 ${clientTTL} 秒，路由器刷新后设备很快就跟上。` : '一般几分钟。'}
              浏览器还打不开就关掉重开；Chrome 可在 chrome://net-internals/#dns 清除；Mac 终端执行 <code>sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder</code>；Windows 执行 <code>ipconfig /flushdns</code>。
            </p>
          </div>
        )}

        {/* prevention */}
        {nd && up?.kind === 'nextdns' && (
          <div className="grid gap-2 rounded-lg border p-3 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">NextDNS 缓存最长保留</span>
              {manage
                ? <select className="h-8 rounded-md border bg-background px-2 text-sm" disabled={!!busy} value={nd.cache_max_age || '0s'} onChange={(e) => setAge(e.target.value)}>
                    {AGES.map((a) => <option key={a.v} value={a.v}>{a.label}</option>)}
                  </select>
                : <Pill>{ageLabel(nd.cache_max_age)}</Pill>}
              {busy === 'age' && <Loader2 className="size-4 animate-spin" />}
            </div>
            <p className="text-xs text-muted-foreground">
              默认按每条记录自己的时间缓存：Cloudflare 上的域名，「不存在」会被记 30 分钟，正常记录一般 5 分钟。设得越短，新建的记录越快在家里生效，但 NextDNS 越常去云端查，命中率略降、个别网页首次打开慢几十毫秒。想折中可选 15 分钟：「不存在」最多记 15 分钟（默认是 30 分钟），只有缓存时间超过 15 分钟的记录会提早去云端重查，命中率影响很小。偶尔新建域名，用上面的「刷新 DNS 缓存」更直接。
            </p>
          </div>
        )}
      </div>
    </Section>
  )
}
