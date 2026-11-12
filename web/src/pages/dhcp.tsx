import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { Loader2, Pencil, Plus, Trash2 } from 'lucide-react'
import { del, post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Empty, ErrorBox, Field, HalfPanel, Pill, Section, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

interface Pool {
  section: string; interface: string; start: string; limit: string; leasetime: string; ignore: boolean; force: boolean
  dns: string[] | null; gateway: string; subnet?: string; proto?: string; other_options: string[] | null; dhcpv6: string; ra: string
}
interface Host { section: string; name: string; mac: string[] | null; ip: string; leasetime: string; managed: boolean }
interface DnsCfg {
  section: string; server: string[] | null; noresolv: boolean; cachesize: string; domain: string; rebind_protection: boolean; rebind_domain: string[] | null
  filter_aaaa: boolean; localservice: boolean; upstream_hint: string; logqueries: boolean
}
interface Lease { hostname?: string; ipaddr?: string; macaddr?: string; expires?: number }
interface DhcpResp {
  pools: Pool[] | null; hosts: Host[] | null; domains: { section: string; name: string; ip: string; managed: boolean }[] | null; dnsmasq: DnsCfg | null
  leases: { dhcp_leases?: Lease[] } | null; interfaces: string[]
}

function poolRange(p: Pool): string {
  const base = p.subnet?.split('/')[0]
  const start = Number(p.start), limit = Number(p.limit)
  if (!base || !start || !limit) return `第 ${p.start} 个起，共 ${p.limit} 个`
  const parts = base.split('.').map(Number)
  const n = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8)
  const ip = (x: number) => [x >>> 24, (x >> 16) & 255, (x >> 8) & 255, x & 255].join('.')
  return `${ip(n + start)} – ${ip(n + start + limit - 1)}`
}

const leaseLabel = (s: string) => {
  const m = /^(\d+)([smhdw]?)$/.exec(s)
  if (s === 'infinite') return '永久'
  if (!m) return s || '默认（12 小时）'
  return m[1] + ({ s: ' 秒', m: ' 分钟', h: ' 小时', d: ' 天', w: ' 周', '': ' 秒' } as Record<string, string>)[m[2]]
}

export default function DHCPPage() {
  const { can } = useAuth()
  const manage = can('network.manage')
  const { data, error, reload } = useApi<DhcpResp>('/net/dhcp', 30000)
  const [pool, setPool] = useState<Pool | 'new' | null>(null)
  const [host, setHost] = useState<Partial<Host> | null>(null)
  const { confirm, dialog } = useConfirm()
  const leases = data?.leases?.dhcp_leases ?? []
  const missing = (data?.interfaces ?? []).filter((i) => !data?.pools?.some((p) => p.interface === i))

  const removeHost = async (h: Host) => {
    if (!(await confirm(`删除 ${h.ip} 的静态分配？`, '设备下次续租时会从地址池里拿一个新地址。', { danger: true, ok: '删除' }))) return
    try { await del(`/net/dhcp/host/${h.section}`); toast.success('已删除'); reload() } catch (e) { toast.error((e as Error).message) }
  }

  return (
    <div className="grid gap-4">
      <PageHeader title="DHCP 与 DNS" desc="给家里设备分配地址的规则、固定 IP，以及路由器去哪里解析域名。" />
      {error && <ErrorBox>{error}</ErrorBox>}

      <Section title="地址池" desc="每个局域网接口给设备自动分配的地址范围。" action={manage && missing.length > 0 && <Button size="sm" variant="outline" onClick={() => setPool('new')}><Plus /> 为接口开启 DHCP</Button>}>
        <div className="grid gap-3 p-4 lg:grid-cols-2">
          {data?.pools?.map((p) => (
            <div key={p.section} className={cn('grid gap-2 rounded-xl border p-3', p.ignore && 'opacity-70')}>
              <div className="flex items-center gap-2">
                <span className="font-semibold">{p.interface.toUpperCase()}</span>
                {p.subnet && <span className="font-mono text-xs text-muted-foreground">{p.subnet}</span>}
                {p.ignore ? <Pill>不分配地址</Pill> : <Pill tone="green">正在分配</Pill>}
                <span className="flex-1" />
                {manage && <Button variant="ghost" size="icon-sm" onClick={() => setPool(p)}><Pencil /></Button>}
              </div>
              {!p.ignore && (
                <div className="grid gap-1 text-sm sm:grid-cols-2">
                  <div><span className="text-xs text-muted-foreground">范围 </span><span className="font-mono">{poolRange(p)}</span></div>
                  <div><span className="text-xs text-muted-foreground">租期 </span>{leaseLabel(p.leasetime)}</div>
                  <div><span className="text-xs text-muted-foreground">下发 DNS </span><span className="font-mono">{p.dns?.join('、') || '路由器自己'}</span></div>
                  <div><span className="text-xs text-muted-foreground">下发网关 </span><span className="font-mono">{p.gateway || '路由器自己'}</span></div>
                </div>
              )}
              {p.interface === 'wan' && !p.ignore && <p className="text-xs text-warning">WAN 口在分配地址，通常不应该这样。</p>}
            </div>
          ))}
          {data && !data.pools?.length && <Empty>没有地址池</Empty>}
        </div>
      </Section>

      {data?.dnsmasq && <DNSCard d={data.dnsmasq} manage={manage} onSaved={reload} />}

      <Section title="静态分配（固定 IP）" desc="让某台设备每次都拿到同一个地址。设备页的「固定 IP」也写在这里。"
        action={manage && <Button size="sm" onClick={() => setHost({})}><Plus /> 添加</Button>}>
        <div className="divide-y">
          {data?.hosts?.map((h) => (
            <div key={h.section} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2 text-sm">
              <span className="w-32 font-mono">{h.ip}</span>
              <span className="min-w-0 flex-1 truncate">{h.name || <span className="text-muted-foreground">未命名</span>}</span>
              <span className="font-mono text-xs text-muted-foreground">{h.mac?.join(' ')}</span>
              {h.leasetime && <span className="text-xs text-muted-foreground">租期 {leaseLabel(h.leasetime)}</span>}
              {manage && (
                <span className="flex gap-1">
                  <Button variant="ghost" size="icon-sm" onClick={() => setHost(h)}><Pencil /></Button>
                  <Button variant="ghost" size="icon-sm" onClick={() => removeHost(h)}><Trash2 /></Button>
                </span>
              )}
            </div>
          ))}
          {data && !data.hosts?.length && <Empty>还没有静态分配</Empty>}
        </div>
      </Section>

      <Section title="当前租约" desc="正在使用自动分配地址的设备。">
        <div className="divide-y">
          {leases.map((l, i) => (
            <div key={i} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2 text-sm">
              <span className="w-32 font-mono">{l.ipaddr}</span>
              <span className="min-w-0 flex-1 truncate">{l.hostname || <span className="text-muted-foreground">无主机名</span>}</span>
              <span className="font-mono text-xs text-muted-foreground">{l.macaddr?.toUpperCase()}</span>
              <span className="w-28 text-right text-xs text-muted-foreground">{l.expires == null ? '' : l.expires <= 0 ? '已过期' : `${Math.round(l.expires / 60)} 分钟后到期`}</span>
              {manage && !data?.hosts?.some((h) => h.mac?.some((m) => m.toUpperCase() === l.macaddr?.toUpperCase())) && (
                <Button variant="ghost" size="sm" onClick={() => setHost({ name: l.hostname ?? '', mac: [l.macaddr?.toUpperCase() ?? ''], ip: l.ipaddr ?? '' })}>固定这个地址</Button>
              )}
            </div>
          ))}
          {data && !leases.length && <Empty>没有租约</Empty>}
        </div>
      </Section>

      {data?.domains && data.domains.length > 0 && (
        <Section title="自定义域名解析" desc="在局域网里把某个域名解析到指定地址。在「网络工具 → 自定义解析」里管理。" action={<Button variant="ghost" size="sm" render={<Link to="/tools" />}>去管理</Button>}>
          <div className="divide-y">
            {data.domains.map((d) => (
              <div key={d.section} className="flex items-center gap-4 px-4 py-2 text-sm">
                <span className="min-w-0 flex-1 truncate font-mono">{d.name}</span><span className="font-mono text-muted-foreground">{d.ip}</span>
                {d.managed && <Pill tone="blue">Wharf</Pill>}
              </div>
            ))}
          </div>
        </Section>
      )}

      {pool && data && <PoolEditor pool={pool === 'new' ? null : pool} ifaces={missing} onClose={() => setPool(null)} onSaved={() => { setPool(null); reload() }} />}
      {host && <HostEditor host={host} onClose={() => setHost(null)} onSaved={() => { setHost(null); reload() }} />}
      {dialog}
    </div>
  )
}

function DNSCard({ d, manage, onSaved }: { d: DnsCfg; manage: boolean; onSaved: () => void }) {
  const [v, setV] = useState({ ...d, server: (d.server ?? []).join('\n'), rebind_domain: (d.rebind_domain ?? []).join('\n') })
  const [busy, setBusy] = useState(false)
  const dirty = useMemo(() => JSON.stringify(v) !== JSON.stringify({ ...d, server: (d.server ?? []).join('\n'), rebind_domain: (d.rebind_domain ?? []).join('\n') }), [v, d])
  const save = async () => {
    setBusy(true)
    try {
      await put('/net/dns', { ...v, server: v.server.split(/\s+/).filter(Boolean), rebind_domain: v.rebind_domain.split(/\s+/).filter(Boolean) })
      toast.success('DNS 设置已生效'); onSaved()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const sw = (k: 'noresolv' | 'rebind_protection' | 'filter_aaaa' | 'localservice', label: string, hint: string) => (
    <label className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm">
      <span>{label}<span className="block text-xs text-muted-foreground">{hint}</span></span>
      <Switch checked={v[k]} disabled={!manage} onCheckedChange={(c) => setV({ ...v, [k]: !!c })} />
    </label>
  )
  return (
    <Section title="DNS" desc="路由器替家里设备解析域名时，去问哪些上游。">
      <div className="grid gap-4 p-4 lg:grid-cols-2">
        <div className="grid gap-3">
          <Field label="上游 DNS" hint={<>每行一个，如 <code>223.5.5.5</code>、<code>127.0.0.1#5342</code>、<code>/corp.example/10.0.0.53</code>（指定域名走指定服务器）</>}>
            <textarea className="min-h-24 rounded-md border bg-background px-3 py-2 font-mono text-sm" disabled={!manage} value={v.server} onChange={(e) => setV({ ...v, server: e.target.value })} />
          </Field>
          {d.upstream_hint && <p className="text-xs text-muted-foreground">现在的上游是 <Pill tone="blue">{d.upstream_hint}</Pill>，改上游前先确认这个插件不再需要。</p>}
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="缓存条数"><Input value={v.cachesize} disabled={!manage} onChange={(e) => setV({ ...v, cachesize: e.target.value })} className="font-mono" placeholder="150" /></Field>
            <Field label="本地域名" hint="设备可用 主机名.这个域名 访问"><Input value={v.domain} disabled={!manage} onChange={(e) => setV({ ...v, domain: e.target.value })} className="font-mono" placeholder="lan" /></Field>
          </div>
        </div>
        <div className="grid content-start gap-2">
          {sw('noresolv', '不用运营商的 DNS', '只问左边填的上游')}
          {sw('rebind_protection', '防 DNS 重绑定', '拒绝公网域名解析到内网地址（防攻击）')}
          {v.rebind_protection && (
            <Field label="允许解析到内网的域名" hint="每行一个，例如自己的内网服务域名">
              <textarea className="min-h-16 rounded-md border bg-background px-3 py-2 font-mono text-sm" disabled={!manage} value={v.rebind_domain} onChange={(e) => setV({ ...v, rebind_domain: e.target.value })} />
            </Field>
          )}
          {sw('filter_aaaa', '不返回 IPv6 地址', '没有 IPv6 时可减少等待')}
          {sw('localservice', '只服务本地网络', '不回答来自外网的查询（建议开启）')}
          {d.logqueries && <p className="text-xs text-muted-foreground">查询日志由 Wharf 的「DNS 拦截」统计使用，在这里不显示开关。</p>}
        </div>
      </div>
      {manage && dirty && (
        <div className="flex justify-end gap-2 border-t px-4 py-2">
          <Button variant="outline" size="sm" onClick={() => setV({ ...d, server: (d.server ?? []).join('\n'), rebind_domain: (d.rebind_domain ?? []).join('\n') })}>还原</Button>
          <Button size="sm" disabled={busy} onClick={save}>{busy && <Loader2 className="animate-spin" />} 保存</Button>
        </div>
      )}
    </Section>
  )
}

function PoolEditor({ pool, ifaces, onClose, onSaved }: { pool: Pool | null; ifaces: string[]; onClose: () => void; onSaved: () => void }) {
  const [v, setV] = useState({
    interface: pool?.interface ?? ifaces[0] ?? '', start: pool?.start || '100', limit: pool?.limit || '150', leasetime: pool?.leasetime || '12h',
    ignore: pool?.ignore ?? false, force: pool?.force ?? false, dns: (pool?.dns ?? []).join(' '), gateway: pool?.gateway ?? '',
  })
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    const body = { ...v, dns: v.dns.split(/[\s,，]+/).filter(Boolean) }
    try {
      if (pool) await put(`/net/dhcp/pool/${pool.section}`, body)
      else await post('/net/dhcp/pool', body)
      toast.success('已生效'); onSaved()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <HalfPanel open onOpenChange={(o) => { if (!o) onClose() }} title={pool ? `地址池 ${pool.interface.toUpperCase()}` : '为接口开启 DHCP'}
      footer={<><Button variant="outline" onClick={onClose}>取消</Button><Button disabled={busy} onClick={save}>{busy && <Loader2 className="animate-spin" />} 保存</Button></>}>
      <div className="grid gap-4">
        {!pool && (
          <Field label="接口">
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={v.interface} onChange={(e) => setV({ ...v, interface: e.target.value })}>
              {ifaces.map((i) => <option key={i} value={i}>{i}</option>)}
            </select>
          </Field>
        )}
        <label className="flex items-center justify-between rounded-lg border px-3 py-2 text-sm">不给这个接口分配地址<Switch checked={v.ignore} onCheckedChange={(c) => setV({ ...v, ignore: !!c })} /></label>
        {!v.ignore && (
          <>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="从第几个地址开始" hint="如 100 → x.x.x.100"><Input value={v.start} onChange={(e) => setV({ ...v, start: e.target.value })} className="font-mono" /></Field>
              <Field label="最多分配几个"><Input value={v.limit} onChange={(e) => setV({ ...v, limit: e.target.value })} className="font-mono" /></Field>
              <Field label="租期" hint="12h、30m、7d、infinite"><Input value={v.leasetime} onChange={(e) => setV({ ...v, leasetime: e.target.value })} className="font-mono" /></Field>
            </div>
            <Field label="下发给设备的 DNS" hint="留空 = 路由器自己（推荐，这样 DNS 统计和拦截才有效）"><Input value={v.dns} onChange={(e) => setV({ ...v, dns: e.target.value })} className="font-mono" placeholder="留空" /></Field>
            <Field label="下发给设备的网关" hint="留空 = 路由器自己；旁路由场景才需要填"><Input value={v.gateway} onChange={(e) => setV({ ...v, gateway: e.target.value })} className="font-mono" placeholder="留空" /></Field>
            <label className="flex items-center justify-between rounded-lg border px-3 py-2 text-sm">
              <span>强制分配<span className="block text-xs text-muted-foreground">即使网络里已有别的 DHCP 服务器（如光猫）也照样分配</span></span>
              <Switch checked={v.force} onCheckedChange={(c) => setV({ ...v, force: !!c })} />
            </label>
          </>
        )}
      </div>
    </HalfPanel>
  )
}

function HostEditor({ host, onClose, onSaved }: { host: Partial<Host>; onClose: () => void; onSaved: () => void }) {
  const [v, setV] = useState({ name: host.name ?? '', mac: (host.mac ?? []).join(' '), ip: host.ip ?? '', leasetime: host.leasetime ?? '' })
  const [busy, setBusy] = useState(false)
  const save = async () => {
    setBusy(true)
    try {
      await put('/net/dhcp/host', { section: host.section ?? '', name: v.name, mac: v.mac.split(/[\s,，]+/).filter(Boolean), ip: v.ip, leasetime: v.leasetime })
      toast.success('已保存，设备下次续租时生效'); onSaved()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <HalfPanel open onOpenChange={(o) => { if (!o) onClose() }} title={host.section ? '修改静态分配' : '添加静态分配'}
      footer={<><Button variant="outline" onClick={onClose}>取消</Button><Button disabled={busy || !v.mac || !v.ip} onClick={save}>{busy && <Loader2 className="animate-spin" />} 保存</Button></>}>
      <div className="grid gap-4">
        <Field label="MAC 地址" hint="同一台设备有多个网卡时可填多个，空格分隔"><Input value={v.mac} onChange={(e) => setV({ ...v, mac: e.target.value })} className="font-mono" placeholder="AA:BB:CC:DD:EE:FF" /></Field>
        <Field label="固定的 IP"><Input value={v.ip} onChange={(e) => setV({ ...v, ip: e.target.value })} className="font-mono" placeholder="192.168.1.50" /></Field>
        <Field label="主机名（可不填）" hint="填了以后局域网里可以用这个名字访问它"><Input value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
        <Field label="租期（可不填）"><Input value={v.leasetime} onChange={(e) => setV({ ...v, leasetime: e.target.value })} className="font-mono" placeholder="跟随地址池" /></Field>
      </div>
    </HalfPanel>
  )
}
