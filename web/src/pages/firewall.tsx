import { useState } from 'react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { ArrowRight, Loader2, Pencil, Plus, ShieldCheck, Sparkles, Trash2, X } from 'lucide-react'
import { del, post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { netChanged, type Pending } from '@/lib/netcfg'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Empty, ErrorBox, Field, HalfPanel, Pill, Section, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

interface Zone { section: string; name: string; network: string[] | null; input: string; output: string; forward: string; masq: boolean; mtu_fix: boolean; device: string[] | null; subnet: string[] | null }
interface Fwd { section: string; src: string; dest: string; enabled: boolean }
interface Rule {
  section: string; name: string; src: string; dest: string; proto: string[] | null; src_ip: string[] | null; dest_ip: string[] | null; src_port: string; dest_port: string
  target: string; family: string; enabled: boolean; icmp_type: string[] | null; src_mac: string[] | null; ipset: string; extra: string; managed: boolean
}
interface FwResp {
  defaults: { section: string; input: string; output: string; forward: string; syn_flood: boolean; drop_invalid: boolean; flow_offloading: boolean; flow_offloading_hw: boolean } | null
  zones: Zone[] | null; forwardings: Fwd[] | null; rules: Rule[] | null; includes: { section: string; path: string; type: string; enabled: boolean; managed: boolean }[] | null
  redirects: { wharf: number; other: number }; interfaces: string[]; orphans: Record<string, string[]> | null; flavor: string
}

const policyLabel: Record<string, string> = { ACCEPT: '允许', REJECT: '拒绝', DROP: '丢弃' }
const policyTone = (p: string) => (p === 'ACCEPT' ? 'green' : p === 'DROP' ? 'red' : 'amber') as 'green' | 'red' | 'amber'

export default function FirewallPage() {
  const { can } = useAuth()
  const manage = can('firewall.manage')
  const { data, error, reload } = useApi<FwResp>('/net/firewall', 30000)
  const [zone, setZone] = useState<Zone | 'new' | null>(null)
  const [rule, setRule] = useState<Rule | 'new' | null>(null)
  const [showManaged, setShowManaged] = useState(false)
  const { confirm, dialog } = useConfirm()

  const done = (r: { pending?: Pending }) => {
    if (r?.pending) toast.success('已生效。确认网络正常后在顶部点「一切正常，保留」', { duration: 8000 })
    netChanged(); reload()
  }
  const run = async (f: () => Promise<{ pending?: Pending }>) => { try { done(await f()) } catch (e) { toast.error((e as Error).message) } }
  const orphans = Object.entries(data?.orphans ?? {}).filter(([, l]) => l?.length)
  const rules = (data?.rules ?? []).filter((r) => showManaged || !r.managed)
  const managedCount = (data?.rules ?? []).filter((r) => r.managed).length

  return (
    <div className="grid gap-4">
      <PageHeader title="防火墙" desc={`谁可以进、谁可以出。每次改动生效后要在倒计时内确认，否则自动恢复。${data?.flavor ? `（${data.flavor === 'fw4' ? 'fw4 / nftables' : 'fw3 / iptables'}）` : ''}`} />
      {error && <ErrorBox>{error}</ErrorBox>}

      {orphans.length > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
          <Sparkles className="size-4 text-warning" />
          <span>区域里写着不存在的接口：{orphans.map(([z, l]) => `${z} 区的 ${l.join('、')}`).join('；')}。这通常是以前的设置留下的，不影响使用。</span>
          {manage && <Button size="sm" variant="outline" className="ml-auto" onClick={() => run(() => post('/net/firewall/tidy'))}>清理</Button>}
        </div>
      )}

      {data?.defaults && <Defaults d={data.defaults} manage={manage} onSave={(v) => run(() => put('/net/firewall/defaults', v))} />}

      <Section title="区域" desc="把接口分组：同一区域规则相同。默认 lan 区放内网，wan 区放外网。" action={manage && <Button size="sm" variant="outline" onClick={() => setZone('new')}><Plus /> 新增区域</Button>}>
        <div className="grid gap-3 p-4 lg:grid-cols-2">
          {data?.zones?.map((z) => {
            const to = (data.forwardings ?? []).filter((f) => f.src === z.name)
            return (
              <div key={z.section} className="grid gap-2 rounded-xl border p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold">{z.name}</span>
                  {(z.network ?? []).map((n) => <Pill key={n} tone={data.interfaces.includes(n) ? 'blue' : 'muted'}>{n}</Pill>)}
                  {z.masq && <Pill tone="green">地址伪装（NAT）</Pill>}
                  <span className="flex-1" />
                  {manage && <Button variant="ghost" size="icon-sm" onClick={() => setZone(z)}><Pencil /></Button>}
                  {manage && z.name !== 'lan' && z.name !== 'wan' && (
                    <Button variant="ghost" size="icon-sm" onClick={async () => { if (await confirm(`删除区域 ${z.name}？`, '和它相关的区域转发会一起删除。', { danger: true, ok: '删除' })) run(() => del(`/net/firewall/zone/${z.section}`)) }}><Trash2 /></Button>
                  )}
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  {(['input', 'output', 'forward'] as const).map((k) => (
                    <div key={k} className="rounded-lg bg-muted/40 px-2 py-1.5">
                      <div className="text-muted-foreground">{{ input: '访问路由器', output: '路由器外出', forward: '区内转发' }[k]}</div>
                      <Pill tone={policyTone(z[k])}>{policyLabel[z[k]] ?? z[k]}</Pill>
                    </div>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-1.5 text-xs">
                  <span className="text-muted-foreground">可以访问：</span>
                  {to.map((f) => (
                    <span key={f.section} className="inline-flex items-center gap-1 rounded-full bg-accent px-2 py-0.5 text-accent-foreground">
                      <ArrowRight className="size-3" />{f.dest}
                      {manage && <button className="opacity-60 hover:opacity-100" onClick={() => run(() => del(`/net/firewall/forwarding/${f.section}`))}><X className="size-3" /></button>}
                    </span>
                  ))}
                  {!to.length && <span className="text-muted-foreground">（只能访问自己区内）</span>}
                  {manage && <AddForward zones={(data.zones ?? []).map((x) => x.name).filter((n) => n !== z.name && !to.some((f) => f.dest === n))} onAdd={(dest) => run(() => post('/net/firewall/forwarding', { src: z.name, dest }))} />}
                </div>
              </div>
            )
          })}
        </div>
      </Section>

      <Section title="通信规则" desc="单独放行或拦截某些流量，例如允许外网访问某个端口。按顺序匹配，先匹配到的生效。"
        action={<div className="flex items-center gap-2">
          {managedCount > 0 && <label className="flex items-center gap-1.5 text-xs text-muted-foreground"><Switch size="sm" checked={showManaged} onCheckedChange={(c) => setShowManaged(!!c)} />显示 Wharf 的 {managedCount} 条</label>}
          {manage && <Button size="sm" onClick={() => setRule('new')}><Plus /> 新增规则</Button>}
        </div>}>
        <div className="divide-y">
          {rules.map((r) => (
            <div key={r.section} className={cn('flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-sm', !r.enabled && 'opacity-55')}>
              <Pill tone={policyTone(r.target)}>{policyLabel[r.target] ?? r.target}</Pill>
              <span className="min-w-0 font-medium">{r.name || <span className="text-muted-foreground">未命名</span>}</span>
              {r.managed && <Pill tone="blue">Wharf</Pill>}
              <span className="text-xs text-muted-foreground">{ruleSummary(r)}</span>
              <span className="flex-1" />
              {manage && !r.managed && (
                <span className="flex items-center gap-1">
                  <Switch size="sm" checked={r.enabled} onCheckedChange={(c) => run(() => post(`/net/firewall/rule/${r.section}/toggle`, { enabled: !!c }))} />
                  <Button variant="ghost" size="icon-sm" onClick={() => setRule(r)}><Pencil /></Button>
                  <Button variant="ghost" size="icon-sm" onClick={async () => { if (await confirm(`删除规则「${r.name}」？`, undefined, { danger: true, ok: '删除' })) run(() => del(`/net/firewall/rule/${r.section}`)) }}><Trash2 /></Button>
                </span>
              )}
            </div>
          ))}
          {data && !rules.length && <Empty>没有规则</Empty>}
        </div>
      </Section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="端口转发" desc="把外网的端口转到家里的设备。">
          <div className="flex items-center gap-3 p-4 text-sm">
            <ShieldCheck className="size-5 text-primary" />
            <span className="flex-1">共 {(data?.redirects.wharf ?? 0) + (data?.redirects.other ?? 0)} 条（Wharf 创建 {data?.redirects.wharf ?? 0} 条），在「端口转发」页面管理：带用量统计、来源限制和审计。</span>
            <Button size="sm" variant="outline" render={<Link to="/forwards" />}>打开</Button>
          </div>
        </Section>
        <Section title="自定义脚本" desc="插件或手工加入的额外防火墙脚本，只读显示。">
          <div className="divide-y">
            {data?.includes?.map((i) => (
              <div key={i.section} className={cn('flex items-center gap-2 px-4 py-2 text-sm', !i.enabled && 'opacity-55')}>
                <span className="min-w-0 flex-1 truncate font-mono text-xs" title={i.path}>{i.path || i.section}</span>
                {i.type && <Pill>{i.type}</Pill>}{i.managed && <Pill tone="blue">Wharf</Pill>}
              </div>
            ))}
            {data && !data.includes?.length && <Empty>没有</Empty>}
          </div>
        </Section>
      </div>

      {zone && data && <ZoneEditor zone={zone === 'new' ? null : zone} ifaces={data.interfaces} onClose={() => setZone(null)}
        onSave={(body) => run(async () => { const r = zone === 'new' ? await post<{ pending?: Pending }>('/net/firewall/zone', body) : await put<{ pending?: Pending }>(`/net/firewall/zone/${zone.section}`, body); setZone(null); return r })} />}
      {rule && data && <RuleEditor rule={rule === 'new' ? null : rule} zones={(data.zones ?? []).map((z) => z.name)} onClose={() => setRule(null)}
        onSave={(body) => run(async () => { const r = rule === 'new' ? await post<{ pending?: Pending }>('/net/firewall/rule', body) : await put<{ pending?: Pending }>(`/net/firewall/rule/${rule.section}`, body); setRule(null); return r })} />}
      {dialog}
    </div>
  )
}

function ruleSummary(r: Rule) {
  const parts: string[] = []
  const zone = (z: string) => (z === '*' ? '任何区域' : z)
  parts.push(r.dest ? `${r.src ? zone(r.src) : '路由器'} → ${zone(r.dest)}` : `${r.src ? zone(r.src) : '路由器发出'} → 路由器`)
  if (r.proto?.length) parts.push(r.proto.join('/').toUpperCase())
  if (r.src_ip?.length) parts.push('来自 ' + r.src_ip.join(' '))
  if (r.src_mac?.length) parts.push('MAC ' + r.src_mac.join(' '))
  if (r.dest_ip?.length) parts.push('去往 ' + r.dest_ip.join(' '))
  if (r.dest_port) parts.push('端口 ' + r.dest_port)
  if (r.icmp_type?.length) parts.push('ICMP ' + r.icmp_type.join(' '))
  if (r.family === 'ipv4' || r.family === 'ipv6') parts.push(r.family === 'ipv4' ? '仅 IPv4' : '仅 IPv6')
  if (r.ipset) parts.push('IP 集合 ' + r.ipset)
  return parts.join(' · ')
}

function AddForward({ zones, onAdd }: { zones: string[]; onAdd: (z: string) => void }) {
  if (!zones.length) return null
  return (
    <select className="h-6 rounded-full border bg-background px-2 text-xs" value="" onChange={(e) => e.target.value && onAdd(e.target.value)}>
      <option value="">+ 允许访问…</option>
      {zones.map((z) => <option key={z} value={z}>{z}</option>)}
    </select>
  )
}

function PolicySelect({ value, onChange, disabled }: { value: string; onChange: (v: string) => void; disabled?: boolean }) {
  return (
    <select className="h-9 rounded-md border bg-background px-2 text-sm" value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}>
      {['ACCEPT', 'REJECT', 'DROP'].map((p) => <option key={p} value={p}>{policyLabel[p]}（{p}）</option>)}
    </select>
  )
}

function Defaults({ d, manage, onSave }: { d: NonNullable<FwResp['defaults']>; manage: boolean; onSave: (v: unknown) => void }) {
  const [v, setV] = useState(d)
  const dirty = JSON.stringify(v) !== JSON.stringify(d)
  return (
    <Section title="默认策略" desc="没有被任何区域或规则匹配到的流量怎么处理。">
      <div className="grid gap-3 p-4 md:grid-cols-3">
        <Field label="进入路由器"><PolicySelect value={v.input} disabled={!manage} onChange={(x) => setV({ ...v, input: x })} /></Field>
        <Field label="路由器发出"><PolicySelect value={v.output} disabled={!manage} onChange={(x) => setV({ ...v, output: x })} /></Field>
        <Field label="经过路由器转发"><PolicySelect value={v.forward} disabled={!manage} onChange={(x) => setV({ ...v, forward: x })} /></Field>
        <label className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm">防 SYN 洪水攻击<Switch checked={v.syn_flood} disabled={!manage} onCheckedChange={(c) => setV({ ...v, syn_flood: !!c })} /></label>
        <label className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm">丢弃无效数据包<Switch checked={v.drop_invalid} disabled={!manage} onCheckedChange={(c) => setV({ ...v, drop_invalid: !!c })} /></label>
        <label className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm">
          <span>软件流量分载<span className="block text-xs text-muted-foreground">提升转发速度；开启后 Wharf 的实时网速可能偏低</span></span>
          <Switch checked={v.flow_offloading} disabled={!manage} onCheckedChange={(c) => setV({ ...v, flow_offloading: !!c, flow_offloading_hw: c ? v.flow_offloading_hw : false })} />
        </label>
      </div>
      {manage && dirty && (
        <div className="flex justify-end gap-2 border-t px-4 py-2">
          <Button variant="outline" size="sm" onClick={() => setV(d)}>还原</Button>
          <Button size="sm" onClick={() => onSave(v)}>保存并应用</Button>
        </div>
      )}
    </Section>
  )
}

function ZoneEditor({ zone, ifaces, onClose, onSave }: { zone: Zone | null; ifaces: string[]; onClose: () => void; onSave: (b: unknown) => Promise<void> }) {
  const [v, setV] = useState({ name: zone?.name ?? '', network: zone?.network ?? [], input: zone?.input || 'REJECT', output: zone?.output || 'ACCEPT', forward: zone?.forward || 'REJECT', masq: zone?.masq ?? false, mtu_fix: zone?.mtu_fix ?? false })
  const [busy, setBusy] = useState(false)
  const fixed = zone?.name === 'lan' || zone?.name === 'wan'
  return (
    <HalfPanel open onOpenChange={(o) => { if (!o) onClose() }} title={zone ? `区域 ${zone.name}` : '新增区域'}
      footer={<><Button variant="outline" onClick={onClose}>取消</Button><Button disabled={busy || !v.name} onClick={async () => { setBusy(true); await onSave(v); setBusy(false) }}>{busy && <Loader2 className="animate-spin" />} 保存并应用</Button></>}>
      <div className="grid gap-4">
        <Field label="区域名" hint={fixed ? 'lan / wan 区域不能改名' : '字母开头，最多 11 个字符'}><Input value={v.name} disabled={fixed} onChange={(e) => setV({ ...v, name: e.target.value })} className="font-mono" /></Field>
        <Field label="包含的接口" hint="一个接口只能在一个区域里，选到这里会从别的区域移出">
          <div className="flex flex-wrap gap-x-4 gap-y-2">
            {ifaces.map((i) => (
              <label key={i} className="flex items-center gap-1.5 text-sm">
                <Checkbox checked={v.network.includes(i)} onCheckedChange={(c) => setV({ ...v, network: c ? [...v.network, i] : v.network.filter((x) => x !== i) })} />{i}
              </label>
            ))}
          </div>
        </Field>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="访问路由器"><PolicySelect value={v.input} onChange={(x) => setV({ ...v, input: x })} /></Field>
          <Field label="路由器外出"><PolicySelect value={v.output} onChange={(x) => setV({ ...v, output: x })} /></Field>
          <Field label="区内转发"><PolicySelect value={v.forward} onChange={(x) => setV({ ...v, forward: x })} /></Field>
        </div>
        <label className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm">
          <span>地址伪装（NAT）<span className="block text-xs text-muted-foreground">外网区域要开，内网设备才能共用一个公网地址上网</span></span>
          <Switch checked={v.masq} onCheckedChange={(c) => setV({ ...v, masq: !!c })} />
        </label>
        <label className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm">
          <span>MSS 钳制<span className="block text-xs text-muted-foreground">PPPoE 等 MTU 较小的线路建议开启，避免部分网站打不开</span></span>
          <Switch checked={v.mtu_fix} onCheckedChange={(c) => setV({ ...v, mtu_fix: !!c })} />
        </label>
      </div>
    </HalfPanel>
  )
}

function RuleEditor({ rule, zones, onClose, onSave }: { rule: Rule | null; zones: string[]; onClose: () => void; onSave: (b: unknown) => Promise<void> }) {
  const [v, setV] = useState({
    name: rule?.name ?? '', src: rule?.src ?? 'wan', dest: rule?.dest ?? '', proto: rule?.proto ?? ['tcp', 'udp'], src_ip: (rule?.src_ip ?? []).join(' '), dest_ip: (rule?.dest_ip ?? []).join(' '),
    src_port: rule?.src_port ?? '', dest_port: rule?.dest_port ?? '', target: rule?.target ?? 'ACCEPT', family: rule?.family || 'any', icmp_type: (rule?.icmp_type ?? []).join(' '),
  })
  const [busy, setBusy] = useState(false)
  const toggleProto = (p: string, on: boolean) => setV({ ...v, proto: on ? [...v.proto.filter((x) => x !== 'all'), p] : v.proto.filter((x) => x !== p) })
  const save = async () => {
    setBusy(true)
    await onSave({ ...v, src_ip: v.src_ip.split(/[\s,，]+/).filter(Boolean), dest_ip: v.dest_ip.split(/[\s,，]+/).filter(Boolean), icmp_type: v.icmp_type.split(/\s+/).filter(Boolean), enabled: rule?.enabled ?? true })
    setBusy(false)
  }
  return (
    <HalfPanel open onOpenChange={(o) => { if (!o) onClose() }} title={rule ? `规则「${rule.name}」` : '新增通信规则'}
      desc="例：允许外网访问路由器的 51820/udp（WireGuard）：来源 wan、目标「路由器本身」、UDP、端口 51820、允许。"
      footer={<><Button variant="outline" onClick={onClose}>取消</Button><Button disabled={busy || !v.name} onClick={save}>{busy && <Loader2 className="animate-spin" />} 保存并应用</Button></>}>
      <div className="grid gap-4">
        <Field label="名称"><Input value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} /></Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="来源区域">
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={v.src} onChange={(e) => setV({ ...v, src: e.target.value })}>
              <option value="">路由器自己发出</option><option value="*">任何区域</option>{zones.map((z) => <option key={z} value={z}>{z}</option>)}
            </select>
          </Field>
          <Field label="目标">
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={v.dest} onChange={(e) => setV({ ...v, dest: e.target.value })}>
              <option value="">路由器本身</option><option value="*">任何区域（转发）</option>{zones.map((z) => <option key={z} value={z}>{z} 区的设备</option>)}
            </select>
          </Field>
        </div>
        <Field label="协议">
          <div className="flex flex-wrap gap-x-4 gap-y-1.5">
            {['tcp', 'udp', 'icmp', 'all'].map((p) => (
              <label key={p} className="flex items-center gap-1.5 text-sm"><Checkbox checked={v.proto.includes(p)} onCheckedChange={(c) => p === 'all' ? setV({ ...v, proto: c ? ['all'] : [] }) : toggleProto(p, !!c)} />{p === 'all' ? '全部' : p.toUpperCase()}</label>
            ))}
          </div>
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="来源 IP / 网段" hint="可多个，空格分隔；! 开头表示排除"><Input value={v.src_ip} onChange={(e) => setV({ ...v, src_ip: e.target.value })} className="font-mono" placeholder="任何" /></Field>
          <Field label="目标 IP / 网段"><Input value={v.dest_ip} onChange={(e) => setV({ ...v, dest_ip: e.target.value })} className="font-mono" placeholder="任何" /></Field>
          <Field label="目标端口" hint="80、8000-8080 或 80 443"><Input value={v.dest_port} onChange={(e) => setV({ ...v, dest_port: e.target.value })} className="font-mono" placeholder="任何" /></Field>
          <Field label="来源端口"><Input value={v.src_port} onChange={(e) => setV({ ...v, src_port: e.target.value })} className="font-mono" placeholder="任何" /></Field>
        </div>
        {v.proto.includes('icmp') && <Field label="ICMP 类型（可不填）"><Input value={v.icmp_type} onChange={(e) => setV({ ...v, icmp_type: e.target.value })} className="font-mono" placeholder="echo-request" /></Field>}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="动作">
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={v.target} onChange={(e) => setV({ ...v, target: e.target.value })}>
              <option value="ACCEPT">允许</option><option value="REJECT">拒绝（告诉对方）</option><option value="DROP">丢弃（不回应）</option>
            </select>
          </Field>
          <Field label="IP 版本">
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={v.family} onChange={(e) => setV({ ...v, family: e.target.value })}>
              <option value="any">IPv4 和 IPv6</option><option value="ipv4">仅 IPv4</option><option value="ipv6">仅 IPv6</option>
            </select>
          </Field>
        </div>
      </div>
    </HalfPanel>
  )
}
