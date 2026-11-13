import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import {
  AlertTriangle, ArrowDownToLine, ArrowUpFromLine, Cable, CheckCircle2, CircleSlash, Copy, Globe, Loader2, Network, Pencil, Plus, Power,
  RefreshCw, Stethoscope, Trash2, XCircle,
} from 'lucide-react'
import { del, post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { bytes, datetime, duration } from '@/lib/format'
import { netChanged, protoLabel, roleLabel, type IfaceStat, type NetLink, type Pending, type WanDiag } from '@/lib/netcfg'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { PublicIPCard } from '@/components/public-ip'
import { Dot, Empty, ErrorBox, Field, HalfPanel, Pill, Section, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

interface NetResp {
  interfaces: IfaceStat[]; devices: NetLink[]; pending: Pending | null; firewall: string; protos: string[]; zones: string[]
  outages: { from: number; to: number; kind: string; note: string }[] | null
  mwan3?: { interfaces?: Record<string, { status: string; enabled: boolean; online: number; offline: number; uptime: number; track_ip?: { ip: string; status: string }[] }> } | null
  health?: { internet: boolean; checked: boolean; down_since: number; gateway_ok: boolean } | null
}

const mwanLabel: Record<string, [string, 'green' | 'red' | 'amber' | 'muted']> = {
  online: ['多线：在线', 'green'], offline: ['多线：离线', 'red'], disabled: ['多线：未启用', 'muted'], notracking: ['多线：未检测', 'muted'], connecting: ['多线：连接中', 'amber'], disconnecting: ['多线：断开中', 'amber'],
}

export default function Interfaces() {
  const { can } = useAuth()
  const manage = can('network.manage')
  const { data, error, reload } = useApi<NetResp>('/net/interfaces', 15000)
  const [q, setQ] = useSearchParams()
  const [diag, setDiag] = useState<WanDiag | null>(null)
  const [diagBusy, setDiagBusy] = useState(false)
  const [edit, setEdit] = useState<IfaceStat | 'new' | null>(null)
  const { confirm, dialog } = useConfirm()

  const runDiag = async (iface = 'wan') => {
    setDiagBusy(true)
    try { setDiag(await post<WanDiag>('/net/diagnose', { iface })) } catch (e) { toast.error((e as Error).message) } finally { setDiagBusy(false) }
  }
  useEffect(() => {
    if (q.get('diagnose')) { runDiag(); q.delete('diagnose'); setQ(q, { replace: true }) }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { const f = () => reload(); window.addEventListener('owp:net-confirmed', f); return () => window.removeEventListener('owp:net-confirmed', f) }, [reload])

  const devs = useMemo(() => Object.fromEntries((data?.devices ?? []).map((d) => [d.name, d])), [data])
  const wan = data?.interfaces.find((i) => i.role === 'wan' && i.up) ?? data?.interfaces.find((i) => i.role === 'wan')
  const wan6 = data?.interfaces.find((i) => i.role === 'wan6')
  const online = data?.health?.checked ? data.health.internet : wan?.up

  const action = async (i: IfaceStat, act: 'restart' | 'up' | 'down') => {
    const lan = i.role === 'lan'
    const text = {
      restart: lan ? `重启 ${i.name.toUpperCase()} 时，局域网里的所有设备（包括你现在用的这台）会断开几秒。` : `${i.name.toUpperCase()} 会断开几秒再重新连接，期间家里上不了网。`,
      down: lan ? '停止 LAN 后局域网会完全断开，你将无法再打开这个面板，只能接显示器或重启路由器恢复。' : `停止后 ${i.name.toUpperCase()} 不再联网，直到你再次启动。`,
      up: '',
    }[act]
    if (act !== 'up' && !(await confirm(`${{ restart: '重启', down: '停止', up: '启动' }[act]}接口 ${i.name.toUpperCase()}？`, text, { danger: act === 'down', ok: { restart: '重启', down: '停止', up: '启动' }[act] }))) return
    try {
      await post(`/net/interfaces/${i.name}/action`, { action: act })
      toast.success(act === 'restart' ? '正在重启接口，几秒后恢复' : act === 'down' ? '接口已停止' : '接口正在启动')
      setTimeout(reload, 4000)
    } catch (e) { toast.error((e as Error).message) }
  }
  const remove = async (i: IfaceStat) => {
    if (!(await confirm(`删除接口 ${i.name.toUpperCase()}？`, '它的地址池和防火墙区域里的这一项会一起删除。改动生效后要在倒计时内确认，否则自动恢复。', { danger: true, ok: '删除' }))) return
    try { await del(`/net/interfaces/${i.name}`); toast.success('已删除，请确认'); netChanged(); reload() } catch (e) { toast.error((e as Error).message) }
  }

  return (
    <div className="grid gap-4">
      <PageHeader title="网络接口" desc="家里的宽带、局域网和每个网口：是否联网、地址是什么、出了问题在哪一段。">
        <Button variant="outline" size="sm" onClick={() => runDiag()} disabled={diagBusy}>{diagBusy ? <Loader2 className="animate-spin" /> : <Stethoscope />} 诊断网络</Button>
        {manage && <Button size="sm" onClick={() => setEdit('new')}><Plus /> 新增接口</Button>}
      </PageHeader>
      {error && <ErrorBox>{error}</ErrorBox>}

      {data && (
        <section className={cn('grid gap-4 rounded-2xl border p-4 sm:p-5 lg:grid-cols-[1.1fr_1fr]', online ? 'bg-card' : 'border-destructive/40 bg-destructive/5')}>
          <div className="flex items-start gap-4">
            <span className={cn('grid size-12 shrink-0 place-items-center rounded-2xl', online ? 'bg-success/12 text-success' : 'bg-destructive/12 text-destructive')}>
              {online ? <Globe className="size-6" /> : <CircleSlash className="size-6" />}
            </span>
            <div className="grid min-w-0 gap-1">
              <div className="text-lg font-semibold">{online ? '已联网' : '外网断了'}</div>
              <div className="text-sm text-muted-foreground">
                {online ? (wan?.uptime ? `宽带已连续在线 ${duration(wan.uptime)}` : '') : data.health?.down_since ? `已断开 ${duration(Math.max(0, Math.round(Date.now() / 1000 - data.health.down_since)))}，点「诊断网络」找原因` : '点「诊断网络」找原因'}
              </div>
              {wan?.public?.ip && (
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <span className="text-xs text-muted-foreground">公网 IP</span>
                  <button className="group flex items-center gap-1 font-mono text-base font-semibold" onClick={() => { navigator.clipboard?.writeText(wan.public!.ip); toast.success('已复制') }}>
                    {wan.public.ip}<Copy className="size-3.5 opacity-0 group-hover:opacity-60" />
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-3">
            <Kv k="上网方式">{wan ? protoLabel(wan.proto) : '—'}</Kv>
            <Kv k="WAN 地址">{wan?.ipv4?.[0] ?? '—'}</Kv>
            <Kv k="网关">{wan?.gateway ?? '—'}</Kv>
            <Kv k="DNS">{wan?.dns?.join('、') || '—'}</Kv>
            <Kv k="IPv6">{wan6?.up ? (wan6.ipv6?.[0] ?? wan6.prefix6?.[0] ?? '已连接') : wan6 ? (wan6.autostart ? '未连接' : '已关闭') : '未配置'}</Kv>
            <Kv k="防火墙">{data.firewall === 'fw4' ? 'fw4（nftables）' : 'fw3（iptables）'}</Kv>
          </div>
        </section>
      )}

      {wan && <PublicIPCard iface={wan.name} />}

      {diag && <DiagCard d={diag} onClose={() => setDiag(null)} onRerun={() => runDiag(diag.iface)} busy={diagBusy} />}

      <div className="grid gap-4 xl:grid-cols-2">
        {data?.interfaces.map((i) => (
          <IfaceCard key={i.name} i={i} devs={devs} mwan={data.mwan3?.interfaces?.[i.name]} manage={manage}
            onEdit={() => setEdit(i)} onAction={(a) => action(i, a)} onDelete={() => remove(i)} />
        ))}
      </div>

      {data && <Ports devices={data.devices} />}

      {data && (
        <Section title="断网记录" desc="最近 30 天 WAN 断开 / 重新拨号的记录。整段时间的网络质量见「网络」页。" action={<Button variant="ghost" size="sm" render={<Link to="/network" />}>网络质量</Button>}>
          <div className="divide-y">
            {(data.outages ?? []).map((o, idx) => (
              <div key={idx} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-sm">
                {o.kind === 'reconnect' ? <RefreshCw className="size-4 text-warning" /> : <XCircle className="size-4 text-destructive" />}
                <span className="tabular-nums">{datetime(o.from)}</span>
                <span className="text-muted-foreground">{o.kind === 'reconnect' ? '重新拨号 / 换了地址' : o.to ? `断开 ${duration(o.to - o.from)}` : '仍在断开'}</span>
                <span className="text-xs text-muted-foreground">{o.note}</span>
              </div>
            ))}
            {!data.outages?.length && <Empty>最近 30 天没有断网</Empty>}
          </div>
        </Section>
      )}

      {edit && data && <IfaceEditor iface={edit === 'new' ? null : edit} data={data} onClose={() => setEdit(null)} onSaved={() => { setEdit(null); netChanged(); reload() }} />}
      {dialog}
    </div>
  )
}

function Kv({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg bg-muted/40 px-3 py-2">
      <div className="text-[11px] text-muted-foreground">{k}</div>
      <div className="truncate font-medium" title={typeof children === 'string' ? children : undefined}>{children}</div>
    </div>
  )
}

function DiagCard({ d, onClose, onRerun, busy }: { d: WanDiag; onClose: () => void; onRerun: () => void; busy: boolean }) {
  const ok = d.who === 'ok'
  const whoLabel: Record<string, string> = { ok: '一切正常', home: '问题在家里这一侧', account: '账号问题', isp: '运营商的问题', dns: '家里的 DNS 设置', web: '代理或拦截' }
  return (
    <section className={cn('grid gap-3 rounded-2xl border p-4', ok ? 'border-success/40 bg-success/5' : 'border-warning/50 bg-warning/8')}>
      <div className="flex flex-wrap items-start gap-3">
        {ok ? <CheckCircle2 className="mt-0.5 size-5 text-success" /> : <AlertTriangle className="mt-0.5 size-5 text-warning" />}
        <div className="min-w-0 flex-1">
          <div className="font-semibold">{d.verdict}</div>
          {d.advice && <p className="mt-0.5 text-sm text-muted-foreground">{d.advice}</p>}
        </div>
        <Pill tone={ok ? 'green' : d.who === 'isp' ? 'red' : 'amber'}>{whoLabel[d.who] ?? d.who}</Pill>
        <Button variant="ghost" size="sm" onClick={onRerun} disabled={busy}>{busy ? <Loader2 className="animate-spin" /> : <RefreshCw />} 再查一次</Button>
        <Button variant="ghost" size="sm" onClick={onClose}>收起</Button>
      </div>
      <ol className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
        {d.steps.map((s, idx) => (
          <li key={s.id} className="flex items-start gap-2 rounded-lg border bg-card px-3 py-2 text-sm">
            <span className={cn('mt-0.5 grid size-5 shrink-0 place-items-center rounded-full text-[11px] font-semibold text-white',
              { ok: 'bg-success', warn: 'bg-warning', fail: 'bg-destructive', skip: 'bg-muted-foreground/40' }[s.status])}>{idx + 1}</span>
            <span className="min-w-0">
              <span className="font-medium">{s.label}</span>
              <span className="block text-xs text-muted-foreground">{s.detail}</span>
            </span>
          </li>
        ))}
      </ol>
      <p className="text-xs text-muted-foreground">检查顺序：网线 → 拿地址 → 运营商网关 → 外网 → 域名解析 → 打开网页。第一个不通的环节就是问题所在。{datetime(d.at)}</p>
    </section>
  )
}

function IfaceCard({ i, devs, mwan, manage, onEdit, onAction, onDelete }: {
  i: IfaceStat; devs: Record<string, NetLink>; mwan?: { status: string; enabled: boolean }; manage: boolean
  onEdit: () => void; onAction: (a: 'restart' | 'up' | 'down') => void; onDelete: () => void
}) {
  const devName = (i.l3_device || i.device || '').replace(/^@/, '')
  const dev = devs[i.device] ?? devs[devName]
  const phys = dev?.type === 'bridge' ? (dev.members ?? []).map((m) => devs[m]).filter(Boolean) : dev ? [dev] : []
  const noLink = phys.length > 0 && phys.every((p) => !p.carrier)
  const state: [string, 'ok' | 'warn' | 'bad' | 'off'] = !i.autostart && !i.up ? ['已停用', 'off'] : i.up ? ['已连接', 'ok'] : i.pending ? ['正在连接', 'warn'] : noLink ? ['网线未连接', 'bad'] : ['未连接', 'bad']
  const accent = { lan: 'from-emerald-500/15', wan: 'from-sky-500/15', wan6: 'from-violet-500/15', other: 'from-muted' }[i.role]
  const mw = mwan ? mwanLabel[mwan.status] : undefined
  return (
    <section className="overflow-hidden rounded-xl border bg-card">
      <div className={cn('flex flex-wrap items-center gap-2 bg-gradient-to-r to-transparent px-4 py-3', accent)}>
        <span className="grid size-9 place-items-center rounded-lg bg-background/80"><Network className="size-4" /></span>
        <div className="min-w-0">
          <div className="flex items-center gap-2 font-semibold">{i.name.toUpperCase()}<Pill tone={i.role === 'wan' || i.role === 'wan6' ? 'blue' : i.role === 'lan' ? 'green' : 'muted'}>{roleLabel[i.role]}</Pill></div>
          <div className="text-xs text-muted-foreground">{protoLabel(i.proto)}{i.zones?.length ? ` · 防火墙区域 ${i.zones.join('、')}` : ' · 不在任何防火墙区域'}</div>
        </div>
        <span className="flex-1" />
        <span className="flex items-center gap-1.5 text-sm"><Dot tone={state[1]} />{state[0]}</span>
      </div>
      <div className="grid gap-x-6 gap-y-1.5 px-4 py-3 text-sm sm:grid-cols-2">
        <Row k="IPv4">{i.ipv4?.length ? i.ipv4.join('、') : '—'}</Row>
        {i.public?.ip && <Row k="公网 IP">{i.public.ip}{i.public.kind !== 'direct' && <span className="text-xs text-muted-foreground">（{i.public.kind === 'cgnat' ? '运营商大内网' : '经上级设备'}）</span>}</Row>}
        {i.gateway && <Row k="网关">{i.gateway}</Row>}
        {(i.ipv6?.length || i.prefix6?.length) ? <Row k="IPv6">{[...(i.ipv6 ?? []), ...(i.prefix6 ?? []).map((p) => p + '（前缀）')].join('、')}</Row> : null}
        {i.dns?.length ? <Row k="DNS">{i.dns.join('、')}</Row> : null}
        {i.up && <Row k="在线">{duration(i.uptime)}</Row>}
        <Row k="网口">
          <span className="font-mono">{i.device || '—'}</span>
          {dev && dev.type === 'bridge' && <span className="text-xs text-muted-foreground"> 桥接 {(dev.members ?? []).join(' ')}</span>}
        </Row>
        {phys.length > 0 && (
          <Row k="链路">
            {phys.map((p) => (
              <span key={p.name} className="mr-2 inline-flex items-center gap-1"><Dot tone={p.carrier ? 'ok' : 'bad'} />{p.name} {p.carrier ? (p.speed ? `${p.speed >= 1000 ? p.speed / 1000 + 'G' : p.speed + 'M'}${p.duplex === 'half' ? ' 半双工' : ''}` : '已连接') : '未插网线'}</span>
            ))}
          </Row>
        )}
        {dev && <Row k="流量"><ArrowDownToLine className="inline size-3 text-muted-foreground" /> {bytes(dev.rx)} <ArrowUpFromLine className="ml-1 inline size-3 text-muted-foreground" /> {bytes(dev.tx)}</Row>}
        {dev?.mac && <Row k="MAC"><span className="font-mono">{dev.mac}</span></Row>}
      </div>
      {(i.errors?.length || mw) ? (
        <div className="flex flex-wrap gap-2 border-t px-4 py-2">
          {mw && <Pill tone={mw[1]}>{mw[0]}</Pill>}
          {i.errors?.map((e) => <Pill key={e} tone="red">{e}</Pill>)}
        </div>
      ) : null}
      {manage && (
        <div className="flex flex-wrap gap-1.5 border-t px-3 py-2">
          <Button variant="ghost" size="sm" onClick={onEdit}><Pencil /> 设置</Button>
          <Button variant="ghost" size="sm" onClick={() => onAction('restart')}><RefreshCw /> 重启</Button>
          {i.up ? <Button variant="ghost" size="sm" onClick={() => onAction('down')}><Power /> 停止</Button> : <Button variant="ghost" size="sm" onClick={() => onAction('up')}><Power /> 启动</Button>}
          {i.role !== 'lan' && <Button variant="ghost" size="sm" className="ml-auto text-destructive" onClick={onDelete}><Trash2 /> 删除</Button>}
        </div>
      )}
    </section>
  )
}

function Row({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 gap-2">
      <span className="w-12 shrink-0 text-xs leading-5 text-muted-foreground">{k}</span>
      <span className="min-w-0 break-all">{children}</span>
    </div>
  )
}

function Ports({ devices }: { devices: NetLink[] }) {
  const phys = devices.filter((d) => d.physical || d.type === 'wireless')
  if (!phys.length) return null
  return (
    <Section title="物理网口" desc="每个网口有没有插线、协商的速率和收发流量。">
      <div className="grid gap-2 p-4 sm:grid-cols-2 lg:grid-cols-4">
        {phys.map((d) => (
          <div key={d.name} className="flex items-center gap-3 rounded-xl border px-3 py-2.5">
            <span className={cn('grid size-9 shrink-0 place-items-center rounded-lg', d.carrier ? 'bg-success/12 text-success' : 'bg-muted text-muted-foreground')}><Cable className="size-4" /></span>
            <div className="min-w-0 text-sm">
              <div className="flex items-center gap-1.5 font-medium">{d.name}{d.bridge && <span className="text-xs font-normal text-muted-foreground">→ {d.bridge}</span>}</div>
              <div className="text-xs text-muted-foreground">
                {d.carrier ? (d.speed ? `${d.speed >= 1000 ? d.speed / 1000 + ' Gbps' : d.speed + ' Mbps'}${d.duplex === 'half' ? ' 半双工' : ''}` : '已连接') : '未插网线'}
                {d.driver ? ` · ${d.driver}` : ''}
              </div>
              <div className="text-xs text-muted-foreground">↓ {bytes(d.rx)} ↑ {bytes(d.tx)}{d.rx_errors + d.tx_errors > 0 ? ` · 错误 ${d.rx_errors + d.tx_errors}` : ''}</div>
            </div>
          </div>
        ))}
      </div>
    </Section>
  )
}

// ---- editor ----

const commonProtos = ['dhcp', 'static', 'pppoe', 'dhcpv6', 'none']

function IfaceEditor({ iface, data, onClose, onSaved }: { iface: IfaceStat | null; data: NetResp; onClose: () => void; onSaved: () => void }) {
  const cfg = (iface?.config ?? {}) as Record<string, unknown>
  const s = (k: string) => (cfg[k] == null ? '' : Array.isArray(cfg[k]) ? (cfg[k] as string[]).join(' ') : String(cfg[k]))
  const [name, setName] = useState('')
  const [v, setV] = useState<Record<string, string>>(() => ({
    proto: s('proto') || 'dhcp', device: s('device') || s('ifname'), ipaddr: s('ipaddr'), netmask: s('netmask') || '255.255.255.0', gateway: s('gateway'),
    username: s('username'), password: cfg.password ? '\u0000set' : '', mtu: s('mtu'), metric: s('metric'), dns: s('dns'), peerdns: s('peerdns') || '1',
    macaddr: s('macaddr'), auto: s('auto') || '1', hostname: s('hostname'), reqaddress: s('reqaddress') || 'try', reqprefix: s('reqprefix') || 'auto', service: s('service'),
  }))
  const [zone, setZone] = useState(iface ? (iface.zones?.[0] ?? '') : 'wan')
  const [busy, setBusy] = useState(false)
  const set = (k: string, x: string) => setV((c) => ({ ...c, [k]: x }))
  const protos = [...new Set([...commonProtos.filter((p) => data.protos.includes(p) || p === 'static' || p === 'none'), ...data.protos.filter((p) => !commonProtos.includes(p))])]
  const devices = data.devices.filter((d) => d.type !== 'tunnel').map((d) => d.name)
  const isLan = iface?.role === 'lan'
  const ipChanged = iface && v.proto === 'static' && v.ipaddr !== s('ipaddr')

  const save = async () => {
    setBusy(true)
    const fields: Record<string, string[]> = {
      static: ['ipaddr', 'netmask', 'gateway'], dhcp: ['hostname'], pppoe: ['username', 'password', 'service'], dhcpv6: ['reqaddress', 'reqprefix'], none: [],
    }
    const values: Record<string, unknown> = { proto: v.proto, device: v.device.split(/\s+/).filter(Boolean), auto: v.auto, mtu: v.mtu, metric: v.metric, macaddr: v.macaddr }
    for (const k of fields[v.proto] ?? []) values[k] = v[k]
    if (v.proto !== 'static' && v.proto !== 'none') {
      values.peerdns = v.peerdns
      values.dns = v.peerdns === '0' ? v.dns.split(/[\s,，]+/).filter(Boolean) : []
    } else values.dns = v.dns.split(/[\s,，]+/).filter(Boolean)
    if ((values.device as string[]).length === 1) values.device = (values.device as string[])[0]
    try {
      const body = { name: name.trim(), values, zone }
      const r = iface ? await put<{ pending?: Pending }>(`/net/interfaces/${iface.name}`, body) : await post<{ pending?: Pending }>('/net/interfaces', body)
      if (r.pending) toast.success('已生效。确认网络正常后，在顶部点「一切正常，保留」', { duration: 8000 })
      else toast.success('没有改动')
      onSaved()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }

  return (
    <HalfPanel open onOpenChange={(o) => { if (!o) onClose() }} title={iface ? `接口 ${iface.name.toUpperCase()} 的设置` : '新增接口'}
      desc="保存后立刻生效；在倒计时内确认才会保留，否则路由器自动恢复原来的设置，不怕把自己关在外面。"
      footer={<><Button variant="outline" onClick={onClose}>取消</Button><Button disabled={busy || (!iface && !name.trim())} onClick={save}>{busy && <Loader2 className="animate-spin" />} 保存并应用</Button></>}>
      <div className="grid gap-4">
        {!iface && (
          <Field label="接口名" hint="小写字母开头，如 wan2、lan2、iot。新的宽带一般叫 wan2。"><Input value={name} onChange={(e) => setName(e.target.value.toLowerCase())} placeholder="wan2" className="font-mono" /></Field>
        )}
        <Field label="上网方式 / 协议">
          <div className="flex flex-wrap gap-1.5">
            {protos.map((p) => (
              <button key={p} type="button" onClick={() => set('proto', p)}
                className={cn('rounded-lg border px-3 py-1.5 text-sm', v.proto === p ? 'border-primary bg-accent font-medium text-accent-foreground' : 'hover:bg-muted')}>{protoLabel(p)}</button>
            ))}
          </div>
        </Field>
        {iface && v.proto !== s('proto') && <p className="rounded-lg bg-warning/12 px-3 py-2 text-xs">换协议会清掉旧协议专用的设置（例如从静态改成 DHCP 会去掉固定地址）。</p>}

        {v.proto === 'static' && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="IP 地址"><Input value={v.ipaddr} onChange={(e) => set('ipaddr', e.target.value)} placeholder="192.168.1.1" className="font-mono" /></Field>
            <Field label="子网掩码"><Input value={v.netmask} onChange={(e) => set('netmask', e.target.value)} className="font-mono" /></Field>
            {!isLan && <Field label="网关"><Input value={v.gateway} onChange={(e) => set('gateway', e.target.value)} placeholder="上级路由器的地址" className="font-mono" /></Field>}
            <Field label="DNS 服务器" hint="空格分隔，可不填"><Input value={v.dns} onChange={(e) => set('dns', e.target.value)} className="font-mono" /></Field>
          </div>
        )}
        {ipChanged && isLan && (
          <p className="rounded-lg border border-warning/40 bg-warning/10 px-3 py-2 text-sm">
            LAN 地址改成 <b className="font-mono">{v.ipaddr}</b> 后，面板要用新地址打开（例如 https://{v.ipaddr}:{location.port || '443'}），登录后在顶部确认。4 分钟内没确认会自动改回来。家里设备要重新获取地址（重连 Wi-Fi 或拔插网线）。
          </p>
        )}
        {v.proto === 'pppoe' && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="宽带账号"><Input value={v.username} onChange={(e) => set('username', e.target.value)} autoComplete="off" /></Field>
            <Field label="宽带密码" hint={v.password === '\u0000set' ? '已设置，留空不改' : undefined}>
              <Input type="password" autoComplete="new-password" value={v.password === '\u0000set' ? '' : v.password} placeholder={v.password === '\u0000set' ? '••••••' : ''} onChange={(e) => set('password', e.target.value || (cfg.password ? '\u0000set' : ''))} />
            </Field>
            <Field label="服务名（可不填）"><Input value={v.service} onChange={(e) => set('service', e.target.value)} /></Field>
          </div>
        )}
        {v.proto === 'dhcp' && <Field label="向上级报告的主机名（可不填）"><Input value={v.hostname} onChange={(e) => set('hostname', e.target.value)} /></Field>}
        {v.proto === 'dhcpv6' && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="请求 IPv6 地址">
              <select className="h-9 rounded-md border bg-background px-2 text-sm" value={v.reqaddress} onChange={(e) => set('reqaddress', e.target.value)}>
                <option value="try">尝试获取</option><option value="force">必须获取</option><option value="none">不要</option>
              </select>
            </Field>
            <Field label="请求前缀长度">
              <select className="h-9 rounded-md border bg-background px-2 text-sm" value={v.reqprefix} onChange={(e) => set('reqprefix', e.target.value)}>
                <option value="auto">自动</option><option value="no">不要</option>{[48, 56, 60, 62, 64].map((n) => <option key={n} value={String(n)}>/{n}</option>)}
              </select>
            </Field>
          </div>
        )}
        {!['static', 'dhcp', 'pppoe', 'dhcpv6', 'none'].includes(v.proto) && (
          <p className="rounded-lg bg-muted/50 px-3 py-2 text-sm text-muted-foreground">{protoLabel(v.proto)} 的专用设置请在 LuCI 中填写；这里可以改网口、防火墙区域和下面的通用选项。</p>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="网口" hint="可以填多个（空格分隔）；LAN 通常是网桥 br-lan">
            <Input value={v.device} onChange={(e) => set('device', e.target.value)} list="owp-devs" className="font-mono" />
            <datalist id="owp-devs">{devices.map((d) => <option key={d} value={d} />)}</datalist>
          </Field>
          <Field label="防火墙区域" hint="外网接口放 wan，内网放 lan">
            <select className="h-9 rounded-md border bg-background px-2 text-sm" value={zone} onChange={(e) => setZone(e.target.value)}>
              <option value="">不放进任何区域</option>
              {data.zones.map((z) => <option key={z} value={z}>{z}</option>)}
            </select>
          </Field>
        </div>

        {v.proto !== 'static' && v.proto !== 'none' && (
          <div className="grid gap-2 rounded-lg border p-3">
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>使用运营商下发的 DNS<span className="block text-xs text-muted-foreground">关闭后用下面自己填的 DNS</span></span>
              <Switch checked={v.peerdns !== '0'} onCheckedChange={(c) => set('peerdns', c ? '1' : '0')} />
            </label>
            {v.peerdns === '0' && <Input value={v.dns} onChange={(e) => set('dns', e.target.value)} placeholder="223.5.5.5 1.1.1.1" className="font-mono" />}
          </div>
        )}

        <details className="rounded-lg border px-3 py-2">
          <summary className="cursor-pointer text-sm font-medium">高级选项</summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <Field label="MTU" hint="留空用默认（1500；PPPoE 一般 1492）"><Input value={v.mtu} onChange={(e) => set('mtu', e.target.value)} className="font-mono" /></Field>
            <Field label="路由优先级 metric" hint="多条宽带时，数字小的优先"><Input value={v.metric} onChange={(e) => set('metric', e.target.value)} className="font-mono" /></Field>
            <Field label="克隆 MAC 地址" hint="有的运营商绑定了旧路由器的 MAC"><Input value={v.macaddr} onChange={(e) => set('macaddr', e.target.value)} placeholder="AA:BB:CC:DD:EE:FF" className="font-mono" /></Field>
            <label className="flex items-center justify-between gap-3 self-end rounded-lg border px-3 py-2 text-sm">开机自动连接<Switch checked={v.auto !== '0'} onCheckedChange={(c) => set('auto', c ? '1' : '0')} /></label>
          </div>
        </details>
      </div>
    </HalfPanel>
  )
}
