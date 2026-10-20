import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { ArrowRight, BarChart3, Globe2, Plus, Search, ShieldBan, ShieldCheck } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { runAction } from '@/lib/actions'
import type { Forward, ForwardTarget, PortsInfo, RegionInfo } from '@/lib/types'
import { cn } from '@/lib/utils'
import { grantLabel } from '@/components/grants'
import { PageHeader } from '@/components/layout'
import { Empty, ErrorBox, Field, HalfPanel, Pill, Section, useConfirm, VMTag } from '@/components/common'
import { DeviceSelect, IPListInput, RegionPicker, regionLabel } from '@/components/pickers'
import { ForwardStats, UsageCell, type FwdUsage } from '@/components/forward-stats'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

interface ListResp { items: Forward[]; quota: number; used: number }

const protoLabel = (p: string) => (p === 'tcp udp' ? 'TCP+UDP' : p.toUpperCase())

function SourceCell({ f, regions }: { f: Forward; regions?: RegionInfo[] | null }) {
  if (f.mode === 'restrict') {
    const items = [...f.regions.map((r) => regionLabel(r, regions)), ...f.allow]
    return (
      <span className="flex flex-wrap items-center gap-1">
        <Pill tone="green"><ShieldCheck className="size-3" />仅 {items.slice(0, 2).join('、')}{items.length > 2 ? ` 等 ${items.length} 项` : ''}</Pill>
        {f.deny.length > 0 && <Pill tone="red"><ShieldBan className="size-3" />黑名单 {f.deny.length}</Pill>}
      </span>
    )
  }
  return (
    <span className="flex flex-wrap items-center gap-1">
      <Pill tone="amber"><Globe2 className="size-3" />所有人</Pill>
      {f.deny.length > 0 && <Pill tone="red"><ShieldBan className="size-3" />黑名单 {f.deny.length}</Pill>}
    </span>
  )
}

export default function Forwards() {
  const { data, error, reload } = useApi<ListResp>('/forwards', 15000)
  const { data: regions } = useApi<RegionInfo[]>('/geo/regions')
  const { can, isSuper } = useAuth()
  const [sel, setSel] = useState<Forward | 'new' | null>(null)
  const [stats, setStats] = useState<Forward | null>(null)
  const { data: usage } = useApi<Record<string, FwdUsage>>('/forwards/usage?range=24h', 60000)
  const [q, setQ] = useState('')
  const [scope, setScope] = useState('all')
  const canManage = can('forwards.manage')

  const items = useMemo(() => {
    const s = q.trim().toLowerCase()
    return (data?.items ?? [])
      .filter((f) => scope === 'all' || (scope === 'owp' ? f.managed : !f.managed))
      .filter((f) => !s || [f.name, f.device_name, f.device_now, f.vm_tag, f.lan_ip, f.lan_port, f.wan_port, f.note, f.owner_name].some((x) => (x ?? '').toLowerCase().includes(s)))
  }, [data, q, scope])

  const toggle = async (f: Forward, on: boolean) => {
    try { await runAction('forward.toggle', { id: f.id, rev: f.rev, enabled: on }) } catch (e) { toast.error((e as Error).message) } finally { reload() }
  }
  const quota = data && data.quota >= 0 ? `已用 ${data.used} / ${data.quota} 条` : ''

  return (
    <>
      <PageHeader title="端口转发" desc={`将内网设备的端口映射到 WAN 口，可按地区 / IP 段限制来源。写入 OpenWrt 防火墙，并带有结构化备注。${quota ? ' · ' + quota : ''}`}>
        {canManage && <Button size="sm" onClick={() => setSel('new')} disabled={!!data && data.quota >= 0 && data.used >= data.quota}><Plus /> 新增转发</Button>}
      </PageHeader>
      {error && <div className="mb-4"><ErrorBox>{error}</ErrorBox></div>}
      <Section title="转发规则" action={
        <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
          {isSuper && (
            <Tabs value={scope} onValueChange={(v) => setScope(String(v))}>
              <TabsList><TabsTrigger value="all">全部</TabsTrigger><TabsTrigger value="owp">面板创建</TabsTrigger><TabsTrigger value="legacy">路由器原有</TabsTrigger></TabsList>
            </Tabs>
          )}
          <div className="relative min-w-40 flex-1 sm:flex-none">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="设备 / 端口 / 备注" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-full pl-8 sm:w-44" />
          </div>
        </div>
      }>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12 pl-4">启用</TableHead><TableHead>名称</TableHead><TableHead>WAN</TableHead><TableHead className="hidden sm:table-cell" /><TableHead className="hidden sm:table-cell">内网目标</TableHead>
              <TableHead className="hidden md:table-cell">来源</TableHead><TableHead>24h 用量</TableHead><TableHead className="hidden pr-4 lg:table-cell">创建者</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((f) => (
              <TableRow key={f.id} className="cursor-pointer" onClick={() => setSel(f)}>
                <TableCell className="pl-4" onClick={(e) => e.stopPropagation()}>
                  <Switch size="sm" checked={f.enabled} disabled={!f.editable} onCheckedChange={(c) => toggle(f, !!c)} />
                </TableCell>
                <TableCell className="w-full max-w-0 sm:w-auto sm:max-w-64">
                  <div className="flex min-w-0 items-center gap-1.5">
                    <span className="truncate font-medium">{f.managed ? f.device_now || f.device_name || f.lan_ip : f.name || f.id}</span>
                    <VMTag tag={f.vm_tag} />
                    {f.online === false && <span className="shrink-0 text-[11px] text-muted-foreground">离线</span>}
                  </div>
                  {/* router-made rules are named after the rule; show which device they point at */}
                  {!f.managed && f.device_now && <div className="truncate text-xs text-muted-foreground">→ {f.device_now}</div>}
                  {f.managed && f.note && <div className="truncate text-xs text-muted-foreground">{f.note}</div>}
                  <div className="truncate font-mono text-[11px] text-muted-foreground sm:hidden">→ {f.lan_ip}:{f.lan_port}</div>
                </TableCell>
                <TableCell className="whitespace-nowrap pr-4 font-mono text-xs sm:pr-2">{f.wan && <span className="text-muted-foreground">{f.wan}:</span>}{f.wan_port}<span className="ml-1 text-muted-foreground">{protoLabel(f.proto)}</span></TableCell>
                <TableCell className="hidden w-6 px-0 sm:table-cell"><ArrowRight className="size-3.5 text-muted-foreground" /></TableCell>
                <TableCell className="hidden whitespace-nowrap font-mono text-xs sm:table-cell">{f.lan_ip}:{f.lan_port}</TableCell>
                <TableCell className="hidden md:table-cell"><SourceCell f={f} regions={regions} /></TableCell>
                <TableCell className="whitespace-nowrap py-1"><UsageCell u={usage?.[f.id]} onOpen={() => setStats(f)} /></TableCell>
                <TableCell className="hidden pr-4 text-muted-foreground lg:table-cell">{f.owner_name || (f.managed ? '—' : '路由器原有')}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!items.length && <Empty>{data ? '暂无端口转发' : '加载中…'}</Empty>}
      </Section>
      <ForwardPanel target={sel} onClose={() => setSel(null)} onSaved={() => { setSel(null); reload() }} onStats={(f) => { setSel(null); setStats(f) }} />
      <ForwardStats f={stats} onClose={() => setStats(null)} />
    </>
  )
}

interface Form {
  lan_ip: string; device_mac: string; device_name: string; lan_port: string; wan_port: string; wan: string; proto: string
  note: string; enabled: boolean; mode: 'all' | 'restrict'; regions: string[]; allow: string[]; deny: string[]
}

const emptyForm: Form = { lan_ip: '', device_mac: '', device_name: '', lan_port: '', wan_port: '', wan: '', proto: 'tcp', note: '', enabled: true, mode: 'restrict', regions: ['NZ'], allow: [], deny: [] }

function ForwardPanel({ target, onClose, onSaved, onStats }: { target: Forward | 'new' | null; onClose: () => void; onSaved: () => void; onStats: (f: Forward) => void }) {
  const { user } = useAuth()
  const isNew = target === 'new'
  const f = isNew ? null : target
  const { data: targets } = useApi<ForwardTarget[]>(target && (isNew || f?.editable) ? '/forwards/targets' : null)
  const [form, setForm] = useState<Form>(emptyForm)
  const [loaded, setLoaded] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const [portOk, setPortOk] = useState<boolean | null>(null)
  const { confirm, dialog } = useConfirm()
  if (target && loaded !== target) {
    setLoaded(target)
    setPortOk(null)
    setForm(f ? {
      lan_ip: f.lan_ip, device_mac: f.device_mac, device_name: f.device_name, lan_port: f.lan_port, wan_port: f.wan_port, wan: f.wan ?? '',
      proto: f.proto, note: f.note, enabled: f.enabled, mode: f.mode, regions: f.regions, allow: f.allow, deny: f.deny,
    } : emptyForm)
  }
  const editable = isNew || !!f?.editable
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((x) => ({ ...x, [k]: v }))
  const pickDevice = (ip: string, d?: ForwardTarget) => {
    setForm((x) => ({ ...x, lan_ip: ip, device_mac: d?.mac ?? '', device_name: (d?.name ?? x.device_name).slice(0, 32) }))
  }
  const owner = f && f.owner_id ? { id: f.owner_id, name: f.owner_name } : { id: user?.id ?? 0, name: user?.username ?? '' }
  const preview = `OWP|uid=${owner.id}|user=${owner.name}|dev=${form.device_name}|${form.lan_ip || '?'}:${form.lan_port || '?'}>${form.wan || 'wan'}:${form.wan_port || '?'}/${form.proto.replace(' ', '+')}${form.note ? '|note=' + form.note : ''}`

  const save = async () => {
    if (form.mode === 'all' && !(await confirm('对所有人开放该端口？', '任何人都可以从公网访问这个端口。普通管理员执行此操作需要超级管理员批准。', { ok: '确认开放' }))) return
    setBusy(true)
    try {
      await runAction('forward.save', { ...form, id: f?.id ?? '', rev: f?.rev ?? '' })
      onSaved()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const remove = async () => {
    if (!f || !(await confirm('删除该端口转发？', `WAN ${f.wan_port} → ${f.lan_ip}:${f.lan_port}`, { danger: true, ok: '删除' }))) return
    setBusy(true)
    try { await runAction('forward.delete', { id: f.id, rev: f.rev }); onSaved() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }

  return (
    <HalfPanel open={!!target} onOpenChange={(o) => { if (!o) { onClose(); setLoaded(null) } }}
      title={isNew ? '新增端口转发' : f?.managed ? f.device_now || f.device_name || f.lan_ip : f?.name || f?.id}
      desc={f ? `WAN ${f.wan_port}/${protoLabel(f.proto)} → ${f.lan_ip}:${f.lan_port}${f.managed ? '' : ' · 路由器原有规则'}` : '把内网设备的端口映射到 WAN 口'}
      footer={editable && (
        <>
          {f && <Button variant="outline" className="mr-auto text-destructive" disabled={busy} onClick={remove}>删除</Button>}
          <Button variant="outline" onClick={onClose}>取消</Button>
          <Button disabled={busy || !form.lan_ip || !form.lan_port || !form.wan_port || portOk === false} onClick={save}>{busy ? '应用中…' : isNew ? '创建' : '保存'}</Button>
        </>
      )}>
      {f && <Button variant="outline" size="sm" className="mb-4" onClick={() => onStats(f)}><BarChart3 /> 查看流量与连接记录</Button>}
      <fieldset key={f?.id ?? 'new'} disabled={!editable} className="grid gap-6">
        <div className="grid gap-4 rounded-xl border p-4">
          <h3 className="text-sm font-semibold">转发目标</h3>
          <Field label="内网设备" hint="名称与设备页一致；可搜索名称、IP、MAC、厂商或备注，也可以直接输入 IP">
            <DeviceSelect devices={targets} value={form.lan_ip} fallbackName={form.device_name} onChange={(ip, d) => pickDevice(ip, d)} />
          </Field>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="内网端口"><Input inputMode="numeric" value={form.lan_port} onChange={(e) => set('lan_port', e.target.value.replace(/\D/g, ''))} placeholder="80" /></Field>
            <Field label="WAN 端口"><Input inputMode="numeric" value={form.wan_port} onChange={(e) => set('wan_port', e.target.value.replace(/\D/g, ''))} placeholder="443" /></Field>
            <Field label="协议">
              <Tabs value={form.proto} onValueChange={(v) => set('proto', String(v))}>
                <TabsList className="w-full"><TabsTrigger value="tcp">TCP</TabsTrigger><TabsTrigger value="udp">UDP</TabsTrigger><TabsTrigger value="tcp udp">两者</TabsTrigger></TabsList>
              </Tabs>
            </Field>
          </div>
          {editable && <PortHelper form={form} id={f?.id} onPick={(wan, port) => setForm((x) => ({ ...x, wan, wan_port: String(port) }))} onCheck={setPortOk} />}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="设备名称（写入备注）"><Input maxLength={32} value={form.device_name} onChange={(e) => set('device_name', e.target.value)} /></Field>
            <Field label="备注"><Input maxLength={64} value={form.note} onChange={(e) => set('note', e.target.value)} placeholder="例如：家里 NAS 网页" /></Field>
          </div>
          <label className="flex items-center justify-between">
            <span className="text-sm">启用</span>
            <Switch checked={form.enabled} onCheckedChange={(c) => set('enabled', !!c)} />
          </label>
        </div>

        <div className="grid gap-4 rounded-xl border p-4">
          <div>
            <h3 className="text-sm font-semibold">来源限制</h3>
            <p className="text-xs text-muted-foreground">在路由器防火墙上按来源 IP 过滤（IP 段由本地离线库生成）。内网设备通过公网 IP 访问不受此限制。</p>
          </div>
          <Tabs value={form.mode} onValueChange={(v) => set('mode', v as Form['mode'])}>
            <TabsList><TabsTrigger value="restrict">仅允许指定来源</TabsTrigger><TabsTrigger value="all">允许所有人</TabsTrigger></TabsList>
          </Tabs>
          {form.mode === 'restrict' && (
            <>
              <Field label="允许的国家 / 省州"><RegionPicker value={form.regions} onChange={(v) => set('regions', v)} /></Field>
              <Field label="额外允许的 IP / IP 段"><IPListInput value={form.allow} onChange={(v) => set('allow', v)} /></Field>
            </>
          )}
          <Field label="黑名单 IP / IP 段" hint="黑名单优先于白名单"><IPListInput value={form.deny} onChange={(v) => set('deny', v)} /></Field>
        </div>

        <div className="grid gap-1.5">
          <div className="text-xs font-medium text-muted-foreground">写入 OpenWrt 的备注（预览）</div>
          <code className="break-all rounded-lg bg-muted px-3 py-2 text-xs">{preview}</code>
        </div>
        {!editable && <p className="text-sm text-muted-foreground">该规则不是你创建的，只能查看。</p>}
      </fieldset>
      {dialog}
    </HalfPanel>
  )
}

// PortHelper: WAN choice (multi-WAN), live conflict check of the chosen port, and
// the port ranges this admin may use with their next free port.
function PortHelper({ form, id, onPick, onCheck }: { form: Form; id?: string; onPick: (wan: string, port: number) => void; onCheck: (ok: boolean | null) => void }) {
  const [q, setQ] = useState('')
  const port = Number(form.wan_port)
  useEffect(() => {
    const t = setTimeout(() => setQ(new URLSearchParams({ wan: form.wan, port: port ? String(port) : '', proto: form.proto, lan_ip: form.lan_ip, id: id ?? '', size: '1' }).toString()), 350)
    return () => clearTimeout(t)
  }, [form.wan, port, form.proto, form.lan_ip, id])
  const { data } = useApi<PortsInfo>(q ? `/forwards/ports?${q}` : null)
  const check = port ? data?.check : undefined
  useEffect(() => { onCheck(check ? check.ok : null) }, [check]) // eslint-disable-line react-hooks/exhaustive-deps
  if (!data) return null
  const wans = data.wans ?? []
  return (
    <div className="grid gap-2 rounded-lg bg-muted/50 p-3 text-xs">
      {wans.length > 1 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-muted-foreground">从哪个 WAN 口进来</span>
          <Tabs value={form.wan || '_all'} onValueChange={(v) => onPick(v === '_all' ? '' : String(v), port)}>
            <TabsList>
              <TabsTrigger value="_all">全部</TabsTrigger>
              {wans.map((w) => <TabsTrigger key={w.interface} value={w.interface}>{w.interface}{w.ipv4 ? ` · ${w.ipv4}` : w.up ? '' : '（未连接）'}</TabsTrigger>)}
            </TabsList>
          </Tabs>
        </div>
      )}
      {data.restricted ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground">你可以使用的端口段：</span>
          {data.grants.map((g) => (
            <button key={g.wan + g.from} type="button" disabled={!g.next} onClick={() => onPick(g.wan, g.next)}
              className={cn('rounded-md border bg-background px-1.5 py-0.5 font-mono hover:border-primary/50', !g.next && 'opacity-50')}
              title={g.next ? `点击填入下一个空闲端口 ${g.next}` : '已用满'}>
              {grantLabel(g, wans)} <span className="font-sans text-muted-foreground">空闲 {g.free}</span>
            </button>
          ))}
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-1.5 text-muted-foreground">
          {data.suggest ? (
            <>建议的空闲端口：<button type="button" className="rounded-md border bg-background px-1.5 py-0.5 font-mono text-foreground hover:border-primary/50" onClick={() => onPick(form.wan, data.suggest!.from)}>{data.suggest.from}</button></>
          ) : null}
          <span>已占用：{(data.used ?? []).filter((u) => !form.wan || !u.wan || u.wan === form.wan).length} 个端口</span>
        </div>
      )}
      {data.lan_restricted && <div className="text-muted-foreground">允许转发到的内网设备：<span className="font-mono">{data.lan.join('、')}</span></div>}
      {check && (
        <div className="grid gap-0.5">
          {check.ok && !check.issues.length && <div className="text-success">✓ 端口 {check.port} 可以使用</div>}
          {check.issues.map((i, k) => (
            <div key={k} className={i.level === 'error' ? 'text-destructive' : 'text-[color-mix(in_oklch,var(--warning),black_35%)] dark:text-warning'}>
              {i.level === 'error' ? '✗' : '!'} {i.msg}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
