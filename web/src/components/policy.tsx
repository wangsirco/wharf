import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Ban, Clock, Plus, Search, ShieldCheck, Trash2, Wifi, X } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { runAction } from '@/lib/actions'
import type { Catalog, DevicePolicy, PolicySchedule } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Empty, ErrorBox, Field, Section, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

const DAYS = ['日', '一', '二', '三', '四', '五', '六']
const PORT_PRESETS: [string, string][] = [['22', 'SSH'], ['80', 'LuCI'], ['443', 'LuCI HTTPS'], ['7080', 'Wharf 面板'], ['445', 'SMB 共享'], ['7681', 'ttyd 终端']]

export function policyLabel(p?: DevicePolicy | null) {
  if (!p?.exists) return null
  if (p.status?.blocked) return p.status.reason === 'schedule' ? '定时断网中' : '已断网'
  if (p.mode === 'blacklist') return '黑名单'
  if (p.mode === 'whitelist') return '白名单'
  if (p.schedules.length) return '已设定时'
  return '已设管控'
}

function targetLabel(t: string) {
  const [k, v] = t.split(/:(.*)/s)
  return { k, v, text: k === 'service' ? v : v, tag: k === 'service' ? '服务' : k === 'domain' ? '域名' : 'IP' }
}

export function PolicyEditor({ mac, name }: { mac: string; name: string }) {
  const { data, error, reload } = useApi<DevicePolicy>(`/devices/${encodeURIComponent(mac)}/policy`, 20000)
  const { data: catalog } = useApi<Catalog>('/rules/catalog')
  const [form, setForm] = useState<DevicePolicy | null>(null)
  const [loadedRev, setLoadedRev] = useState<string>('')
  const [q, setQ] = useState('')
  const [custom, setCustom] = useState('')
  const [port, setPort] = useState('')
  const [busy, setBusy] = useState(false)
  const { confirm, dialog } = useConfirm()

  // take server state unless the user has unsaved edits
  const rev = data ? JSON.stringify({ ...data, status: null }) : ''
  if (data && rev !== loadedRev && (!form || JSON.stringify({ ...form, status: null }) === loadedRev)) {
    setLoadedRev(rev)
    setForm({ ...data, name: data.name || name })
  }
  const dirty = !!form && JSON.stringify({ ...form, status: null }) !== loadedRev
  const set = <K extends keyof DevicePolicy>(k: K, v: DevicePolicy[K]) => setForm((f) => (f ? { ...f, [k]: v } : f))

  const services = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!s || !catalog?.services) return []
    return catalog.services.filter((x) => x.n.toLowerCase().includes(s) || x.c.includes(s) || (x.s ?? '').includes(s) || x.o.toLowerCase().includes(s)).slice(0, 30)
  }, [q, catalog])

  if (error) return <ErrorBox>{error}</ErrorBox>
  if (!form || !data) return <Empty>加载中…</Empty>
  const editable = data.editable

  const save = async (next = form) => {
    setBusy(true)
    try {
      if (await runAction('device.policy.save', next)) { setLoadedRev(''); setForm(null) }
      reload()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const quickBlock = async (on: boolean) => {
    if (on && !(await confirm(`立即断开 ${name || mac} 的网络？`, form.captive ? '设备仍会显示「已连接互联网」，但打不开任何内容。' : '设备将无法访问互联网。', { danger: true, ok: '断网' }))) return
    save({ ...form, block: on })
  }
  const remove = async () => {
    if (!(await confirm('解除该设备的全部管控？', '断网、名单、定时规则都会被删除。', { danger: true, ok: '解除' }))) return
    setBusy(true)
    try { await runAction('device.policy.delete', { mac }); setLoadedRev(''); setForm(null); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const addTarget = (t: string) => { if (!form.targets.includes(t)) set('targets', [...form.targets, t]) }
  const addCustom = () => {
    const v = custom.trim()
    if (!v) return
    addTarget(/^[\d./]+$/.test(v) ? `ip:${v}` : `domain:${v.replace(/^https?:\/\//, '').split('/')[0]}`)
    setCustom('')
  }
  const updSched = (i: number, s: Partial<PolicySchedule>) => set('schedules', form.schedules.map((x, j) => (j === i ? { ...x, ...s } : x)))

  const st = data.status
  return (
    <div className="grid gap-4">
      <div className={cn('flex flex-wrap items-center gap-4 rounded-xl border p-4', st?.blocked ? 'border-destructive/40 bg-destructive/5' : 'bg-card')}>
        <div className={cn('grid size-10 place-items-center rounded-full', st?.blocked ? 'bg-destructive/15 text-destructive' : 'bg-success/15 text-success')}>
          {st?.blocked ? <Ban className="size-5" /> : <Wifi className="size-5" />}
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-medium">{st?.blocked ? (st.reason === 'schedule' ? '定时断网中' : '已断网') : '可以上网'}</div>
          <div className="text-xs text-muted-foreground">
            {data.exists ? `管控规则由 ${data.owner_name || '超级管理员'} 设置` : '该设备还没有管控规则'}
            {!editable && data.exists && ' · 你只能查看'}
          </div>
        </div>
        {editable && (
          <Button variant={form.block ? 'outline' : 'destructive'} disabled={busy} onClick={() => quickBlock(!form.block)}>
            {form.block ? <><ShieldCheck /> 恢复上网</> : <><Ban /> 立即断网</>}
          </Button>
        )}
      </div>

      <fieldset disabled={!editable || busy} className="grid gap-4 xl:grid-cols-2">
        <Section title="断网选项">
          <div className="grid gap-4 p-4">
            <label className="flex items-start justify-between gap-4">
              <span><span className="text-sm">骗过联网检测</span><span className="block text-xs text-muted-foreground">断网时仍放行 Apple / Android / Windows / 小米等系统的联网检测地址，设备会显示「已连接互联网」，但打不开任何内容。</span></span>
              <Switch checked={form.captive} onCheckedChange={(c) => set('captive', !!c)} />
            </label>
            <label className="flex items-start justify-between gap-4">
              <span><span className="text-sm">强制使用路由器 DNS</span><span className="block text-xs text-muted-foreground">把该设备的 DNS 请求转到路由器并拦截 DoT，防止通过自定义 DNS 绕过名单。使用 DoH（加密 DNS）的应用可能仍可绕过域名规则。</span></span>
              <Switch checked={form.force_dns} onCheckedChange={(c) => set('force_dns', !!c)} />
            </label>
          </div>
        </Section>

        <Section title="定时断网" desc="在这些时间段自动断网（路由器本地时间，跨午夜自动处理）" action={editable && (
          <Button variant="ghost" size="sm" onClick={() => set('schedules', [...form.schedules, { days: [0, 1, 2, 3, 4, 5, 6], start: '22:00', end: '07:00' }])}><Plus /> 添加</Button>
        )}>
          <div className="grid gap-3 p-4">
            {form.schedules.map((s, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2 rounded-lg border p-2.5">
                <Clock className="size-4 text-muted-foreground" />
                <div className="flex gap-1">
                  {DAYS.map((d, n) => (
                    <button key={n} type="button" onClick={() => updSched(i, { days: s.days.includes(n) ? s.days.filter((x) => x !== n) : [...s.days, n].sort() })}
                      className={cn('size-7 rounded-md text-xs', s.days.includes(n) ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground')}>{d}</button>
                  ))}
                </div>
                <Input type="time" className="h-8 w-28" value={s.start} onChange={(e) => updSched(i, { start: e.target.value })} />
                <span className="text-muted-foreground">→</span>
                <Input type="time" className="h-8 w-28" value={s.end} onChange={(e) => updSched(i, { end: e.target.value })} />
                {s.end < s.start && <span className="text-xs text-muted-foreground">次日</span>}
                <Button variant="ghost" size="icon-sm" className="ml-auto" onClick={() => set('schedules', form.schedules.filter((_, j) => j !== i))}><Trash2 /></Button>
              </div>
            ))}
            {!form.schedules.length && <p className="text-sm text-muted-foreground">没有定时规则</p>}
          </div>
        </Section>

        <Section title="访问名单" desc="黑名单：禁止访问这些目标；白名单：只能访问这些目标" className="xl:col-span-2">
          <div className="grid gap-4 p-4">
            <Tabs value={form.mode} onValueChange={(v) => set('mode', v as DevicePolicy['mode'])}>
              <TabsList><TabsTrigger value="none">不限制</TabsTrigger><TabsTrigger value="blacklist">黑名单</TabsTrigger><TabsTrigger value="whitelist">白名单</TabsTrigger></TabsList>
            </Tabs>
            {form.mode !== 'none' && (
              <>
                <div className="flex flex-wrap gap-1.5">
                  {form.targets.map((t) => {
                    const l = targetLabel(t)
                    return (
                      <span key={t} className={cn('inline-flex items-center gap-1 rounded-full py-0.5 pl-2.5 pr-1 text-xs', form.mode === 'blacklist' ? 'bg-destructive/10 text-destructive' : 'bg-success/12 text-success')}>
                        <span className="opacity-70">{l.tag}</span>{l.text}
                        <button type="button" className="rounded-full p-0.5 hover:bg-black/10" onClick={() => set('targets', form.targets.filter((x) => x !== t))}><X className="size-3" /></button>
                      </span>
                    )
                  })}
                  {!form.targets.length && <span className="text-sm text-muted-foreground">还没有目标</span>}
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <Field label="按服务添加" hint="来自内容识别规则库，例如 YouTube、抖音、Steam、ChatGPT">
                    <div className="rounded-lg border">
                      <div className="relative border-b">
                        <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                        <Input className="h-8 border-0 pl-8 shadow-none focus-visible:ring-0" placeholder="搜索服务 / 大类 / 公司" value={q} onChange={(e) => setQ(e.target.value)} />
                      </div>
                      <div className="max-h-56 overflow-y-auto py-1 text-sm">
                        {services.map((s) => (
                          <button key={s.n} type="button" onClick={() => addTarget(`service:${s.n}`)} disabled={form.targets.includes(`service:${s.n}`)}
                            className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-muted disabled:opacity-40">
                            <span className="flex-1">{s.n}</span><span className="text-xs text-muted-foreground">{s.c}{s.s && s.s !== s.c ? ` · ${s.s}` : ''}</span><Plus className="size-3.5" />
                          </button>
                        ))}
                        {!q && <div className="px-3 py-2 text-xs text-muted-foreground">输入关键词搜索</div>}
                        {q && !services.length && <div className="px-3 py-2 text-xs text-muted-foreground">没有匹配的服务</div>}
                      </div>
                    </div>
                  </Field>
                  <Field label="添加域名或 IP" hint="域名会包含其所有子域名，例如 example.com 也匹配 www.example.com">
                    <div className="flex gap-2">
                      <Input placeholder="example.com 或 203.0.113.0/24" value={custom} onChange={(e) => setCustom(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addCustom() } }} />
                      <Button variant="outline" onClick={addCustom}><Plus /> 添加</Button>
                    </div>
                  </Field>
                </div>
              </>
            )}
          </div>
        </Section>

        <Section title="禁止访问路由器端口" desc="例如不让访客手机打开路由器后台或共享盘" className="xl:col-span-2">
          <div className="flex flex-wrap items-center gap-2 p-4">
            {PORT_PRESETS.map(([p, l]) => (
              <button key={p} type="button" onClick={() => set('router_ports', form.router_ports.includes(p) ? form.router_ports.filter((x) => x !== p) : [...form.router_ports, p])}
                className={cn('rounded-full border px-3 py-1 text-xs', form.router_ports.includes(p) ? 'border-destructive/40 bg-destructive/10 text-destructive' : 'text-muted-foreground hover:bg-muted')}>
                {l} <span className="opacity-60">{p}</span>
              </button>
            ))}
            {form.router_ports.filter((p) => !PORT_PRESETS.some(([x]) => x === p)).map((p) => (
              <span key={p} className="inline-flex items-center gap-1 rounded-full border border-destructive/40 bg-destructive/10 py-1 pl-3 pr-1 text-xs text-destructive">
                {p}<button type="button" onClick={() => set('router_ports', form.router_ports.filter((x) => x !== p))}><X className="size-3" /></button>
              </span>
            ))}
            <Input className="h-7 w-24 text-xs" placeholder="其他端口" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))}
              onKeyDown={(e) => { if (e.key === 'Enter' && port) { e.preventDefault(); set('router_ports', [...new Set([...form.router_ports, port])]); setPort('') } }} />
          </div>
        </Section>
      </fieldset>

      {editable && (
        <div className="sticky bottom-0 flex items-center justify-end gap-2 border-t bg-background/90 py-3 backdrop-blur">
          {data.exists && <Button variant="outline" className="mr-auto text-destructive" disabled={busy} onClick={remove}>解除全部管控</Button>}
          {dirty && <span className="text-xs text-muted-foreground">有未保存的修改</span>}
          <Button disabled={busy || !dirty} onClick={() => save()}>{busy ? '应用中…' : '保存并生效'}</Button>
        </div>
      )}
      {dialog}
    </div>
  )
}
