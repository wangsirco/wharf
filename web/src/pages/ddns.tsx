import { useState } from 'react'
import { toast } from 'sonner'
import { History, Loader2, Pencil, Play, Plus, Radar, Trash2 } from 'lucide-react'
import { api, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { ago, datetime } from '@/lib/format'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Dot, Empty, ErrorBox, Field, HalfPanel, Pill, Section, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

interface Source { mode: 'auto' | 'iface' | 'api'; iface: string; apis: string[] | null; target?: string; check_min?: number }
interface Entry {
  id: number; name: string; enabled: boolean; provider: string; creds: Record<string, string>; domain: string; rtype: 'A' | 'AAAA' | 'CNAME'
  source: Source; interval_min: number; on_change: boolean; ttl: number; proxied: boolean
  last_ip: string; last_ok: number; last_run: number; last_err: string; created: number
}
interface Provider { id: string; name: string; fields: string[]; labels: string[]; help: string }
interface Resp { items: Entry[]; providers: Provider[]; ip_services: { id: string; url: string; v6: boolean }[]; ifaces: string[] | null }

type Form = Omit<Entry, 'id' | 'last_ip' | 'last_ok' | 'last_run' | 'last_err' | 'created'> & { id?: number }

const blank: Form = { name: '', enabled: true, provider: 'cloudflare', creds: {}, domain: '', rtype: 'A', source: { mode: 'auto', iface: 'wan', apis: [] }, interval_min: 0, on_change: true, ttl: 300, proxied: false }

const CNAME_OK = ['cloudflare', 'alidns', 'dnspod']
const SOURCE: Record<string, string> = { auto: '自动（接口是公网 IP 就用接口，否则问公网服务）', iface: '只看 WAN 接口', api: '只问公网 IP 查询服务' }

export default function DDNSPage() {
  const { data, error, reload } = useApi<Resp>('/ddns', 20000)
  const [edit, setEdit] = useState<Form | null>(null)
  const [log, setLog] = useState<Entry | null>(null)
  const [running, setRunning] = useState(0)
  const { confirm, dialog } = useConfirm()
  const prov = (id: string) => data?.providers.find((p) => p.id === id)
  const runNow = async (e: Entry) => {
    setRunning(e.id)
    try {
      const r = await post<{ ok: boolean; ip: string; msg?: string; error?: string }>(`/ddns/${e.id}/run`)
      if (r.ok) toast.success(`${e.domain}：${r.msg || r.ip}`)
      else toast.error(`${e.domain}：${r.error}`)
      reload()
    } catch (err) { toast.error((err as Error).message) } finally { setRunning(0) }
  }
  const del = async (e: Entry) => {
    if (!(await confirm(`删除「${e.name}」？`, '只是停止自动更新，服务商那里的 DNS 记录不会被删除。', { danger: true, ok: '删除' }))) return
    try { await api('DELETE', `/ddns/${e.id}`); reload() } catch (err) { toast.error((err as Error).message) }
  }
  return (
    <>
      <PageHeader title="动态域名 DDNS" desc="公网 IP 变了，自动把域名改过去。支持多条记录、多个 WAN、IPv4 / IPv6，任意层级的子域名">
        <Button size="sm" disabled={!data} onClick={() => setEdit({ ...blank, creds: {}, source: { ...blank.source, apis: [] } })}><Plus /> 添加域名</Button>
      </PageHeader>
      {error && <div className="mb-4"><ErrorBox>{error}</ErrorBox></div>}
      <CloudflareAccount onAdded={reload} />
      <Section title="域名" className="mt-4">
        {!data?.items.length ? <Empty>{data ? '还没有。添加一个域名，比如 home.example.com，让它始终指向家里。' : '加载中…'}</Empty> : (
          <div className="divide-y">
            {data.items.map((e) => (
              <div key={e.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                <Dot tone={!e.enabled ? 'off' : e.last_err ? 'bad' : e.last_ok ? 'ok' : 'warn'} />
                <button type="button" className="min-w-0 flex-1 text-left" onClick={() => setEdit({ ...e, creds: { ...e.creds }, source: { ...e.source, apis: [...(e.source.apis ?? [])] } })}>
                  <div className="flex items-center gap-1.5 text-sm font-medium">
                    <span className="truncate font-mono">{e.domain}</span><Pill>{e.rtype}</Pill><Pill tone="blue">{prov(e.provider)?.name ?? e.provider}</Pill>
                    {!e.enabled && <Pill>已暂停</Pill>}
                  </div>
                  <div className="truncate text-xs text-muted-foreground">
                    {e.rtype === 'CNAME'
                      ? <>指向 <span className="font-mono">{e.source.target}</span>{e.last_ok ? ` · ${ago(e.last_ok)}核对` : ' · 还没有写入'}</>
                      : <>{e.last_ip ? <>当前 <span className="font-mono">{e.last_ip}</span> · {ago(e.last_ok)}更新</> : '还没有更新过'}
                    {' · '}{scheduleText(e)}
                    {e.source.mode !== 'api' && e.source.iface ? ` · 接口 ${e.source.iface}` : ''}</>}
                  </div>
                  {e.last_err && <div className="truncate text-xs text-destructive">{e.last_err}</div>}
                </button>
                <div className="flex">
                  <Button variant="ghost" size="icon-sm" title="立即更新" disabled={running === e.id} onClick={() => runNow(e)}>{running === e.id ? <Loader2 className="animate-spin" /> : <Play />}</Button>
                  <Button variant="ghost" size="icon-sm" title="记录" onClick={() => setLog(e)}><History /></Button>
                  <Button variant="ghost" size="icon-sm" title="修改" onClick={() => setEdit({ ...e, creds: { ...e.creds }, source: { ...e.source, apis: [...(e.source.apis ?? [])] } })}><Pencil /></Button>
                  <Button variant="ghost" size="icon-sm" title="删除" onClick={() => del(e)}><Trash2 /></Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
      {data && <Editor value={edit} onChange={setEdit} data={data} onSaved={() => { setEdit(null); reload() }} />}
      <LogPanel entry={log} onClose={() => setLog(null)} />
      {dialog}
    </>
  )
}

function Editor({ value: v, onChange, data, onSaved }: { value: Form | null; onChange: (v: Form | null) => void; data: Resp; onSaved: () => void }) {
  const [busy, setBusy] = useState(false)
  const [detect, setDetect] = useState<{ source: string; ip: string; error?: string; public: boolean }[] | null>(null)
  const [detecting, setDetecting] = useState(false)
  const [custom, setCustom] = useState('')
  if (!v) return <HalfPanel open={false} onOpenChange={() => {}} title=""><div /></HalfPanel>
  const set = (p: Partial<Form>) => onChange({ ...v, ...p })
  const setSrc = (p: Partial<Source>) => onChange({ ...v, source: { ...v.source, ...p } })
  const p = data.providers.find((x) => x.id === v.provider)
  const v6 = v.rtype === 'AAAA'
  const cname = v.rtype === 'CNAME'
  const services = data.ip_services.filter((s) => s.v6 === v6)
  const apis = v.source.apis ?? []
  const save = async () => {
    setBusy(true)
    try { await post('/ddns', v); toast.success('已保存，马上更新一次'); onSaved() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const runDetect = async () => {
    setDetecting(true)
    try { const r = await post<{ results: typeof detect }>('/ddns/detect', { rtype: v.rtype, source: v.source }); setDetect(r.results) } catch (e) { toast.error((e as Error).message) } finally { setDetecting(false) }
  }
  return (
    <HalfPanel open={!!v} onOpenChange={(o) => { if (!o) { onChange(null); setDetect(null) } }} title={v.id ? `修改「${v.name || v.domain}」` : '添加域名'}
      footer={<><Button variant="outline" onClick={() => onChange(null)}>取消</Button><Button disabled={!v.domain || (cname && !v.source.target) || busy} onClick={save}>{busy && <Loader2 className="animate-spin" />}保存</Button></>}>
      <div className="grid gap-5">
        <Field label="服务商">
          <div className="grid gap-1.5 sm:grid-cols-2">
            {data.providers.map((x) => (
              <button key={x.id} type="button" onClick={() => set({ provider: x.id, creds: {}, rtype: v.rtype === 'CNAME' && !CNAME_OK.includes(x.id) ? 'A' : v.rtype })}
                className={cn('rounded-lg border px-3 py-2 text-left text-sm', v.provider === x.id ? 'border-primary bg-accent' : 'hover:bg-muted')}>{x.name}</button>
            ))}
          </div>
        </Field>
        {p && (
          <div className="grid gap-3 rounded-xl border p-4">
            <p className="text-xs text-muted-foreground">{p.help}</p>
            {v.provider === 'cloudflare' && <p className="text-xs text-muted-foreground">已连接 Cloudflare 账户时 API Token 可以留空，自动使用账户的令牌。</p>}
            {p.fields.map((f, i) => (
              <Field key={f} label={p.labels[i]}>
                <Input value={v.creds[f] === '@account' ? '' : v.creds[f] ?? ''} placeholder={v.creds[f] === '@account' ? '使用 Cloudflare 账户' : undefined} onChange={(e) => set({ creds: { ...v.creds, [f]: e.target.value } })}
                  type={/secret|password|token|key/.test(f) && !(v.creds[f] ?? '').startsWith('••') ? 'password' : 'text'} className="font-mono" autoComplete="off" />
              </Field>
            ))}
          </div>
        )}
        <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
          <Field label="域名" hint="完整的名字，几级都可以：home.example.com、a.b.example.com"><Input value={v.domain} onChange={(e) => set({ domain: e.target.value.trim().toLowerCase() })} placeholder="home.example.com" className="font-mono" /></Field>
          <Field label="记录类型">
            <div className="flex gap-1.5">
              {(CNAME_OK.includes(v.provider) ? ['A', 'AAAA', 'CNAME'] as const : ['A', 'AAAA'] as const).map((t) => (
                <button key={t} type="button" onClick={() => onChange({ ...v, rtype: t, source: { ...v.source, apis: [], iface: t === 'AAAA' && v.source.iface === 'wan' ? 'wan6' : t === 'A' && v.source.iface === 'wan6' ? 'wan' : v.source.iface } })}
                  className={cn('rounded-md border px-3 py-1.5 text-xs', v.rtype === t ? 'border-primary bg-accent' : 'text-muted-foreground hover:bg-muted')}>{t === 'A' ? 'A（IPv4）' : t === 'AAAA' ? 'AAAA（IPv6）' : 'CNAME（别名）'}</button>
              ))}
            </div>
          </Field>
        </div>
        {cname && (
          <Field label="指向（已有的动态域名）" hint="家里已经有别的设备在做 DDNS 时，新子域名直接 CNAME 到它，不用再管 IP。每天核对一次记录">
            <Input value={v.source.target ?? ''} onChange={(e) => setSrc({ target: e.target.value.trim().toLowerCase() })} placeholder="home.example.net" className="font-mono" />
          </Field>
        )}
        <Field label="名称（可选）"><Input value={v.name} maxLength={40} onChange={(e) => set({ name: e.target.value })} placeholder={v.domain || '家里'} /></Field>

        {!cname && <><div className="grid gap-3 rounded-xl border p-4">
          <div className="text-sm font-medium">IP 从哪里来</div>
          <div className="grid gap-1.5">
            {Object.entries(SOURCE).map(([k, l]) => (
              <label key={k} className="flex items-center gap-2 text-sm"><input type="radio" checked={v.source.mode === k} onChange={() => setSrc({ mode: k as Source['mode'] })} />{l}</label>
            ))}
          </div>
          {v.source.mode !== 'api' && (
            <Field label="WAN 接口" hint="多条宽带时选对应的那一条；公网服务也会从这条线路去问">
              <div className="flex flex-wrap gap-1.5">
                {[...new Set([...(data.ifaces ?? []), v.source.iface].filter(Boolean))].map((i) => (
                  <button key={i} type="button" onClick={() => setSrc({ iface: i })} className={cn('rounded-md border px-2.5 py-1 font-mono text-xs', v.source.iface === i ? 'border-primary bg-accent' : 'text-muted-foreground hover:bg-muted')}>{i}</button>
                ))}
              </div>
            </Field>
          )}
          {v.source.mode !== 'iface' && (
            <Field label="公网 IP 查询服务" hint="按顺序尝试，前一个失败就用下一个。适合光猫拨号、路由器拿不到公网 IP 的情况">
              <div className="flex flex-wrap gap-1.5">
                {services.map((s) => (
                  <button key={s.id} type="button" title={s.url} onClick={() => setSrc({ apis: apis.includes(s.id) ? apis.filter((x) => x !== s.id) : [...apis, s.id] })}
                    className={cn('rounded-md border px-2.5 py-1 text-xs', apis.includes(s.id) ? 'border-primary bg-accent' : 'text-muted-foreground hover:bg-muted')}>
                    {apis.includes(s.id) && <span className="mr-1 tabular-nums">{apis.indexOf(s.id) + 1}.</span>}{s.id.replace(/6$/, '')}
                  </button>
                ))}
                {apis.filter((a) => a.startsWith('http')).map((a) => <Pill key={a}>{a} <button type="button" onClick={() => setSrc({ apis: apis.filter((x) => x !== a) })}>×</button></Pill>)}
              </div>
              <div className="mt-1.5 flex gap-2">
                <Input value={custom} onChange={(e) => setCustom(e.target.value.trim())} placeholder="自定义：https://… （返回纯文本 IP）" className="h-8 text-xs" />
                <Button size="sm" variant="outline" disabled={!/^https?:\/\//.test(custom)} onClick={() => { setSrc({ apis: [...apis, custom] }); setCustom('') }}>添加</Button>
              </div>
              {!apis.length && <p className="text-xs text-muted-foreground">没选时默认用 ipify → ip.sb → Cloudflare</p>}
            </Field>
          )}
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" disabled={detecting} onClick={runDetect}>{detecting ? <Loader2 className="animate-spin" /> : <Radar />} 现在检测一下</Button>
          </div>
          {detect && (
            <div className="grid gap-1 text-xs">
              {detect.map((d) => (
                <div key={d.source} className="flex items-center gap-2">
                  <Dot tone={d.error ? 'bad' : d.public ? 'ok' : 'warn'} />
                  <span className="w-28 truncate text-muted-foreground">{d.source}</span>
                  {d.error ? <span className="text-destructive">{d.error}</span> : <><span className="font-mono">{d.ip}</span>{!d.public && <Pill tone="amber">不是公网地址</Pill>}</>}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="grid gap-3 rounded-xl border p-4">
          <div className="text-sm font-medium">什么时候更新（可以都选）</div>
          <Schedule check={v.on_change ? (v.source.check_min || 0) : -1} force={v.interval_min}
            onChange={(check, force) => set({ on_change: check >= 0, interval_min: force, source: { ...v.source, check_min: Math.max(check, 0) } })} custom />
        </div></>}
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="TTL（秒）" hint="阿里云 / DNSPod 免费版最低 600"><Input value={v.ttl} inputMode="numeric" onChange={(e) => set({ ttl: Number(e.target.value.replace(/\D/g, '')) || 0 })} /></Field>
          {v.provider === 'cloudflare' && (
            <label className="flex items-center gap-2 self-end pb-2 text-sm"><Switch checked={v.proxied} onCheckedChange={(c) => set({ proxied: c })} />经过 Cloudflare 代理（橙色云）</label>
          )}
        </div>
        {v.provider === 'cloudflare' && v.proxied && <p className="text-xs text-muted-foreground">开了橙色云，域名会解析到 Cloudflare 的 IP：网页可以访问，但代理节点（REALITY、TLS 直连）和端口转发都没法用这个域名直接连。给代理节点用的域名请保持关闭。</p>}
        <label className="flex items-center gap-2 text-sm"><Switch checked={v.enabled} onCheckedChange={(c) => set({ enabled: c })} />启用</label>
      </div>
    </HalfPanel>
  )
}

function LogPanel({ entry, onClose }: { entry: Entry | null; onClose: () => void }) {
  const { data } = useApi<{ items: { ts: number; ip: string; ok: boolean; msg: string }[] }>(entry ? `/ddns/${entry.id}/log` : null)
  return (
    <HalfPanel open={!!entry} onOpenChange={(o) => { if (!o) onClose() }} title={`「${entry?.domain}」更新记录`} desc="只记 IP 变化、手动更新和失败">
      {!data ? <Empty>加载中…</Empty> : !data.items.length ? <Empty>还没有记录</Empty> : (
        <div className="divide-y rounded-xl border">
          {data.items.map((x, i) => (
            <div key={i} className="flex items-start gap-2 px-3 py-2 text-sm">
              <Dot tone={x.ok ? 'ok' : 'bad'} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2"><span className="font-mono">{x.ip || '—'}</span><span className="ml-auto text-xs text-muted-foreground">{datetime(x.ts)}</span></div>
                <div className={cn('text-xs', x.ok ? 'text-muted-foreground' : 'text-destructive')}>{x.msg}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </HalfPanel>
  )
}

// ---- schedule presets ----

const CHECKS: [number, string][] = [[1, '每 1 分钟'], [5, '每 5 分钟'], [10, '每 10 分钟'], [30, '每 30 分钟']]
const FORCES: [number, string][] = [[0, '不强制'], [360, '每 6 小时'], [720, '每 12 小时'], [1440, '每天'], [10080, '每周']]
const PLANS: { label: string; desc: string; check: number; force: number }[] = [
  { label: '推荐', desc: '每 5 分钟看一次 IP，变了就改；每天再强制写一次兜底', check: 5, force: 1440 },
  { label: '实时', desc: '每分钟看一次，适合经常换 IP 的拨号宽带', check: 1, force: 720 },
  { label: '省事', desc: '每 30 分钟看一次，每周兜底', check: 30, force: 10080 },
  { label: '只定时', desc: '不检测变化，每 10 分钟直接写一次', check: -1, force: 10 },
]

function label(n: number) {
  return n <= 0 ? '不强制' : n < 60 ? `每 ${n} 分钟` : n < 1440 ? `每 ${n / 60} 小时` : n === 1440 ? '每天' : n === 10080 ? '每周' : `每 ${Math.round(n / 1440)} 天`
}

export function scheduleText(e: { on_change: boolean; interval_min: number; source: { check_min?: number; mode: string } }) {
  const parts: string[] = []
  if (e.on_change) parts.push(`IP 变化时（${e.source.check_min ? `每 ${e.source.check_min} 分钟检查` : e.source.mode === 'api' ? '每 5 分钟检查' : '每分钟检查'}）`)
  if (e.interval_min > 0) parts.push(`${label(e.interval_min)}强制`)
  return parts.join(' + ')
}

// Schedule: check = minutes between looks for a new address (-1 = do not watch, 0 = default);
// force = minutes between forced writes (0 = never).
function Schedule({ check, force, onChange, custom }: { check: number; force: number; onChange: (check: number, force: number) => void; custom?: boolean }) {
  const chip = (on: boolean) => cn('rounded-md border px-2.5 py-1 text-xs', on ? 'border-primary bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted')
  return (
    <div className="grid gap-3">
      <Field label="快速方案">
        <div className="grid gap-1.5 sm:grid-cols-2">
          {PLANS.map((p) => (
            <button key={p.label} type="button" onClick={() => onChange(p.check, p.force)}
              className={cn('rounded-lg border px-3 py-2 text-left', check === p.check && force === p.force ? 'border-primary bg-accent' : 'hover:bg-muted')}>
              <div className="text-sm font-medium">{p.label}</div><div className="text-xs text-muted-foreground">{p.desc}</div>
            </button>
          ))}
        </div>
      </Field>
      {custom && (
        <>
          <Field label="多久检查一次 IP（变了立即更新）">
            <div className="flex flex-wrap gap-1.5">
              <button type="button" className={chip(check < 0)} onClick={() => onChange(-1, force || 60)}>不检查</button>
              {CHECKS.map(([n, l]) => <button key={n} type="button" className={chip(check === n || (n === 1 && check === 0))} onClick={() => onChange(n, force)}>{l}</button>)}
            </div>
          </Field>
          <Field label="兜底：定时强制更新" hint="即使 IP 没变也重新写一次，防止记录被别处改掉或服务商丢了更新">
            <div className="flex flex-wrap items-center gap-1.5">
              {FORCES.map(([n, l]) => <button key={n} type="button" className={chip(force === n)} onClick={() => onChange(check, n)}>{l}</button>)}
              <Input className="h-7 w-24 text-xs" inputMode="numeric" value={force} onChange={(e) => onChange(check, Number(e.target.value.replace(/\D/g, '')) || 0)} />
              <span className="text-xs text-muted-foreground">分钟（自定义，最长 10080）</span>
            </div>
          </Field>
        </>
      )}
    </div>
  )
}

// ---- Cloudflare account ----

interface CFState { connected: boolean; token: string; create_url: string; zones: { id: string; name: string }[]; error?: string }
interface CFRecord { id: string; type: string; name: string; content: string; proxied: boolean }

function CloudflareAccount({ onAdded }: { onAdded: () => void }) {
  const { data, reload } = useApi<CFState>('/cloudflare')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [zone, setZone] = useState('')
  const [sub, setSub] = useState('')
  const [rtype, setRtype] = useState<'A' | 'AAAA'>('A')
  const [plan, setPlan] = useState({ check: 5, force: 1440 })
  const { data: records, reload: reloadRecs } = useApi<CFRecord[]>(zone ? `/cloudflare/records?zone=${zone}` : null)
  const { confirm, dialog } = useConfirm()
  if (!data) return null
  const zoneName = data.zones.find((z) => z.id === zone)?.name ?? ''
  const connect = async (t: string) => {
    setBusy(true)
    try { await post('/cloudflare', { token: t }); setToken(''); toast.success(t ? '已连接 Cloudflare 账户' : '已断开'); reload() }
    catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const add = async (domain: string, type: string) => {
    setBusy(true)
    try {
      await post('/ddns', { name: domain, enabled: true, provider: 'cloudflare', creds: { token: '' }, domain, rtype: type,
        source: { mode: 'auto', iface: type === 'AAAA' ? 'wan6' : 'wan', apis: [], check_min: Math.max(plan.check, 0) },
        interval_min: plan.force, on_change: plan.check >= 0, ttl: 300, proxied: false })
      toast.success(`已添加 ${domain}，马上更新一次`); setSub(''); onAdded(); reloadRecs()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const takeOver = async (r: CFRecord) => {
    if (r.type === 'CNAME') { toast.error('这是 CNAME 记录：要改成跟随家里 IP，请先在 Cloudflare 删掉它，再在这里用同名新建'); return }
    if (!(await confirm(`接管 ${r.name}？`, `它现在指向 ${r.content}${r.proxied ? '（开着橙色云）' : ''}。接管后由面板按家里的公网 IP 自动更新${r.proxied ? '，并关闭橙色云' : ''}。`, { ok: '接管' }))) return
    await add(r.name, r.type)
  }
  return (
    <Section title="Cloudflare 账户" desc="连接一次，就能直接选域名、新建或接管已有的解析记录，面板域名和证书也会用它。">
      <div className="grid gap-4 p-4">
        {!data.connected ? (
          <div className="grid gap-3">
            <ol className="list-decimal space-y-0.5 pl-5 text-sm">
              <li><a className="text-primary underline" href={data.create_url} target="_blank" rel="noreferrer">打开 Cloudflare 创建令牌</a>（权限已经选好：读取区域、编辑 DNS；登录后滚到最下面点「继续」→「创建令牌」）</li>
              <li>复制生成的令牌，粘贴到下面</li>
            </ol>
            <div className="flex gap-2">
              <Input type="password" autoComplete="off" placeholder="Cloudflare API 令牌" value={token} onChange={(e) => setToken(e.target.value.trim())} />
              <Button disabled={busy || !token} onClick={() => connect(token)}>{busy && <Loader2 className="animate-spin" />}连接</Button>
            </div>
            <p className="text-xs text-muted-foreground">Cloudflare 暂不支持让家用设备直接「用账号登录」（OAuth 需要固定的回调网址），所以用这个一键创建的令牌代替：只能读域名、改 DNS，随时可以在 Cloudflare 撤销。</p>
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Dot tone={data.error ? 'bad' : 'ok'} />{data.error ? <span className="text-destructive">{data.error}</span> : <span>已连接 · {data.zones.length} 个域名：</span>}
              {data.zones.map((z) => <Pill key={z.id}>{z.name}</Pill>)}
              <Button variant="ghost" size="sm" disabled={busy} onClick={() => connect('')}>断开</Button>
            </div>
            <div className="grid gap-3 rounded-xl border p-4">
              <div className="text-sm font-medium">快速添加</div>
              <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]">
                <Field label="主域名">
                  <select className="h-9 rounded-md border bg-background px-2 text-sm" value={zone} onChange={(e) => setZone(e.target.value)}>
                    <option value="">选择…</option>
                    {data.zones.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
                  </select>
                </Field>
                <Field label="子域名" hint={zoneName ? `将更新 ${sub ? sub + '.' : ''}${zoneName}` : '留空 = 主域名本身'}>
                  <Input value={sub} placeholder="home" onChange={(e) => setSub(e.target.value.trim().toLowerCase())} />
                </Field>
                <Field label="类型">
                  <div className="flex gap-1">
                    {(['A', 'AAAA'] as const).map((t) => <button key={t} type="button" onClick={() => setRtype(t)} className={cn('h-9 rounded-md border px-3 text-xs', rtype === t ? 'border-primary bg-accent' : 'text-muted-foreground')}>{t === 'A' ? 'IPv4' : 'IPv6'}</button>)}
                  </div>
                </Field>
              </div>
              <Schedule check={plan.check} force={plan.force} onChange={(check, force) => setPlan({ check, force })} />
              <div><Button disabled={busy || !zone} onClick={() => add(sub ? `${sub}.${zoneName}` : zoneName, rtype)}><Plus /> 添加并更新</Button></div>
              {zone && (
                <div className="grid gap-1">
                  <div className="text-xs text-muted-foreground">{zoneName} 现有的解析记录（可以直接接管）</div>
                  <div className="max-h-56 divide-y overflow-y-auto rounded-lg border">
                    {(records ?? []).map((r) => (
                      <div key={r.id} className="flex items-center gap-2 px-3 py-1.5 text-sm">
                        <span className="min-w-0 flex-1 truncate font-mono">{r.name}</span><Pill>{r.type}</Pill>
                        <span className="hidden truncate font-mono text-xs text-muted-foreground sm:inline">{r.content}{r.proxied ? ' · 橙色云' : ''}</span>
                        <Button variant="ghost" size="sm" disabled={busy} onClick={() => takeOver(r)}>接管</Button>
                      </div>
                    ))}
                    {records && !records.length && <Empty>没有 A / AAAA / CNAME 记录</Empty>}
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>
      {dialog}
    </Section>
  )
}
