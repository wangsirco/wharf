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

interface Source { mode: 'auto' | 'iface' | 'api'; iface: string; apis: string[] | null; target?: string }
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
      <Section title="域名">
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
                    {' · '}{[e.on_change && 'IP 变化时', e.interval_min > 0 && `每 ${e.interval_min} 分钟`].filter(Boolean).join(' + ')}
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
            {p.fields.map((f, i) => (
              <Field key={f} label={p.labels[i]}>
                <Input value={v.creds[f] ?? ''} onChange={(e) => set({ creds: { ...v.creds, [f]: e.target.value } })}
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
          <label className="flex items-center gap-2 text-sm"><Switch checked={v.on_change} onCheckedChange={(c) => set({ on_change: c })} />IP 变化时立即更新<span className="text-xs text-muted-foreground">（接口每分钟看一次，公网服务每 5 分钟问一次）</span></label>
          <Field label="定时强制更新">
            <div className="flex flex-wrap gap-1.5">
              {[0, 5, 10, 30, 60, 360, 1440].map((n) => (
                <button key={n} type="button" onClick={() => set({ interval_min: n })} className={cn('rounded-md border px-2.5 py-1 text-xs', v.interval_min === n ? 'border-primary bg-accent' : 'text-muted-foreground hover:bg-muted')}>
                  {n === 0 ? '不定时' : n < 60 ? `${n} 分钟` : n < 1440 ? `${n / 60} 小时` : '每天'}
                </button>
              ))}
            </div>
          </Field>
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
