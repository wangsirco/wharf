import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Download, Loader2, RefreshCw } from 'lucide-react'
import { get, post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { refreshBrand } from '@/lib/brand'
import { bytes, datetime } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { Dot, Field, Section, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

type Settings = Record<string, string>
interface AgentStatus { ok: boolean; url: string; error?: string; version?: string; hostname?: string; firewall?: string; time?: number }

const retention = [
  { key: 'retention.audit_days', label: '操作审计保留天数', hint: '审计记录单独保留，不受流量日志清理影响' },
  { key: 'retention.visitor_days', label: '访问记录保留天数' },
  { key: 'retention.traffic_days', label: '流量 / 访问目标日志保留天数', hint: '每小时汇总的流量、访问目标与 DNS 记录；分钟级数据固定保留 48 小时' },
  { key: 'retention.traffic_mb', label: '流量日志最大占用（MB）', hint: '超出后从最早的访问明细开始删除' },
  { key: 'approval.expire_hours', label: '审批有效期（小时）', hint: '超时未处理的申请自动作废' },
  { key: 'presence.away_minutes', label: '离开网络判定（分钟）', hint: '设备连续这么久没有出现在网络中，记为「离开网络」；3-240，太短会让休眠的手机反复上下线' },
]

export default function SettingsPage() {
  const { meta } = useAuth()
  const [s, setS] = useState<Settings | null>(null)
  const [draft, setDraft] = useState<Settings>({})
  const { data: agent, reload: reloadAgent } = useApi<AgentStatus>('/agent/status')
  const [geoBusy, setGeoBusy] = useState(false)
  const [rulesBusy, setRulesBusy] = useState(false)

  useEffect(() => { get<Settings>('/settings').then((r) => { setS(r); setDraft(r) }) }, [])
  if (!s || !meta) return <PageHeader title="系统设置" />

  const required: string[] = JSON.parse(draft['approval.required'] || '[]')
  const toggleApproval = (k: string, on: boolean) =>
    setDraft({ ...draft, 'approval.required': JSON.stringify(on ? [...required, k] : required.filter((x) => x !== k)) })
  const dirty = Object.keys(draft).filter((k) => draft[k] !== s[k])

  const save = async () => {
    try {
      const body = Object.fromEntries(dirty.map((k) => [k, k.startsWith('ui.') ? draft[k].trim() : draft[k]]))
      const r = await put<Settings>('/settings', body)
      setS(r); setDraft(r)
      if (dirty.some((k) => k.startsWith('ui.'))) refreshBrand()
      toast.success('设置已保存')
    } catch (e) { toast.error((e as Error).message) }
  }
  const updateRules = async () => {
    setRulesBusy(true)
    try { const r = await post<{ version: string; updated_at: string }>('/rules/update'); toast.success(`规则库已更新（${r.version}）`); setS((x) => (x ? { ...x, 'rules.updated_at': r.updated_at } : x)) } catch (e) { toast.error((e as Error).message) } finally { setRulesBusy(false) }
  }
  const updateGeo = async () => {
    setGeoBusy(true)
    try { await post('/geo/update'); toast.success('IP 离线库已更新') } catch (e) { toast.error((e as Error).message) } finally { setGeoBusy(false) }
  }

  return (
    <>
      <PageHeader title="系统设置" desc="所有设置的修改都会记入审计，并可还原。">
        <Button size="sm" disabled={!dirty.length} onClick={save}>保存{dirty.length ? `（${dirty.length}）` : ''}</Button>
      </PageHeader>
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title="面板名称" desc="显示在登录页、侧栏、浏览器标签和「添加到主屏幕」的图标名称上">
          <div className="grid gap-4 p-4 sm:grid-cols-2">
            <Field label="名称" hint="最多 24 个字符"><Input maxLength={24} value={draft['ui.name'] ?? ''} placeholder="Wharf" onChange={(e) => setDraft({ ...draft, 'ui.name': e.target.value })} /></Field>
            <Field label="副标题" hint="最多 40 个字符，可留空"><Input maxLength={40} value={draft['ui.subtitle'] ?? ''} placeholder="OpenWrt 控制面板" onChange={(e) => setDraft({ ...draft, 'ui.subtitle': e.target.value })} /></Field>
          </div>
        </Section>
        <Section title="敏感操作二次确认" desc="开启后，普通管理员执行该操作需要超级管理员批准；超级管理员本人不受限制。">
          <div className="divide-y">
            <label className="flex items-center justify-between gap-4 px-4 py-3">
              <span><span className="text-sm">端口转发「允许所有人」</span><span className="block text-xs text-muted-foreground">普通管理员把端口开放给所有来源时需要审批</span></span>
              <Switch checked={draft['approval.forward_open_all'] === '1'} onCheckedChange={(c) => setDraft({ ...draft, 'approval.forward_open_all': c ? '1' : '0' })} />
            </label>
            {meta.actions.map((a) => (
              <label key={a.key} className="flex items-center justify-between gap-4 px-4 py-3">
                <span><span className="text-sm">{a.label}</span><span className="block font-mono text-xs text-muted-foreground">{a.key}</span></span>
                <Switch checked={required.includes(a.key)} onCheckedChange={(c) => toggleApproval(a.key, !!c)} />
              </label>
            ))}
          </div>
        </Section>
        <Section title="日志保留与判定">
          <div className="grid gap-4 p-4 sm:grid-cols-2">
            {retention.map((r) => (
              <Field key={r.key} label={r.label} hint={r.hint}>
                <Input type="number" min={1} value={draft[r.key] ?? ''} onChange={(e) => setDraft({ ...draft, [r.key]: e.target.value })} />
              </Field>
            ))}
          </div>
        </Section>
        <Section title="路由器 Agent" action={<Button variant="ghost" size="sm" onClick={reloadAgent}><RefreshCw /> 检测</Button>}>
          <dl className="grid grid-cols-[7rem_1fr] gap-y-2.5 p-4 text-sm">
            <dt className="text-muted-foreground">状态</dt>
            <dd className="flex items-center gap-2"><Dot tone={agent?.ok ? 'ok' : 'bad'} />{agent ? (agent.ok ? '已连接' : `连接失败：${agent.error}`) : '检测中…'}</dd>
            <dt className="text-muted-foreground">地址</dt><dd className="font-mono text-xs">{agent?.url}</dd>
            {agent?.ok && <>
              <dt className="text-muted-foreground">路由器</dt><dd>{agent.hostname}</dd>
              <dt className="text-muted-foreground">Agent 版本</dt><dd>{agent.version}</dd>
              <dt className="text-muted-foreground">防火墙</dt><dd>{agent.firewall}</dd>
              <dt className="text-muted-foreground">路由器时间</dt><dd className="tabular-nums">{datetime(agent.time ?? 0)}</dd>
            </>}
          </dl>
        </Section>
        <Section title="IP 离线库" desc="DB-IP Lite（City + ASN），每月自动更新，用于访问记录的 ASN / 运营商 / 位置 / 时区判断。">
          <div className="p-4"><Button variant="outline" size="sm" disabled={geoBusy} onClick={updateGeo}><RefreshCw className={geoBusy ? 'animate-spin' : ''} /> 立即更新</Button></div>
        </Section>
        <NextDNSSettings draft={draft} setDraft={setDraft} saved={s} />
        <PVESettings draft={draft} setDraft={setDraft} saved={s} />
        <UpdateSettings draft={draft} setDraft={setDraft} />
        <Section title="内容识别规则库" desc="来自 blackmatrix7/ios_rule_script，另含 AI 等新平台的补充规则，约 290 个服务。程序内置一份，并按下面的间隔自动在线更新。">
          <div className="flex flex-wrap items-end gap-3 p-4">
            <Field label="自动更新间隔">
              <select className="h-8 rounded-lg border bg-transparent px-2 text-sm" value={draft['rules.update_hours'] ?? '72'} onChange={(e) => setDraft({ ...draft, 'rules.update_hours': e.target.value })}>
                {[['0', '不自动更新'], ['6', '每 6 小时'], ['12', '每 12 小时'], ['24', '每天'], ['72', '每 3 天'], ['168', '每周']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            </Field>
            <Button variant="outline" size="sm" disabled={rulesBusy} onClick={updateRules}><RefreshCw className={rulesBusy ? 'animate-spin' : ''} /> 立即更新</Button>
            <span className="pb-1.5 text-xs text-muted-foreground">上次在线更新：{s?.['rules.updated_at'] ? datetime(Number(s['rules.updated_at'])) : '从未（使用内置规则）'}</span>
          </div>
        </Section>
      </div>
    </>
  )
}

function NextDNSSettings({ draft, setDraft, saved }: { draft: Settings; setDraft: (d: Settings) => void; saved: Settings | null }) {
  const [key, setKey] = useState('')
  const [profiles, setProfiles] = useState<{ id: string; name: string }[] | null>(null)
  const [busy, setBusy] = useState(false)
  const test = async () => {
    setBusy(true)
    try {
      const r = await post<{ profiles: { id: string; name: string }[] }>('/nextdns/test', { api_key: key })
      setProfiles(r.profiles)
      toast.success(`连接成功，找到 ${r.profiles.length} 个 profile`)
      if (key) setDraft({ ...draft, 'nextdns.api_key': key })
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <Section title="NextDNS" desc="填写 API Key（NextDNS 后台 → Account → API）后，可查看拦截原因、全网统计与查询记录。Key 只保存在面板数据库中，界面与审计里均打码。">
      <div className="grid gap-4 p-4 sm:grid-cols-2">
        <Field label="API Key" hint={saved?.['nextdns.api_key'] ? `已保存：${saved['nextdns.api_key']}` : '未配置'}>
          <div className="flex gap-2">
            <Input type="password" autoComplete="off" placeholder={saved?.['nextdns.api_key'] ? '留空则保持不变' : '40 位十六进制'} value={key}
              onChange={(e) => { setKey(e.target.value.trim()); if (e.target.value.trim()) setDraft({ ...draft, 'nextdns.api_key': e.target.value.trim() }) }} />
            <Button variant="outline" disabled={busy || (!key && !saved?.['nextdns.api_key'])} onClick={test}>测试</Button>
          </div>
        </Field>
        <Field label="Profile" hint="留空则使用路由器 nextdns 插件当前的 profile">
          {profiles ? (
            <select className="h-8 rounded-lg border bg-transparent px-2 text-sm" value={draft['nextdns.profile'] ?? ''} onChange={(e) => setDraft({ ...draft, 'nextdns.profile': e.target.value })}>
              <option value="">自动（与路由器一致）</option>
              {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}（{p.id}）</option>)}
            </select>
          ) : (
            <Input placeholder="自动" value={draft['nextdns.profile'] ?? ''} onChange={(e) => setDraft({ ...draft, 'nextdns.profile': e.target.value.trim() })} />
          )}
        </Field>
        <Field label="设备 DNS 统计来源" hint="dnsmasq：路由器本地日志（推荐，天然按设备区分）；NextDNS：使用 NextDNS 日志，需先在「DNS」页开启按设备识别">
          <select className="h-8 rounded-lg border bg-transparent px-2 text-sm" value={draft['dns.source'] ?? 'dnsmasq'} onChange={(e) => setDraft({ ...draft, 'dns.source': e.target.value })}>
            <option value="dnsmasq">路由器 dnsmasq 日志</option>
            <option value="nextdns">NextDNS 日志</option>
          </select>
        </Field>
      </div>
    </Section>
  )
}

interface PVEGuest { vmid: number; name: string; node: string; kind: string; status: string }

function PVESettings({ draft, setDraft, saved }: { draft: Settings; setDraft: (d: Settings) => void; saved: Settings | null }) {
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [guests, setGuests] = useState<PVEGuest[] | null>(null)
  const { data: st } = useApi<{ configured: boolean; macs: number; updated: number; error?: string }>('/pve/status', 60000)
  const test = async () => {
    setBusy(true)
    try {
      const r = await post<{ fingerprint: string; guests: PVEGuest[] | null; total: number }>('/pve/test', { url: draft['pve.url'] ?? '', token })
      setGuests(r.guests ?? [])
      setDraft({ ...draft, ...(token ? { 'pve.token': token } : {}), 'pve.fingerprint': r.fingerprint })
      toast.success(`连接成功：${r.total} 台虚拟机 / 容器，已记录证书指纹，保存后生效`)
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const fp = draft['pve.fingerprint'] ?? ''
  return (
    <Section title="Proxmox VE（可选）" desc="连接 PVE 后，虚拟机即使没有通过 DHCP 上报主机名，也能显示它在 PVE 里的名称，并标注「PVE 虚拟机 #编号」。只需要只读权限。">
      <div className="grid gap-4 p-4 sm:grid-cols-2">
        <Field label="PVE 地址" hint="例如 https://192.168.1.64:8006">
          <Input placeholder="https://主机:8006" value={draft['pve.url'] ?? ''} onChange={(e) => setDraft({ ...draft, 'pve.url': e.target.value.trim() })} />
        </Field>
        <Field label="API Token" hint={saved?.['pve.token'] ? `已保存：${saved['pve.token']}` : 'PVE → 数据中心 → 权限 → API 令牌；给它 PVEAuditor 角色'}>
          <div className="flex gap-2">
            <Input type="password" autoComplete="off" placeholder={saved?.['pve.token'] ? '留空则保持不变' : '用户@pve!令牌名=UUID'} value={token} onChange={(e) => setToken(e.target.value.trim())} />
            <Button variant="outline" disabled={busy || !draft['pve.url'] || (!token && !saved?.['pve.token'])} onClick={test}>测试</Button>
          </div>
        </Field>
        <div className="grid gap-1 text-xs text-muted-foreground sm:col-span-2">
          {fp && <div className="break-all">证书指纹（SHA-256，已固定）：<span className="font-mono">{fp}</span></div>}
          {st?.configured && <div>{st.error ? <span className="text-destructive">上次同步失败：{st.error}</span> : `已同步 ${st.macs} 个虚拟网卡 · ${st.updated ? datetime(st.updated) : ''}`}，每 10 分钟刷新</div>}
          {guests && <div className="flex flex-wrap gap-1.5 pt-1">{guests.sort((a, b) => a.vmid - b.vmid).map((g) => <span key={g.vmid} className="rounded-md bg-muted px-1.5 py-0.5">#{g.vmid} {g.name}{g.kind === 'lxc' ? '（容器）' : ''}</span>)}</div>}
        </div>
      </div>
    </Section>
  )
}

interface UpdComp { id: string; name: string; desc: string; current: string; latest?: string; update: boolean; size?: number; auto?: boolean; note?: string }
interface UpdateInfo {
  current: string; web_version: string; repo: string; latest?: string; newer: boolean; url?: string; notes?: string; published?: number; checked?: number
  error?: string; signed: boolean; arch?: string; components: UpdComp[] | null; download: number
}
interface CoreJob { running: boolean; done: boolean; ok: boolean; log: string[] | null; started: number }

function UpdateSettings({ draft, setDraft }: { draft: Settings; setDraft: (d: Settings) => void }) {
  const { data, reload } = useApi<UpdateInfo>('/update')
  const [busy, setBusy] = useState(false)
  const [applying, setApplying] = useState<'core' | 'web' | null>(null)
  const [job, setJob] = useState<CoreJob | null>(null)
  const { confirm, dialog } = useConfirm()
  const check = async () => {
    setBusy(true)
    try { const r = await post<UpdateInfo>('/update/check'); if (r.error && !r.signed) toast.error(r.error); else toast.success(r.newer ? `发现新版本 ${r.latest}` : '已是最新版本'); reload() }
    catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  // follow a program update through the service restart, then reload the page
  useEffect(() => {
    if (applying !== 'core') return
    const from = data?.current
    let gone = false
    const t = setInterval(async () => {
      try {
        const st = await get<{ core: CoreJob; current: string }>('/update/status')
        setJob(st.core)
        if (st.current !== from || (gone && st.core.done)) {
          clearInterval(t)
          if (st.core.done && !st.core.ok) { toast.error('更新失败，详见日志'); setApplying(null); return }
          toast.success(`已更新到 ${st.current}，正在刷新页面`)
          setTimeout(() => location.reload(), 1500)
        }
      } catch { gone = true } // the panel is restarting
    }, 2000)
    return () => clearInterval(t)
  }, [applying]) // eslint-disable-line react-hooks/exhaustive-deps

  const apply = async () => {
    const core = data?.components?.find((c) => c.id === 'core' && c.update)
    if (!(await confirm(`更新到 ${data?.latest}？`, core
      ? `将下载 ${bytes(data?.download ?? 0)} 的安装包并通过 opkg 安装。面板和 agent 会重启约 10 秒，期间页面暂时无法访问，家里的网络不受影响。`
      : `只更新网页界面（${bytes(data?.download ?? 0)}），不需要重启，完成后刷新页面即可。`, { ok: '开始更新' }))) return
    setApplying(core ? 'core' : 'web')
    try {
      const r = await post<{ core?: boolean; web?: boolean; version?: string }>('/update/apply')
      if (r.web) { toast.success(`网页界面已更新到 ${r.version}，正在刷新`); setTimeout(() => location.reload(), 1200) }
    } catch (e) { toast.error((e as Error).message); setApplying(null) }
  }
  const rollback = async () => {
    if (!(await confirm('恢复为程序内置的网页界面？', `当前界面 ${data?.web_version}，恢复后为 ${data?.current}。`, { ok: '恢复' }))) return
    try { await post('/update/rollback-web'); location.reload() } catch (e) { toast.error((e as Error).message) }
  }
  const comps = data?.components ?? []
  return (
    <Section title="版本与更新" desc="从 GitHub Release 获取更新。只更新有变化的组件：网页界面可以单独热更新，程序核心通过 opkg 安装；每个更新都校验签名">
      <div id="update" className="grid gap-4 p-4">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          当前版本 <span className="font-mono">{data?.current ?? '…'}</span>
          {data && data.web_version !== data.current && <span className="text-xs text-muted-foreground">（网页界面 {data.web_version}）</span>}
          {data?.newer && <span className="rounded-full bg-success/12 px-2 py-0.5 text-xs font-medium text-success">可更新到 {data.latest}</span>}
          {data && !data.newer && data.latest && <span className="text-xs text-muted-foreground">已是最新（GitHub 最新 {data.latest}）</span>}
          <Button variant="outline" size="sm" className="ml-auto" disabled={busy || !!applying} onClick={check}><RefreshCw /> 立即检查</Button>
        </div>
        {comps.length > 0 && (
          <div className="divide-y rounded-xl border">
            {comps.map((c) => (
              <div key={c.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-sm">
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{c.name}</div>
                  <div className="text-xs text-muted-foreground">{c.desc}</div>
                </div>
                <div className="text-right text-xs">
                  <div className="font-mono text-muted-foreground">{c.current}{c.latest && c.update ? <> → <span className="text-foreground">{c.latest}</span></> : null}</div>
                  {c.auto ? <span className="text-muted-foreground">{c.note}</span>
                    : c.update ? <span className="font-medium text-success">需要更新{c.size ? ` · ${bytes(c.size)}` : ''}</span>
                    : <span className="text-muted-foreground">{c.note || (data?.signed ? '已是最新' : '—')}</span>}
                  {c.update && c.note && <div className="text-muted-foreground">{c.note}</div>}
                </div>
              </div>
            ))}
          </div>
        )}
        {data?.newer && data.signed && (
          <div className="flex flex-wrap items-center gap-3">
            <Button disabled={!!applying} onClick={apply}>{applying ? <Loader2 className="animate-spin" /> : <Download />} {applying ? '正在更新…' : `更新到 ${data.latest}（下载 ${bytes(data.download)}）`}</Button>
            {data.url && <a className="text-xs text-primary hover:underline" href={data.url} target="_blank" rel="noreferrer">更新说明 →</a>}
          </div>
        )}
        {job && (applying === 'core' || job.running) && <pre className="max-h-48 overflow-auto rounded-lg bg-muted/60 p-2.5 font-mono text-[11px] text-muted-foreground">{(job.log ?? []).join('\n') || '准备中…'}</pre>}
        {data?.newer && data.notes && <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-lg border bg-muted/30 p-3 font-sans text-xs text-muted-foreground">{data.notes}</pre>}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="更新源仓库" hint="GitHub 的「用户名/仓库名」；默认 wangsirco/wharf">
            <Input value={draft['update.repo'] ?? ''} placeholder="wangsirco/wharf" onChange={(e) => setDraft({ ...draft, 'update.repo': e.target.value.trim() })} />
          </Field>
          <label className="flex items-center justify-between gap-3 self-end rounded-lg border px-3 py-2 text-sm">
            每 12 小时自动检查
            <Switch checked={(draft['update.check'] ?? '1') === '1'} onCheckedChange={(v) => setDraft({ ...draft, 'update.check': v ? '1' : '0' })} />
          </label>
        </div>
        {data?.error && <p className="text-xs text-muted-foreground">上次检查：{data.error}</p>}
        {data && data.web_version !== data.current && <button type="button" className="justify-self-start text-xs text-muted-foreground hover:text-foreground" onClick={rollback}>网页界面有问题？恢复为程序内置版本</button>}
        <p className="text-[11px] text-muted-foreground">只会下载经过发布者签名的更新；IP 库和规则库一直是各自自动更新的。</p>
      </div>
      {dialog}
    </Section>
  )
}
