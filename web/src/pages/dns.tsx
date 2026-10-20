import { useState } from 'react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { Search, ShieldAlert, ShieldCheck } from 'lucide-react'
import { post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { datetime } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { Empty, ErrorBox, Pill, Section, useConfirm } from '@/components/common'
import { Donut } from '@/components/charts'
import { Kpi } from '@/components/monitor'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

interface Named { id?: string; name?: string; domain?: string; root?: string; queries: number; status?: string; model?: string }
interface Summary {
  configured: boolean; error?: string; profile?: string; range?: string; per_device?: boolean
  status?: Named[]; domains?: Named[]; blocked?: Named[]; reasons?: Named[]; devices?: Named[]; protocols?: { protocol: string; queries: number }[]
  destinations?: Named[]; series?: { status: string; queries: number[] }[]; series_meta?: { series?: { times?: string[] } }
}
interface NdLog { timestamp: string; domain: string; root?: string; status: string; device?: { name: string }; clientIp?: string; reasons?: { name: string }[]; tracker?: string }

const STATUS: Record<string, string> = { default: '正常解析', blocked: '已拦截', allowed: '白名单放行', relayed: '中继', error: '错误' }

function TopList({ items, label, tone }: { items?: Named[]; label: (x: Named) => string; tone?: 'red' }) {
  if (!items?.length) return <Empty>暂无数据</Empty>
  const max = Math.max(...items.map((x) => x.queries))
  return (
    <div className="grid gap-1.5 p-4">
      {items.map((x, i) => (
        <div key={i} className="grid grid-cols-[1fr_auto] items-center gap-3 text-sm">
          <div className="min-w-0">
            <div className="truncate font-mono text-xs">{label(x)}</div>
            <div className="mt-1 h-1 rounded-full bg-muted"><div className={tone === 'red' ? 'h-1 rounded-full bg-destructive/70' : 'h-1 rounded-full bg-primary'} style={{ width: `${(x.queries / max) * 100}%` }} /></div>
          </div>
          <span className="tabular-nums text-muted-foreground">{x.queries.toLocaleString()}</span>
        </div>
      ))}
    </div>
  )
}

export default function DNS() {
  const [range, setRange] = useState('1d')
  const { data, reload } = useApi<Summary>(`/nextdns/summary?range=${range}`, 60000)
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('blocked')
  const { data: logs, error: logErr } = useApi<{ data: NdLog[] }>(`/nextdns/logs?status=${status === 'all' ? '' : status}&search=${encodeURIComponent(q)}`, 30000)
  const { isSuper } = useAuth()
  const { confirm, dialog } = useConfirm()

  if (data && !data.configured) {
    return (
      <>
        <PageHeader title="DNS 与 NextDNS" />
        <div className="rounded-xl border bg-card p-6 text-sm">
          <p>尚未连接 NextDNS。{data.error}</p>
          {isSuper ? <p className="mt-2"><Link to="/settings" className="text-primary underline">前往「系统设置 → NextDNS」</Link>填写 API Key。</p> : <p className="mt-2 text-muted-foreground">请联系超级管理员配置。</p>}
          <p className="mt-2 text-muted-foreground">未连接时，各设备的 DNS 请求仍会通过路由器本地的 dnsmasq 日志统计（见设备详情 → 设备画像）。</p>
        </div>
      </>
    )
  }
  const st: Record<string, number> = Object.fromEntries((data?.status ?? []).map((s) => [s.status ?? '', s.queries]))
  const total = Object.values(st).reduce((a, b) => a + b, 0)
  const blocked = st.blocked ?? 0
  const times = data?.series_meta?.series?.times ?? []
  const ser = (name: string) => data?.series?.find((s) => s.status === name)?.queries ?? []
  const sDef = ser('default'), sBlk = ser('blocked')
  const smax = Math.max(1, ...times.map((_, i) => (sDef[i] ?? 0) + (sBlk[i] ?? 0)))
  const togglePerDevice = async () => {
    const on = !data?.per_device
    if (!(await confirm(on ? '让 NextDNS 识别每台设备？' : '关闭按设备识别？', on ? '将为 dnsmasq 开启 add-mac，NextDNS 后台与 App 里就能看到每台设备的查询。dnsmasq 会重启一次（DNS 中断约 1 秒）。' : 'dnsmasq 会重启一次（DNS 中断约 1 秒）。', { ok: on ? '开启' : '关闭' }))) return
    try { await post('/nextdns/per-device', { enable: on }); toast.success('已应用'); reload() } catch (e) { toast.error((e as Error).message) }
  }

  return (
    <>
      <PageHeader title="DNS 与 NextDNS" desc={`NextDNS profile ${data?.profile ?? ''} · 拦截原因、全网查询统计与最近记录`}>
        <Tabs value={range} onValueChange={(v) => setRange(String(v))}>
          <TabsList><TabsTrigger value="1h">1 小时</TabsTrigger><TabsTrigger value="1d">24 小时</TabsTrigger><TabsTrigger value="7d">7 天</TabsTrigger><TabsTrigger value="30d">30 天</TabsTrigger></TabsList>
        </Tabs>
      </PageHeader>
      {data?.error && <div className="mb-4"><ErrorBox>{data.error}</ErrorBox></div>}
      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <Kpi icon={ShieldCheck} label="查询总数" value={total.toLocaleString()} />
        <Kpi icon={ShieldAlert} label="已拦截" value={blocked.toLocaleString()} sub={total ? `占 ${((blocked / total) * 100).toFixed(1)}%` : ''} tone="red" />
        <Kpi icon={ShieldCheck} label="白名单放行" value={(st.allowed ?? 0).toLocaleString()} />
        <div className="rounded-xl border bg-card p-4 text-sm">
          <div className="text-xs text-muted-foreground">按设备识别</div>
          <div className="mt-1.5 font-medium">{data?.per_device ? '已开启' : '未开启（NextDNS 只看到路由器）'}</div>
          {isSuper && <Button variant="outline" size="xs" className="mt-2" onClick={togglePerDevice}>{data?.per_device ? '关闭' : '开启'}</Button>}
        </div>
      </div>

      {times.length > 0 && (
        <Section title="查询趋势" className="mt-4" action={<div className="flex gap-3 text-xs"><span className="flex items-center gap-1"><span className="size-2 rounded-full bg-primary" />正常</span><span className="flex items-center gap-1"><span className="size-2 rounded-full bg-destructive" />拦截</span></div>}>
          <div className="flex h-40 items-end gap-px p-4">
            {times.map((t, i) => (
              <div key={t} title={`${datetime(Date.parse(t) / 1000)} · 正常 ${sDef[i] ?? 0} · 拦截 ${sBlk[i] ?? 0}`} className="flex h-full flex-1 flex-col justify-end">
                <div className="bg-destructive/70" style={{ height: `${((sBlk[i] ?? 0) / smax) * 100}%` }} />
                <div className="rounded-t-[2px] bg-primary/80" style={{ height: `${((sDef[i] ?? 0) / smax) * 100}%` }} />
              </div>
            ))}
          </div>
        </Section>
      )}

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Section title="拦截原因"><div className="p-4"><Donut data={(data?.reasons ?? []).map((r) => ({ name: r.name ?? r.id ?? '', value: r.queries }))} format={(v) => v.toLocaleString()} size={160} /></div></Section>
        <Section title="被拦截最多的域名"><TopList items={data?.blocked} label={(x) => x.domain ?? ''} tone="red" /></Section>
        <Section title="查询最多的域名"><TopList items={data?.domains} label={(x) => x.domain ?? ''} /></Section>
        <Section title="设备（NextDNS 视角）"><TopList items={data?.devices} label={(x) => `${x.name ?? x.id}${x.model ? ` · ${x.model}` : ''}`} /></Section>
        <Section title="解析去向国家"><TopList items={data?.destinations} label={(x) => x.name ?? x.id ?? ''} /></Section>
        <Section title="协议"><div className="grid gap-1.5 p-4 text-sm">{data?.protocols?.map((p) => <div key={p.protocol} className="flex justify-between"><span>{p.protocol}</span><span className="tabular-nums text-muted-foreground">{p.queries.toLocaleString()}</span></div>)}</div></Section>
      </div>

      <Section title="最近的查询记录" className="mt-4" action={
        <div className="flex items-center gap-2">
          <Tabs value={status} onValueChange={(v) => setStatus(String(v))}>
            <TabsList><TabsTrigger value="blocked">已拦截</TabsTrigger><TabsTrigger value="all">全部</TabsTrigger></TabsList>
          </Tabs>
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="搜索域名" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-44 pl-8" />
          </div>
        </div>
      }>
        {logErr && <div className="p-4"><ErrorBox>{logErr}</ErrorBox></div>}
        <Table>
          <TableHeader><TableRow><TableHead className="pl-4">时间</TableHead><TableHead>域名</TableHead><TableHead>状态</TableHead><TableHead>原因</TableHead><TableHead className="pr-4">设备</TableHead></TableRow></TableHeader>
          <TableBody>
            {logs?.data?.map((l, i) => (
              <TableRow key={i}>
                <TableCell className="whitespace-nowrap pl-4 text-xs tabular-nums text-muted-foreground">{datetime(Date.parse(l.timestamp) / 1000)}</TableCell>
                <TableCell className="max-w-80 truncate font-mono text-xs">{l.domain}{l.tracker && <span className="ml-1 text-[10px] text-muted-foreground">追踪器 {l.tracker}</span>}</TableCell>
                <TableCell><Pill tone={l.status === 'blocked' ? 'red' : l.status === 'allowed' ? 'green' : 'muted'}>{STATUS[l.status] ?? l.status}</Pill></TableCell>
                <TableCell className="max-w-64 truncate text-xs text-muted-foreground">{l.reasons?.map((r) => r.name).join('、') || '—'}</TableCell>
                <TableCell className="pr-4 text-xs text-muted-foreground">{l.device?.name ?? l.clientIp}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {logs && !logs.data?.length && <Empty>没有记录</Empty>}
      </Section>
      {dialog}
    </>
  )
}
