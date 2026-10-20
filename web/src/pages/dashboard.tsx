import { useNavigate } from 'react-router-dom'
import { ArrowDown, Ban, ClipboardCheck, Cpu, Database, MemoryStick, Monitor, MonitorSmartphone, Network, ShieldAlert } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { bitrate, bytes, duration } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { ErrorBox, Section } from '@/components/common'
import { EventsFeed, Kpi, LiveDevices, ServicesToday, useOverview, useWan, WanChart } from '@/components/monitor'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

export default function Dashboard() {
  const { sys, rate, hist } = useWan()
  const { data: ov } = useOverview()
  const { can, isSuper } = useAuth()
  const navigate = useNavigate()

  if (!sys) return <><PageHeader title="概览" /><div className="grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-24 rounded-xl" />)}</div></>
  const memUsed = sys.mem_total - sys.mem_available
  const dv = ov?.devices
  const today = ov?.today
  const blockedPct = today && today.dns_requests ? (today.dns_blocked / (today.dns_requests + today.dns_blocked)) * 100 : 0

  return (
    <>
      <PageHeader title="概览" desc={`${sys.hostname} · ${sys.release} · 已运行 ${duration(sys.uptime)}`}>
        <Button variant="outline" size="sm" onClick={() => navigate('/screen')}><Monitor /> 大屏模式</Button>
      </PageHeader>
      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-3 2xl:grid-cols-6">
        <Kpi icon={ArrowDown} label="WAN 下行" value={bitrate(rate.rx)} sub={`上行 ${bitrate(rate.tx)}`} />
        <Kpi icon={MonitorSmartphone} label="在线设备" value={dv ? `${dv.online}` : '–'} sub={dv ? `共 ${dv.total} 台${dv.new_24h ? ` · 新接入 ${dv.new_24h}` : ''}` : ''}
          tone={dv?.new_24h ? 'amber' : undefined} onClick={() => navigate('/devices')} />
        <Kpi icon={Database} label="今日流量" value={today ? bytes(today.up + today.down) : '–'} sub={today ? `↓ ${bytes(today.down)} · ↑ ${bytes(today.up)}` : ''}
          onClick={can('traffic.view') ? () => navigate('/traffic') : undefined} />
        <Kpi icon={ShieldAlert} label="今日 DNS 拦截" value={today ? today.dns_blocked.toLocaleString() : '–'} sub={today ? `占 ${blockedPct.toFixed(1)}% · 共 ${today.dns_requests.toLocaleString()} 次查询` : ''}
          onClick={can('traffic.view') ? () => navigate('/dns') : undefined} />
        <Kpi icon={Ban} label="被管控设备" value={dv ? `${dv.controlled}` : '–'} sub={dv?.blocked ? `${dv.blocked} 台正在断网` : '无设备断网'}
          tone={dv?.blocked ? 'red' : undefined} onClick={can('access.manage') ? () => navigate('/controls') : undefined} />
        {isSuper ? (
          <Kpi icon={ClipboardCheck} label="待审批" value={ov?.approvals_pending ?? '–'} sub={ov?.visitors_denied_24h ? `24 小时拒绝访问 ${ov.visitors_denied_24h} 次` : '无异常访问'}
            tone={ov?.approvals_pending ? 'red' : undefined} onClick={() => navigate('/approvals')} />
        ) : (
          <Kpi icon={Cpu} label="负载" value={sys.load[0].toFixed(2)} sub={`内存 ${((memUsed / sys.mem_total) * 100).toFixed(0)}%`} />
        )}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Section title="WAN 实时流量" desc="每 2 秒刷新，最近 5 分钟" className="xl:col-span-2" action={
          <div className="flex gap-4 text-xs">
            <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-chart-1" />下行 {bitrate(rate.rx)}</span>
            <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-chart-2" />上行 {bitrate(rate.tx)}</span>
          </div>
        }>
          <div className="px-4 pb-3 pt-4"><WanChart hist={hist} height={220} /></div>
        </Section>
        <Section title="正在用网的设备" desc="按当前网速排序，点击查看详情">
          {can('devices.view') ? <LiveDevices limit={7} /> : <div className="p-4 text-sm text-muted-foreground">没有查看设备的权限</div>}
        </Section>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        {can('traffic.view') && (
          <Section title="今日流量去向" className="xl:col-span-2">
            <div className="p-4"><ServicesToday data={ov ?? null} /></div>
          </Section>
        )}
        <Section title="最近事件" desc="新设备、断网、定时、拒绝访问、审批" className={can('traffic.view') ? '' : 'xl:col-span-3'}>
          <div className="max-h-[360px] overflow-y-auto"><EventsFeed limit={20} /></div>
        </Section>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Section title="系统">
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2.5 p-4 text-sm">
            <dt className="text-muted-foreground">型号</dt><dd className="truncate">{sys.model}</dd>
            <dt className="text-muted-foreground">内核 / 防火墙</dt><dd>{sys.kernel} · {sys.firewall}</dd>
            <dt className="text-muted-foreground"><Cpu className="mr-1 inline size-3.5" />负载</dt><dd className="tabular-nums">{sys.load.map((l) => l.toFixed(2)).join(' / ')}</dd>
            <dt className="text-muted-foreground"><MemoryStick className="mr-1 inline size-3.5" />内存</dt><dd className="tabular-nums">{bytes(memUsed)} / {bytes(sys.mem_total)}</dd>
            <dt className="text-muted-foreground"><Network className="mr-1 inline size-3.5" />连接数</dt><dd className="tabular-nums">{sys.conntrack.toLocaleString()} / {sys.conntrack_max.toLocaleString()}</dd>
          </dl>
        </Section>
        <Section title="网络接口" className="xl:col-span-2">
          <Table>
            <TableHeader><TableRow><TableHead className="pl-4">接口</TableHead><TableHead className="text-right">累计入站</TableHead><TableHead className="pr-4 text-right">累计出站</TableHead></TableRow></TableHeader>
            <TableBody>
              {sys.ifaces.filter((i) => i.name !== 'lo' && (i.rx_bytes > 0 || i.tx_bytes > 0)).map((i) => (
                <TableRow key={i.name}>
                  <TableCell className="pl-4 font-medium">{i.name}{i.name === sys.wan_ifname && <span className="ml-2 text-[11px] text-primary">WAN</span>}{i.name === sys.lan_ifname && <span className="ml-2 text-[11px] text-success">LAN</span>}</TableCell>
                  <TableCell className="text-right tabular-nums text-muted-foreground">{bytes(i.rx_bytes)}</TableCell>
                  <TableCell className="pr-4 text-right tabular-nums text-muted-foreground">{bytes(i.tx_bytes)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Section>
      </div>
    </>
  )
}

export function DashboardError({ error }: { error: string }) { return <ErrorBox>{error}</ErrorBox> }
