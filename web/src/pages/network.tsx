import { useState } from 'react'
import { toast } from 'sonner'
import { Activity, Gauge, Globe, Loader2, Server, Unplug, Wifi } from 'lucide-react'
import { post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import type { NetworkResp, SpeedRow } from '@/lib/types'
import { datetime, duration } from '@/lib/format'
import { publicNow, quality, targetLabel } from '@/lib/net'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Empty, Pill, Section } from '@/components/common'
import { AreaChart } from '@/components/chart'
import { Kpi } from '@/components/monitor'
import { PALETTE } from '@/components/charts'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

const RANGES: [string, string][] = [['1h', '1 小时'], ['24h', '24 小时'], ['7d', '7 天'], ['30d', '30 天']]

export default function Network() {
  const [range, setRange] = useState('24h')
  const { data, reload } = useApi<NetworkResp>(`/network?range=${range}`, 30000)
  const [testing, setTesting] = useState(false)
  const [engine, setEngine] = useState<'cloudflare' | 'ookla'>('cloudflare')
  const [last, setLast] = useState<SpeedRow | null>(null)
  const wan = data?.wan?.wan
  const targets = data?.targets ?? []
  const now = publicNow(targets, wan?.gateway)
  const q = quality(now.ms, now.loss)
  const outages = data?.outages ?? []
  const lastSpeed = last ?? data?.speedtests?.[0]
  const times = targets[0]?.points?.map((p) => p.t) ?? []

  const speedtest = async () => {
    setTesting(true)
    try {
      const r = await post<SpeedRow>(`/network/speedtest?engine=${engine}`)
      if (r.error) toast.error(r.error); else toast.success(`下载 ${r.down_mbps} Mbps · 上传 ${r.up_mbps} Mbps`)
      setLast(r); reload()
    } catch (e) { toast.error((e as Error).message) } finally { setTesting(false) }
  }

  // availability strip: worst loss across public targets per bucket
  const strip = times.map((t, i) => {
    const losses = targets.filter((x) => x.target !== wan?.gateway).map((x) => x.points?.[i]?.loss ?? 0)
    return { t, loss: losses.length ? Math.min(...losses) : 0 }
  })

  return (
    <>
      <PageHeader title="网络" desc="WAN 状态、延迟与丢包（每 10 秒检测一次）、掉线记录和测速">
        <Tabs value={range} onValueChange={(v) => setRange(String(v))}>
          <TabsList>{RANGES.map(([k, l]) => <TabsTrigger key={k} value={k}>{l}</TabsTrigger>)}</TabsList>
        </Tabs>
      </PageHeader>
      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <Kpi icon={Wifi} label="网络质量" value={<span>{q.label}</span>} tone={q.tone === 'green' ? 'green' : q.tone} sub={now.ms ? `当前延迟 ${now.ms} ms` : '公网不可达'} />
        <Kpi icon={Activity} label="丢包率" value={`${now.loss}%`} sub={`${RANGES.find(([k]) => k === range)?.[1]}内最好线路`} tone={now.loss >= 1 ? 'amber' : undefined} />
        <Kpi icon={Unplug} label="断网" value={outages.length ? `${outages.length} 次` : '无'} tone={outages.length ? 'red' : 'green'}
          sub={outages.length ? `共 ${outages.reduce((a, o) => a + o.minutes, 0)} 分钟` : `WAN 已在线 ${wan ? duration(wan.uptime) : '–'}`} />
        <Kpi icon={Gauge} label="最近测速" value={lastSpeed && !lastSpeed.error ? `${lastSpeed.down_mbps} Mbps` : '–'}
          sub={lastSpeed && !lastSpeed.error ? `上传 ${lastSpeed.up_mbps} Mbps · ${datetime(lastSpeed.ts).slice(5, 16)}` : '还没有测速'} />
      </div>

      <div className="mt-4 grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="grid gap-4">
          <Section title="延迟" desc={`各检测目标的平均延迟（ms）${data?.silent?.length ? ` · ${data.silent.map((t) => (t === wan?.gateway ? '运营商网关' : t)).join('、')} 不响应 ping（常见，不影响上网），已隐藏` : ''}`}>
            <div className="p-4">
              <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
                {targets.map((t, i) => (
                  <span key={t.target} className="flex items-center gap-1.5">
                    <span className="size-2 rounded-full" style={{ background: PALETTE[i % PALETTE.length] }} />
                    {targetLabel(t.target, wan?.gateway)}<span className="text-muted-foreground">平均 {t.avg} ms · 丢包 {t.loss}%</span>
                  </span>
                ))}
              </div>
              {targets.length ? (
                <AreaChart height={220} times={times} format={(v) => `${v.toFixed(0)} ms`}
                  series={targets.map((t, i) => ({ label: targetLabel(t.target, wan?.gateway), color: PALETTE[i % PALETTE.length], values: (t.points ?? []).map((p) => p.avg) }))} />
              ) : <Empty>正在采集，几分钟后出现数据</Empty>}
            </div>
          </Section>
          <Section title="可用性" desc="绿色正常，黄色有丢包，红色断网">
            <div className="p-4">
              <div className="flex h-8 gap-px overflow-hidden rounded-md">
                {strip.map((s) => (
                  <div key={s.t} title={`${datetime(s.t)} · 丢包 ${s.loss}%`} className={cn('flex-1', s.loss >= 50 ? 'bg-destructive' : s.loss > 0 ? 'bg-warning' : 'bg-success/70')} />
                ))}
                {!strip.length && <div className="flex-1 bg-muted" />}
              </div>
              {strip.length > 0 && <div className="mt-1 flex justify-between text-[10px] text-muted-foreground"><span>{datetime(strip[0].t).slice(5, 16)}</span><span>{datetime(strip[strip.length - 1].t).slice(5, 16)}</span></div>}
            </div>
          </Section>
          <Section title="掉线与重连记录">
            <Table>
              <TableHeader><TableRow><TableHead className="pl-4">时间</TableHead><TableHead>事件</TableHead><TableHead className="pr-4">说明</TableHead></TableRow></TableHeader>
              <TableBody>
                {[...outages.map((o) => ({ ts: o.from, kind: 'outage', detail: `所有检测目标不可达，持续约 ${o.minutes} 分钟` })), ...(data?.events ?? [])]
                  .sort((a, b) => b.ts - a.ts).map((e, i) => (
                    <TableRow key={i}>
                      <TableCell className="whitespace-nowrap pl-4 text-xs tabular-nums">{datetime(e.ts)}</TableCell>
                      <TableCell><Pill tone={e.kind === 'up' ? 'green' : e.kind === 'reconnect' ? 'amber' : 'red'}>{{ outage: '断网', down: 'WAN 断开', up: 'WAN 恢复', reconnect: '重新拨号' }[e.kind] ?? e.kind}</Pill></TableCell>
                      <TableCell className="pr-4 text-sm text-muted-foreground">{e.detail}</TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
            {!outages.length && !data?.events?.length && <Empty>这段时间网络一直正常</Empty>}
          </Section>
        </div>

        <div className="grid gap-4">
          <Section title="WAN" action={wan && <Pill tone={wan.up ? 'green' : 'red'}>{wan.up ? '在线' : '离线'}</Pill>}>
            {wan ? (
              <dl className="grid grid-cols-[5.5rem_1fr] gap-y-2 p-4 text-sm">
                <dt className="text-muted-foreground"><Globe className="mr-1 inline size-3.5" />公网 IP</dt><dd className="font-mono">{wan.ipv4 || '—'}</dd>
                <dt className="text-muted-foreground">网关</dt><dd className="font-mono">{wan.gateway || '—'}</dd>
                <dt className="text-muted-foreground">方式</dt><dd>{{ dhcp: 'DHCP 自动获取', pppoe: 'PPPoE 拨号', static: '静态 IP' }[wan.proto] ?? wan.proto} · {wan.device}</dd>
                <dt className="text-muted-foreground">在线时长</dt><dd>{duration(wan.uptime)}</dd>
                <dt className="text-muted-foreground"><Server className="mr-1 inline size-3.5" />DNS</dt><dd className="font-mono text-xs">{wan.dns?.join('、') || '—'}</dd>
                <dt className="text-muted-foreground">IPv6</dt><dd className="font-mono text-xs">{data?.wan?.wan6?.ipv6?.join('、') || wan.ipv6?.join('、') || '未获取'}</dd>
              </dl>
            ) : <Empty>无法读取 WAN 状态</Empty>}
          </Section>
          <Section title="测速" desc="由路由器发起，约 20～30 秒，会短暂占满带宽">
            <div className="grid gap-4 p-4">
              <Tabs value={engine} onValueChange={(v) => setEngine(v as 'cloudflare' | 'ookla')}>
                <TabsList className="w-full"><TabsTrigger value="cloudflare">Cloudflare</TabsTrigger><TabsTrigger value="ookla">Speedtest.net</TabsTrigger></TabsList>
              </Tabs>
              <Button disabled={testing} onClick={speedtest}>{testing ? <><Loader2 className="animate-spin" /> 测速中…</> : <><Gauge /> 开始测速</>}</Button>
              {lastSpeed && !lastSpeed.error && (
                <div className="grid grid-cols-3 gap-2 text-center">
                  <div><div className="text-xs text-muted-foreground">下载</div><div className="text-xl font-semibold tabular-nums">{lastSpeed.down_mbps}</div><div className="text-[10px] text-muted-foreground">Mbps</div></div>
                  <div><div className="text-xs text-muted-foreground">上传</div><div className="text-xl font-semibold tabular-nums">{lastSpeed.up_mbps}</div><div className="text-[10px] text-muted-foreground">Mbps</div></div>
                  <div><div className="text-xs text-muted-foreground">延迟</div><div className="text-xl font-semibold tabular-nums">{lastSpeed.latency_ms}</div><div className="text-[10px] text-muted-foreground">ms</div></div>
                  <div className="col-span-3 truncate text-[11px] text-muted-foreground">{lastSpeed.server}</div>
                </div>
              )}
              {(data?.speedtests?.length ?? 0) > 0 && (
                <div className="grid gap-1 text-xs">
                  <div className="text-muted-foreground">历史</div>
                  {data!.speedtests!.map((s, i) => (
                    <div key={i} className="flex justify-between tabular-nums">
                      <span className="text-muted-foreground">{datetime(s.ts).slice(5, 16)}</span>
                      <span title={s.server}>{s.error ? <span className="text-destructive">{s.error}</span> : `${s.server.startsWith('Speedtest') ? 'Ookla' : 'CF'} · ↓ ${s.down_mbps} · ↑ ${s.up_mbps} Mbps · ${s.latency_ms} ms`}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Section>
        </div>
      </div>
    </>
  )
}
