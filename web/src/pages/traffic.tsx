import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowDown, ArrowUp, Database, MonitorSmartphone } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import type { Agg } from '@/lib/types'
import { bytes, datetime } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { DepHint } from '@/components/deps'
import { Empty, ErrorBox, Section } from '@/components/common'
import { Bars, LevelDonut, presetRange, RangePicker, type Range } from '@/components/charts'
import { DeviceIcon } from '@/components/device-icon'
import { Kpi } from '@/components/monitor'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

interface Overview {
  up: number; down: number; services: Agg[] | null; categories: Agg[] | null; step: number
  series: { t: number; up: number; down: number }[] | null
  devices: { mac: string; name: string; ip: string; type: string; up: number; down: number; last_seen: number }[] | null
}

export default function Traffic() {
  const [range, setRange] = useState<Range>(presetRange('today'))
  const { data, error } = useApi<Overview>(`/traffic/overview?from=${range.from}&to=${range.to}`, 60000)
  const navigate = useNavigate()
  const total = (data?.up ?? 0) + (data?.down ?? 0)
  const devices = data?.devices ?? []
  const max = Math.max(1, ...devices.map((d) => d.up + d.down))
  const uploaders = useMemo(() => [...devices].filter((d) => d.up > d.down && d.up > 50 << 20).sort((a, b) => b.up - a.up).slice(0, 3), [devices])
  const label = (t: number) => {
    const x = new Date(t * 1000)
    return data?.step === 86400 ? `${x.getMonth() + 1}/${x.getDate()}` : `${x.getMonth() + 1}/${x.getDate()} ${String(x.getHours()).padStart(2, '0')}:00`
  }

  return (
    <>
      <PageHeader title="流量统计" desc="全部设备的上网流量与去向。点击设备查看实时网速、历史流量和设备画像。" />
      <DepHint ids={['conntrack', 'conntrack_acct', 'ipset']} className="mb-4" />
      <div className="mb-4"><RangePicker value={range} onChange={setRange} presets={['1h', 'today', '7d', '30d', '90d']} /></div>
      {error && <div className="mb-4"><ErrorBox>{error}</ErrorBox></div>}
      <div className="mb-4 grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <Kpi icon={Database} label="总流量" value={bytes(total)} />
        <Kpi icon={ArrowDown} label="下载" value={bytes(data?.down ?? 0)} sub={total ? `占 ${(((data?.down ?? 0) / total) * 100).toFixed(0)}%` : ''} />
        <Kpi icon={ArrowUp} label="上传" value={bytes(data?.up ?? 0)} sub={uploaders.length ? `主要来自 ${uploaders.map((d) => d.name || d.ip).join('、')}` : total ? `占 ${(((data?.up ?? 0) / total) * 100).toFixed(0)}%` : ''}
          tone={(data?.up ?? 0) > (data?.down ?? 0) ? 'amber' : undefined} />
        <Kpi icon={MonitorSmartphone} label="有流量的设备" value={devices.length} />
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(380px,460px)]">
        <Section title="设备排行" desc="条形：蓝色为下载，绿色为上传">
          <Table>
            <TableHeader><TableRow>
              <TableHead className="pl-4">设备</TableHead><TableHead className="w-[28%]">用量</TableHead>
              <TableHead className="text-right">下载</TableHead><TableHead className="text-right">上传</TableHead><TableHead className="pr-4 text-right">最近活动</TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {devices.map((d) => (
                <TableRow key={d.mac} className="cursor-pointer" onClick={() => navigate(`/devices/${d.mac}`)}>
                  <TableCell className="pl-4">
                    <div className="flex items-center gap-2.5">
                      <DeviceIcon type={d.type} />
                      <div className="min-w-0"><div className="truncate font-medium">{d.name || '未知设备'}</div><div className="font-mono text-[11px] text-muted-foreground">{d.ip}</div></div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex h-2 overflow-hidden rounded-full bg-muted" style={{ width: `${Math.max(4, ((d.up + d.down) / max) * 100)}%` }}>
                      <div className="bg-chart-1" style={{ flex: d.down }} /><div className="bg-chart-2" style={{ flex: d.up }} />
                    </div>
                    <div className="mt-0.5 text-[11px] text-muted-foreground">{total ? `${(((d.up + d.down) / total) * 100).toFixed(1)}%` : ''}</div>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{bytes(d.down)}</TableCell>
                  <TableCell className="text-right tabular-nums text-muted-foreground">{bytes(d.up)}</TableCell>
                  <TableCell className="whitespace-nowrap pr-4 text-right text-xs text-muted-foreground">{datetime(d.last_seen).slice(5, 16)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {!devices.length && <Empty>{data ? '该时间段暂无数据（开始采集后几分钟内会出现）' : '加载中…'}</Empty>}
        </Section>

        <div className="grid gap-4">
          <Section title="流量去向（全部设备）">
            <div className="p-4"><LevelDonut services={data?.services} categories={data?.categories} format={bytes} size={170} /></div>
          </Section>
          <Section title="流量随时间变化" desc={data?.step === 86400 ? '每天' : '每小时'}>
            <div className="p-4"><Bars series={data?.series ?? []} labelOf={label} height={140} /></div>
          </Section>
        </div>
      </div>
    </>
  )
}
