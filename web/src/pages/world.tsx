import { lazy, Suspense, useState } from 'react'
import { Globe2 } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { bytes } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { Empty, Section } from '@/components/common'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { GeoFlows } from '@/components/worldmap'

const WorldFlowMap = lazy(() => import('@/components/worldmap'))
const RANGES: [string, string][] = [['1h', '近 1 小时'], ['24h', '24 小时'], ['7d', '7 天'], ['30d', '30 天']]

export function CountryRanking({ data, limit = 15 }: { data: GeoFlows | null; limit?: number }) {
  const list = (data?.countries ?? []).slice(0, limit)
  const total = (data?.countries ?? []).reduce((a, c) => a + c.bytes, 0)
  if (!list.length) return <Empty>暂无数据</Empty>
  return (
    <div className="grid gap-2.5 p-4">
      {list.map((c, i) => (
        <div key={c.code} className="grid gap-1">
          <div className="flex items-center gap-2 text-sm">
            <span className="w-5 text-right text-xs tabular-nums text-muted-foreground">{i + 1}</span>
            <span className="flex-1 truncate font-medium">{c.name}<span className="ml-1 text-[10px] font-normal text-muted-foreground">{c.code}</span></span>
            <span className="tabular-nums">{bytes(c.bytes)}</span>
            <span className="w-12 text-right text-xs tabular-nums text-muted-foreground">{total ? ((c.bytes / total) * 100).toFixed(1) : 0}%</span>
          </div>
          <div className="ml-7 h-1 rounded-full bg-muted"><div className="h-1 rounded-full bg-gradient-to-r from-sky-500 to-cyan-300" style={{ width: `${(c.bytes / list[0].bytes) * 100}%` }} /></div>
          {c.top?.length ? <div className="ml-7 truncate text-[11px] text-muted-foreground">{c.top.join('、')}</div> : null}
        </div>
      ))}
    </div>
  )
}

export default function World() {
  const [range, setRange] = useState('24h')
  const { data } = useApi<GeoFlows>(`/geo/flows?range=${range}`, range === '1h' ? 60000 : 300000)
  const n = data?.countries?.length ?? 0
  // scanners, NTP pools and P2P touch dozens of countries with a few KB each
  const major = (data?.countries ?? []).filter((c) => c.bytes >= 1 << 20).length
  return (
    <>
      <PageHeader title="全球流量" desc={`从${(data?.origin?.city || '家').replace(/\s*\(.*\)$/, '')}出发，流量去往了哪些国家和地区（按 IP 离线库定位）${n ? ` · 主要 ${major} 个国家 / 地区（超过 1 MB），共 ${n} 个有过连接` : ''}`}>
        <Tabs value={range} onValueChange={(v) => setRange(String(v))}>
          <TabsList>{RANGES.map(([k, l]) => <TabsTrigger key={k} value={k}>{l}</TabsTrigger>)}</TabsList>
        </Tabs>
      </PageHeader>
      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="rounded-xl border bg-[#060b16] p-2">
          <Suspense fallback={<div className="grid h-[min(560px,62vw)] place-items-center text-sm text-slate-400"><Globe2 className="mb-2 size-6 animate-pulse" />加载地图…</div>}>
            <WorldFlowMap data={data} height={560} />
          </Suspense>
        </div>
        <Section title="国家 / 地区排行" desc={`线越粗、光点越大，流量越多；可拖动和缩放地图${data?.anycast_bytes ? `。Cloudflare 等 Anycast CDN 的 ${bytes(data.anycast_bytes)} 按就近节点计入本地` : ''}`}>
          <CountryRanking data={data} />
        </Section>
      </div>
    </>
  )
}
