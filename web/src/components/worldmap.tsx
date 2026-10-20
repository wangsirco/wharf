import { useEffect, useRef } from 'react'
import * as echarts from 'echarts/core'
import { EffectScatterChart, LinesChart, ScatterChart } from 'echarts/charts'
import { GeoComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { feature } from 'topojson-client'
import type { GeometryCollection, Topology } from 'topojson-specification'
import world from 'world-atlas/countries-110m.json'
import { bytes } from '@/lib/format'

echarts.use([GeoComponent, TooltipComponent, LinesChart, EffectScatterChart, ScatterChart, CanvasRenderer])

const CUT = -25
export const wrapLon = (lon: number) => (lon < CUT ? lon + 360 : lon)

let registered = false
function registerWorld() {
  if (registered) return
  const topo = world as unknown as Topology<{ countries: GeometryCollection }>
  const geo = feature(topo, topo.objects.countries)
  // Antarctica only wastes space on a traffic map
  const features = geo.features.filter((f) => f.properties && (f.properties as { name: string }).name !== 'Antarctica')
  // Pacific-centred: ECharts draws geo planar, so rings spanning ±180° (Russia, Fiji) became
  // stripes across the map. Shifting west longitudes by 360° joins them; Greenland, the only
  // ring straddling the new cut, moves as a whole.
  for (const f of features) {
    const g = f.geometry as { type: string; coordinates: number[][][] | number[][][][] }
    const polys = (g.type === 'Polygon' ? [g.coordinates] : g.coordinates) as number[][][][]
    for (const poly of polys) for (const ring of poly) {
      const moved = ring.map((c) => wrapLon(c[0]))
      const split = moved.some((x, i) => i > 0 && Math.abs(x - moved[i - 1]) > 180)
      const all = ring.reduce((a, c) => a + c[0], 0) / ring.length < CUT
      ring.forEach((c, i) => { c[0] = split ? c[0] + (all ? 360 : 0) : moved[i] })
    }
  }
  const fc = { ...geo, features }
  echarts.registerMap('world', fc as never)
  registered = true
}

export interface GeoPlace { code: string; name: string; city?: string; lat: number; lon: number; bytes: number; up?: number; down?: number; conns: number; top?: string[] | null }
export interface GeoFlows { anycast_bytes?: number; origin: { lat?: number; lon?: number; city?: string; name?: string }; countries: GeoPlace[] | null; cities: GeoPlace[] | null }

// WorldFlowMap: animated "fly lines" from home to the countries the household talks to.
export default function WorldFlowMap({ data, height = 460, maxLines = 25 }: { data: GeoFlows | null; height?: number; maxLines?: number }) {
  const ref = useRef<HTMLDivElement>(null)
  const chart = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    registerWorld()
    if (!ref.current) return
    chart.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    const ro = new ResizeObserver(() => chart.current?.resize())
    ro.observe(ref.current)
    return () => { ro.disconnect(); chart.current?.dispose(); chart.current = null }
  }, [])

  useEffect(() => {
    if (!chart.current || !data) return
    const o = data.origin
    const home: [number, number] = [wrapLon(o.lon ?? 0), o.lat ?? 0]
    const list = (data.countries ?? []).filter((c) => c.code !== undefined).slice(0, maxLines).map((c) => ({ ...c, lon: wrapLon(c.lon) }))
    const max = Math.max(1, ...list.map((c) => c.bytes))
    const scale = (b: number) => Math.log10(1 + (b / max) * 99) / 2 // 0..1
    const fly = list.filter((c) => Math.abs(c.lon - home[0]) + Math.abs(c.lat - home[1]) > 0.5)
    chart.current.setOption({
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item', backgroundColor: 'rgba(15,23,42,0.92)', borderColor: '#334155', textStyle: { color: '#e2e8f0', fontSize: 12 },
        formatter: (p: { data?: { info?: GeoPlace } }) => {
          const c = p.data?.info
          if (!c) return ''
          return `<b>${c.name}${c.city ? ' · ' + c.city : ''}</b><br/>流量 ${bytes(c.bytes)}${c.conns ? ` · ${c.conns} 个连接` : ''}${c.top?.length ? `<br/>${c.top.join('、')}` : ''}`
        },
      },
      geo: {
        map: 'world', roam: true, zoom: 1.1, center: [155, 12], silent: false, scaleLimit: { min: 0.8, max: 8 },
        itemStyle: { areaColor: '#10213b', borderColor: '#3b6aa8', borderWidth: 0.7 },
        emphasis: { itemStyle: { areaColor: '#173158' }, label: { show: false } },
      },
      series: [
        {
          type: 'lines', coordinateSystem: 'geo', zlevel: 2,
          effect: { show: true, period: 4, trailLength: 0.35, symbol: 'circle', symbolSize: 4, color: '#7dd3fc' },
          lineStyle: { color: '#38bdf8', opacity: 0.35, curveness: 0.28 },
          data: fly.map((c) => ({
            coords: [home, [c.lon, c.lat]], info: c,
            lineStyle: { width: 0.6 + scale(c.bytes) * 3.2, opacity: 0.25 + scale(c.bytes) * 0.5 },
          })),
        },
        {
          type: 'effectScatter', coordinateSystem: 'geo', zlevel: 3,
          rippleEffect: { brushType: 'stroke', scale: 3.5, period: 4 },
          itemStyle: { color: '#22d3ee', shadowBlur: 10, shadowColor: '#22d3ee' },
          data: list.map((c) => ({ name: c.name, value: [c.lon, c.lat], symbolSize: 4 + scale(c.bytes) * 14, info: c })),
        },
        {
          type: 'scatter', coordinateSystem: 'geo', zlevel: 3, symbolSize: 2.5,
          itemStyle: { color: '#93c5fd', opacity: 0.7 },
          data: (data.cities ?? []).map((c) => ({ value: [wrapLon(c.lon), c.lat], info: c })),
        },
        {
          type: 'effectScatter', coordinateSystem: 'geo', zlevel: 4, symbolSize: 12,
          rippleEffect: { brushType: 'fill', scale: 5, period: 3 },
          itemStyle: { color: '#facc15', shadowBlur: 16, shadowColor: '#facc15' },
          label: { show: true, formatter: (o.city || o.name || '家').replace(/\s*\(.*\)$/, ''), position: 'bottom', color: '#fde68a', fontSize: 11 },
          data: o.lat !== undefined ? [{ value: home, info: { name: '家', city: o.city, bytes: 0, conns: 0 } }] : [],
        },
      ],
    }, true)
  }, [data, maxLines])

  // the map is ~2:1, so on narrow screens the box follows the width instead of a fixed height
  return <div ref={ref} style={{ height: `min(${height}px, max(240px, 62vw))` }} className="w-full overflow-hidden rounded-lg bg-[radial-gradient(ellipse_at_center,#0b1730_0%,#060b16_75%)]" />
}

export interface TraceHop {
  hop: number; ip?: string; host?: string; loss: number; sent: number; last: number; avg: number; best: number; worst: number; stdev: number
  private?: boolean; asn?: number; as_org?: string; country?: string; country_name?: string; region?: string; city?: string; lat?: number; lon?: number
}
export interface TraceResult { target: string; ip: string; mode: string; secs: number; hops: TraceHop[] | null; origin?: { lat: number; lon: number; city?: string; name?: string } | null }

// TraceMap: the route a packet takes, hop by hop, from home to the target.
export function TraceMap({ data, height = 380 }: { data: TraceResult; height?: number }) {
  const ref = useRef<HTMLDivElement>(null)
  const chart = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    registerWorld()
    if (!ref.current) return
    chart.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    const ro = new ResizeObserver(() => chart.current?.resize())
    ro.observe(ref.current)
    return () => { ro.disconnect(); chart.current?.dispose(); chart.current = null }
  }, [])

  useEffect(() => {
    if (!chart.current) return
    // consecutive hops in the same place collapse into one stop
    type Stop = { pos: [number, number]; hops: TraceHop[]; home?: boolean }
    const stops: Stop[] = []
    const o = data.origin
    if (o) stops.push({ pos: [wrapLon(o.lon), o.lat], hops: [], home: true })
    for (const h of data.hops ?? []) {
      if (h.lat === undefined || h.lon === undefined || (!h.lat && !h.lon)) continue
      const pos: [number, number] = [wrapLon(h.lon), h.lat]
      const last = stops[stops.length - 1]
      if (last && Math.abs(last.pos[0] - pos[0]) < 0.3 && Math.abs(last.pos[1] - pos[1]) < 0.3) last.hops.push(h)
      else stops.push({ pos, hops: [h] })
    }
    const segs = stops.slice(1).map((s, i) => ({ coords: [stops[i].pos, s.pos] }))
    const lons = stops.map((s) => s.pos[0]), lats = stops.map((s) => s.pos[1])
    const center: [number, number] = stops.length ? [(Math.min(...lons) + Math.max(...lons)) / 2, (Math.min(...lats) + Math.max(...lats)) / 2] : [155, 12]
    const span = stops.length ? Math.max(Math.max(...lons) - Math.min(...lons), (Math.max(...lats) - Math.min(...lats)) * 2, 8) : 360
    const label = (s: Stop) => s.home ? (o?.city || o?.name || '家') : `#${s.hops.map((h) => h.hop).join(',')} ${s.hops[0].city || s.hops[0].country_name || ''}`
    chart.current.setOption({
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item', backgroundColor: 'rgba(15,23,42,0.92)', borderColor: '#334155', textStyle: { color: '#e2e8f0', fontSize: 12 },
        formatter: (p: { data?: { stop?: Stop } }) => {
          const s = p.data?.stop
          if (!s) return ''
          if (s.home) return `<b>家</b>${o?.city ? ' · ' + o.city : ''}`
          return s.hops.map((h) => `<b>#${h.hop}</b> ${h.ip}${h.host ? ` (${h.host})` : ''}<br/>${[h.country_name, h.region, h.city].filter(Boolean).join(' · ')}${h.asn ? `<br/>AS${h.asn} ${h.as_org ?? ''}` : ''}<br/>延迟 ${h.avg.toFixed(1)} ms · 丢包 ${h.loss}%`).join('<hr style="border-color:#334155;margin:4px 0"/>')
        },
      },
      geo: {
        map: 'world', roam: true, center, zoom: Math.max(1, Math.min(8, 300 / span)), scaleLimit: { min: 0.8, max: 12 },
        itemStyle: { areaColor: '#10213b', borderColor: '#3b6aa8', borderWidth: 0.7 },
        emphasis: { itemStyle: { areaColor: '#173158' }, label: { show: false } },
      },
      series: [
        {
          type: 'lines', coordinateSystem: 'geo', zlevel: 2,
          effect: { show: true, period: 3, trailLength: 0.4, symbol: 'arrow', symbolSize: 6, color: '#fde68a' },
          lineStyle: { color: '#38bdf8', width: 1.6, opacity: 0.7, curveness: 0.2 },
          data: segs,
        },
        {
          type: 'effectScatter', coordinateSystem: 'geo', zlevel: 3,
          rippleEffect: { brushType: 'stroke', scale: 3, period: 4 },
          label: { show: true, position: 'right', color: '#bae6fd', fontSize: 11, formatter: (p: { data: { stop: Stop } }) => label(p.data.stop) },
          data: stops.map((s, i) => ({
            value: s.pos, stop: s, symbolSize: s.home || i === stops.length - 1 ? 11 : 7,
            itemStyle: { color: s.home ? '#facc15' : i === stops.length - 1 ? '#f472b6' : '#22d3ee' },
          })),
        },
      ],
    }, true)
  }, [data])

  return <div ref={ref} style={{ height: `min(${height}px, max(240px, 62vw))` }} className="w-full overflow-hidden rounded-lg bg-[radial-gradient(ellipse_at_center,#0b1730_0%,#060b16_75%)]" />
}
