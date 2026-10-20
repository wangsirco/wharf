import { useEffect, useState } from 'react'
import { Ban, Search, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { get } from '@/lib/api'
import type { IPSB, Visitor } from '@/lib/types'
import { datetime, utcOffset } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { Empty, HalfPanel, Pill, Section } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

const PAGE = 50

function ProxyBadge({ v }: { v: Visitor }) {
  if (v.blocked) return <Pill tone="red"><Ban className="size-3" />已拦截</Pill>
  if (v.tz_match === 'mismatch' || v.ipsb_match === 'diff') return <Pill tone="red"><ShieldAlert className="size-3" />疑似代理</Pill>
  if (v.tz_match === 'match') return <Pill tone="green"><ShieldCheck className="size-3" />时区一致</Pill>
  return <Pill><ShieldQuestion className="size-3" />无法判断</Pill>
}

const parseIPSB = (s: string): IPSB | null => { try { return s ? JSON.parse(s) : null } catch { return null } }

export default function Visitors() {
  const [items, setItems] = useState<Visitor[]>([])
  const [geoReady, setGeoReady] = useState(true)
  const [more, setMore] = useState(false)
  const [q, setQ] = useState('')
  const [match, setMatch] = useState('all')
  const [sel, setSel] = useState<Visitor | null>(null)

  const query = (beforeId?: number) => {
    const p = new URLSearchParams({ limit: String(PAGE) })
    if (q.trim()) p.set('q', q.trim())
    if (match !== 'all') p.set('match', match)
    if (beforeId) p.set('before_id', String(beforeId))
    return get<{ items: Visitor[]; geo_ready: boolean }>('/visitors?' + p)
  }
  const load = async () => { const r = await query(); setItems(r.items); setGeoReady(r.geo_ready); setMore(r.items.length === PAGE) }
  const loadMore = async () => { const r = await query(items[items.length - 1]?.id); setItems([...items, ...r.items]); setMore(r.items.length === PAGE) }
  useEffect(() => { const t = setTimeout(load, 250); return () => clearTimeout(t) }, [q, match]) // eslint-disable-line

  return (
    <>
      <PageHeader title="访问记录" desc="每次打开面板都会记录：访问时间、访问者本机时间与时区、IP、ASN、运营商。浏览器时区与 IP 所在时区不一致，或 ip.sb 看到的出口 IP 与服务器不同时，标记为疑似代理。被访问控制拒绝的访问也会记录。" />
      {!geoReady && <div className="mb-4 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm">IP 离线库尚未下载，ASN / 运营商 / 位置暂时为空。可在「系统设置」中手动更新。</div>}
      <Section title="访问列表" action={
        <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
          <Tabs value={match} onValueChange={(v) => setMatch(String(v))}>
            <TabsList>
              <TabsTrigger value="all">全部</TabsTrigger>
              <TabsTrigger value="suspect">疑似代理</TabsTrigger>
              <TabsTrigger value="blocked">已拦截</TabsTrigger>
            </TabsList>
          </Tabs>
          <div className="relative min-w-40 flex-1 sm:flex-none">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="IP / 运营商 / 用户 / 城市" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-full pl-8 sm:w-52" />
          </div>
        </div>
      }>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-4">访问时间</TableHead><TableHead>用户本机时间</TableHead><TableHead>代理判断</TableHead>
              <TableHead>IP 地址</TableHead><TableHead>ASN</TableHead><TableHead>IP 提供商</TableHead><TableHead>位置</TableHead><TableHead className="pr-4">用户</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((v) => (
              <TableRow key={v.id} className="cursor-pointer" onClick={() => setSel(v)}>
                <TableCell className="whitespace-nowrap pl-4 text-xs tabular-nums">{datetime(v.ts)}</TableCell>
                <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">{v.client_time || '—'}<span className="ml-1">{utcOffset(v.client_offset)}</span></TableCell>
                <TableCell><ProxyBadge v={v} /></TableCell>
                <TableCell className="font-mono text-xs">{v.ip}</TableCell>
                <TableCell className="tabular-nums text-muted-foreground">{v.asn ? `AS${v.asn}` : '—'}</TableCell>
                <TableCell className="max-w-48 truncate">{v.as_org || '—'}</TableCell>
                <TableCell className="max-w-40 truncate text-muted-foreground">{[v.country, v.city].filter(Boolean).join(' · ') || '—'}</TableCell>
                <TableCell className="pr-4 text-muted-foreground">{v.username || '未登录'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!items.length && <Empty>暂无访问记录</Empty>}
        {more && <div className="border-t p-3 text-center"><Button variant="ghost" size="sm" onClick={loadMore}>加载更多</Button></div>}
      </Section>
      <HalfPanel open={!!sel} onOpenChange={(o) => { if (!o) setSel(null) }} title={sel?.ip ?? ''} desc={sel ? datetime(sel.ts) : ''}>
        {sel && (
          <div className="grid gap-6">
            <dl className="grid grid-cols-[8rem_1fr] gap-y-2.5 text-sm">
              <dt className="text-muted-foreground">访问时间</dt><dd className="tabular-nums">{datetime(sel.ts)}（服务器记录）</dd>
              <dt className="text-muted-foreground">用户本机时间</dt><dd className="tabular-nums">{sel.client_time || '—'}</dd>
              <dt className="text-muted-foreground">浏览器时区</dt><dd>{sel.client_tz || '—'}（{utcOffset(sel.client_offset)}）</dd>
              <dt className="text-muted-foreground">IP 所在时区</dt><dd>{sel.ip_tz || '—'}（{utcOffset(sel.ip_offset)}）</dd>
              <dt className="text-muted-foreground">判断</dt><dd className="flex flex-wrap items-center gap-2"><ProxyBadge v={sel} />{sel.reason && <span className="text-xs text-muted-foreground">{sel.reason}</span>}</dd>
              {sel.mac && <><dt className="text-muted-foreground">内网设备</dt><dd className="font-mono">{sel.mac}</dd></>}
              <dt className="text-muted-foreground">IP 地址</dt><dd className="font-mono">{sel.ip}</dd>
              <dt className="text-muted-foreground">ASN</dt><dd>{sel.asn ? `AS${sel.asn}` : '—'}</dd>
              <dt className="text-muted-foreground">IP 提供商</dt><dd>{sel.as_org || '—'}</dd>
              <dt className="text-muted-foreground">位置</dt><dd>{[sel.country, sel.region, sel.city].filter(Boolean).join(' · ') || '—'}</dd>
              <dt className="text-muted-foreground">用户</dt><dd>{sel.username ? `${sel.username}（ID ${sel.user_id}）` : '未登录'}</dd>
              <dt className="text-muted-foreground">页面</dt><dd className="font-mono text-xs">{sel.path}</dd>
              <dt className="text-muted-foreground">浏览器</dt><dd className="break-all text-xs text-muted-foreground">{sel.user_agent}</dd>
            </dl>
            {(() => {
              const sb = parseIPSB(sel.ipsb)
              if (!sb) return null
              return (
                <div className="grid gap-2">
                  <h3 className="flex items-center gap-2 text-sm font-semibold">ip.sb 看到的出口
                    {sel.ipsb_match === 'diff' ? <Pill tone="red">与服务器看到的 IP 不同</Pill> : <Pill tone="green">与服务器一致</Pill>}
                  </h3>
                  <dl className="grid grid-cols-[8rem_1fr] gap-y-2 rounded-lg border p-3 text-sm">
                    <dt className="text-muted-foreground">IP</dt><dd className="font-mono">{sb.ip}</dd>
                    <dt className="text-muted-foreground">ASN</dt><dd>{sb.asn ? `AS${sb.asn}` : '—'} {sb.asn_organization}</dd>
                    <dt className="text-muted-foreground">运营商</dt><dd>{sb.isp || '—'}</dd>
                    <dt className="text-muted-foreground">位置</dt><dd>{[sb.country, sb.region, sb.city].filter(Boolean).join(' · ') || '—'}</dd>
                    <dt className="text-muted-foreground">时区</dt><dd>{sb.timezone || '—'}</dd>
                  </dl>
                  <p className="text-xs text-muted-foreground">该数据由访问者浏览器上报，仅供参考。</p>
                </div>
              )
            })()}
            <p className="text-xs text-muted-foreground">判断依据：比较浏览器上报的当前 UTC 偏移与 IP 地理位置所在时区在访问时刻的 UTC 偏移。出差旅行未改时区的设备也会被标记，仅供参考。IP 数据：DB-IP Lite（CC BY 4.0）。</p>
          </div>
        )}
      </HalfPanel>
    </>
  )
}
