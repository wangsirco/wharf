import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Ban, Pin, RefreshCw, Search, ShieldCheck } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { runAction } from '@/lib/actions'
import { useLive } from '@/lib/live'
import { get } from '@/lib/api'
import type { Device, DevicePolicy } from '@/lib/types'
import { ago, bitrate, datetime } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { Dot, Empty, ErrorBox, Field, HalfPanel, Pill, Section, useConfirm, VMTag } from '@/components/common'
import { DeviceIcon } from '@/components/device-icon'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

const name = (d: Device) => d.static_name || d.hostname || ''
const ipNum = (ip: string) => ip.split('.').reduce((a, b) => a * 256 + Number(b), 0)

// quickBlock toggles "cut internet" while keeping the rest of the device's policy.
export async function quickBlock(d: Pick<Device, 'mac' | 'name'>, on: boolean) {
  const p = await get<DevicePolicy>(`/devices/${encodeURIComponent(d.mac)}/policy`)
  return runAction('device.policy.save', { ...p, name: p.name || d.name, block: on })
}

export default function Devices() {
  const { data, error, reload } = useApi<Device[]>('/devices', 10000)
  const { can } = useAuth()
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState('online')
  const [sort, setSort] = useState<'ip' | 'speed'>('speed')
  const navigate = useNavigate()
  const live = useLive()
  const { confirm, dialog } = useConfirm()

  const rate = (d: Device) => (live[d.mac]?.down ?? 0) + (live[d.mac]?.up ?? 0)
  const list = useMemo(() => {
    const s = q.trim().toLowerCase()
    return (data ?? [])
      .filter((d) => d.ip)
      .filter((d) => filter === 'all' || (filter === 'online' ? d.online : filter === 'static' ? d.static : filter === 'new' ? d.is_new : filter === 'controlled' ? d.controlled : !d.online))
      .filter((d) => !s || [d.ip, d.mac, d.name, d.vendor, d.type, d.os, d.alias].some((v) => (v ?? '').toLowerCase().includes(s)))
      .sort((a, b) => (sort === 'speed' ? rate(b) - rate(a) || ipNum(a.ip) - ipNum(b.ip) : ipNum(a.ip) - ipNum(b.ip)))
  }, [data, q, filter, sort, live]) // eslint-disable-line react-hooks/exhaustive-deps
  const online = data?.filter((d) => d.online && d.ip).length ?? 0
  const newCount = data?.filter((d) => d.is_new).length ?? 0

  const toggleBlock = async (d: Device) => {
    if (!d.blocked && !(await confirm(`断开 ${d.name || d.mac} 的网络？`, '设备仍会显示「已连接互联网」，但打不开任何内容。可随时恢复。', { danger: true, ok: '断网' }))) return
    try { await quickBlock(d, !d.blocked) } catch (e) { toast.error((e as Error).message) } finally { reload() }
  }

  return (
    <>
      <PageHeader title="设备" desc={data ? `共 ${data.filter((d) => d.ip).length} 台，在线 ${online} 台${newCount ? `，24 小时内新接入 ${newCount} 台` : ''} · 网速每 3 秒刷新` : '加载中…'}>
        <Button variant="outline" size="sm" onClick={reload}><RefreshCw /> 刷新</Button>
      </PageHeader>
      {error && <div className="mb-4"><ErrorBox>{error}</ErrorBox></div>}
      <Section title="设备列表" action={
        <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
          <Tabs value={filter} onValueChange={(v) => setFilter(String(v))}>
            <TabsList>
              <TabsTrigger value="online">在线</TabsTrigger>
              <TabsTrigger value="all">全部</TabsTrigger>
              <TabsTrigger value="offline">离线</TabsTrigger>
              <TabsTrigger value="new">新设备{newCount ? ` ${newCount}` : ''}</TabsTrigger>
              <TabsTrigger value="controlled">已管控</TabsTrigger>
              <TabsTrigger value="static">静态绑定</TabsTrigger>
            </TabsList>
          </Tabs>
          <Tabs value={sort} onValueChange={(v) => setSort(v as 'ip' | 'speed')}>
            <TabsList><TabsTrigger value="speed">按网速</TabsTrigger><TabsTrigger value="ip">按 IP</TabsTrigger></TabsList>
          </Tabs>
          <div className="relative min-w-40 flex-1 sm:flex-none">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="名称 / IP / MAC / 厂商 / 类型" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-full pl-8 sm:w-52" />
          </div>
        </div>
      }>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-4">设备</TableHead><TableHead className="hidden md:table-cell">IP 地址</TableHead>
              <TableHead className="hidden text-right md:table-cell">下行</TableHead><TableHead className="hidden text-right md:table-cell">上行</TableHead>
              <TableHead className="hidden lg:table-cell">类型 / 系统</TableHead><TableHead className="hidden sm:table-cell">状态</TableHead><TableHead className="pr-4 text-right">{can('access.manage') ? '上网' : ''}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.map((d) => (
              <TableRow key={d.mac} className="cursor-pointer" onClick={() => navigate(`/devices/${d.mac}`)}>
                <TableCell className="w-full max-w-0 pl-4 md:w-auto md:max-w-none">
                  <div className="flex items-center gap-3">
                    <DeviceIcon type={d.type} online={d.online} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className={d.name ? 'truncate font-medium' : 'text-muted-foreground'}>{d.name || '未知设备'}</span>
                        <VMTag tag={d.vm_tag} />
                        {d.is_new && <Pill tone="amber">新</Pill>}
                      </div>
                      <div className="hidden truncate font-mono text-[11px] text-muted-foreground md:block">{d.mac}{d.vendor ? ` · ${d.vendor}` : d.random_mac ? ' · 隐私 MAC' : ''}</div>
                      {/* phones: IP and live speed under the name instead of separate columns */}
                      <div className="truncate text-[11px] text-muted-foreground md:hidden">
                        <span className="font-mono">{d.ip}</span>
                        {live[d.mac]?.down || live[d.mac]?.up ? <span className="tabular-nums"> · ↓{bitrate(live[d.mac]?.down ?? 0)} ↑{bitrate(live[d.mac]?.up ?? 0)}</span> : d.vendor ? ` · ${d.vendor}` : ''}
                        {d.blocked && <span className="text-destructive sm:hidden"> · 已断网</span>}
                      </div>
                    </div>
                  </div>
                </TableCell>
                <TableCell className="hidden font-mono text-xs md:table-cell">{d.ip}{d.static && <Pin className="ml-1 inline size-3 text-primary" />}</TableCell>
                <TableCell className="hidden text-right text-xs tabular-nums md:table-cell">{live[d.mac]?.down ? bitrate(live[d.mac].down) : <span className="text-muted-foreground">–</span>}</TableCell>
                <TableCell className="hidden text-right text-xs tabular-nums md:table-cell">{live[d.mac]?.up ? bitrate(live[d.mac].up) : <span className="text-muted-foreground">–</span>}</TableCell>
                <TableCell className="hidden text-xs lg:table-cell">
                  <span className={d.type === '未知' ? 'text-muted-foreground' : ''}>{d.type}</span>
                  {d.os && <span className="ml-1 text-muted-foreground">{d.os}</span>}
                </TableCell>
                <TableCell className="hidden sm:table-cell">
                  {d.blocked ? <Pill tone="red"><Ban className="size-3" />{d.blocked_by === 'schedule' ? '定时断网' : '已断网'}</Pill>
                    : d.controlled ? <Pill tone="blue">已管控</Pill>
                    : d.online ? <span className="text-xs text-muted-foreground">在线</span>
                    : <span className="text-xs text-muted-foreground">{d.last_seen ? `离线 · ${ago(d.last_seen)}在线` : d.lease_expiry ? `租约至 ${datetime(d.lease_expiry).slice(5, 16)}` : '离线'}</span>}
                </TableCell>
                <TableCell className="pr-4 text-right" onClick={(e) => e.stopPropagation()}>
                  {can('access.manage') && (
                    <Button variant="ghost" size="icon-sm" title={d.blocked ? '恢复上网' : '断网'} onClick={() => toggleBlock(d)}
                      className={d.blocked ? 'text-success' : 'text-muted-foreground hover:text-destructive'}>
                      {d.blocked ? <ShieldCheck /> : <Ban />}
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!list.length && <Empty>{data ? '没有匹配的设备' : '加载中…'}</Empty>}
      </Section>
      {dialog}
    </>
  )
}


export function DevicePanel({ device, onClose, canManage, onSaved }: { device: Device | null; onClose: () => void; canManage: boolean; onSaved: () => void }) {
  const [form, setForm] = useState({ name: '', ip: '' })
  const [busy, setBusy] = useState(false)
  const { confirm, dialog } = useConfirm()
  const [last, setLast] = useState<string | null>(null)
  if (device && last !== device.mac) {
    setLast(device.mac)
    setForm({ name: (device.static_name || device.hostname || '').replace(/[^A-Za-z0-9-]/g, '-').replace(/^-+|-+$/g, ''), ip: device.ip })
  }
  const d = device
  const editable = !!d && canManage && d.editable

  const save = async () => {
    if (!d) return
    setBusy(true)
    try {
      await runAction('device.static.save', { section: d.static_id ?? '', mac: d.mac, ip: form.ip, name: form.name })
      onSaved()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const remove = async () => {
    if (!d?.static_id) return
    if (!(await confirm('删除静态绑定？', `${d.mac} 将恢复为 DHCP 自动分配。`, { danger: true, ok: '删除' }))) return
    setBusy(true)
    try { await runAction('device.static.delete', { section: d.static_id, mac: d.mac }); onSaved() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }

  return (
    <HalfPanel open={!!d} onOpenChange={(o) => { if (!o) { onClose(); setLast(null) } }}
      title={<span className="flex items-center gap-2"><Dot tone={d?.online ? 'ok' : 'off'} />{d ? name(d) || '未知设备' : ''}</span>}
      desc={d ? `${d.ip} · ${d.mac}` : ''}
      footer={editable && (
        <>
          {d?.static_id && <Button variant="outline" className="mr-auto text-destructive" disabled={busy} onClick={remove}>删除绑定</Button>}
          <Button variant="outline" onClick={onClose}>取消</Button>
          <Button disabled={busy || !form.name || !form.ip} onClick={save}>{d?.static ? '保存修改' : '设为静态绑定'}</Button>
        </>
      )}>
      {d && (
        <div className="grid gap-6">
          <dl className="grid grid-cols-[8rem_1fr] gap-y-2.5 text-sm">
            <dt className="text-muted-foreground">状态</dt><dd>{d.online ? '在线' : '离线'}（{d.neigh_state || '无邻居记录'}）</dd>
            <dt className="text-muted-foreground">DHCP 主机名</dt><dd>{d.hostname || '—'}</dd>
            <dt className="text-muted-foreground">静态绑定名称</dt><dd>{d.static_name || '—'}</dd>
            <dt className="text-muted-foreground">IP 地址</dt><dd className="font-mono">{d.ip}</dd>
            <dt className="text-muted-foreground">MAC 地址</dt><dd className="font-mono">{d.mac}</dd>
            <dt className="text-muted-foreground">租约到期</dt><dd>{d.lease_expiry ? datetime(d.lease_expiry) : '—'}</dd>
            <dt className="text-muted-foreground">创建者</dt><dd>{d.owner_name ?? (d.static ? '路由器原有配置' : '—')}</dd>
          </dl>
          {editable ? (
            <div className="grid gap-4 rounded-xl border p-4">
              <div>
                <h3 className="text-sm font-semibold">静态 IP 绑定</h3>
                <p className="text-xs text-muted-foreground">写入 OpenWrt「DHCP 静态地址分配」，设备下次续租时生效。</p>
              </div>
              <Field label="主机名" hint="仅限字母、数字和 -（OpenWrt / DNS 主机名规则）。想用 Chloe's iPhone 这样带空格或撇号的名字，请在设备详情页点铅笔图标修改「显示名称」">
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </Field>
              <Field label="固定 IP"><Input className="font-mono" value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} /></Field>
            </div>
          ) : canManage && d.static ? (
            <p className="text-sm text-muted-foreground">该静态绑定不是你创建的，只能查看。</p>
          ) : null}
        </div>
      )}
      {dialog}
    </HalfPanel>
  )
}
