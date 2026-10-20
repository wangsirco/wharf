import { useState } from 'react'
import { toast } from 'sonner'
import { Pencil, Plus, Power, Search, Trash2 } from 'lucide-react'
import { runAction } from '@/lib/actions'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import type { Device } from '@/lib/types'
import { duration } from '@/lib/format'
import { cn } from '@/lib/utils'
import { DepHint } from '@/components/deps'
import { PageHeader } from '@/components/layout'
import { Empty, Field, Pill, Section, useConfirm, VMTag } from '@/components/common'
import { DeviceIcon } from '@/components/device-icon'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ConnTools, ScanTool, SpeedTools, TraceTool } from '@/pages/diag'
import { Monitors } from '@/pages/monitor'
import { CaptureTool } from '@/pages/capture'

interface UPnPRule { num: string; proto: string; extport: number; intaddr: string; intport: number; descr: string; expires: number; device: string; mac: string }
interface Host { section: string; name: string; ip: string; editable: boolean }

const TABS: [string, string, (can: (p: string) => boolean) => boolean][] = [
  ['trace', '路由追踪', (c) => c('tools.diag')],
  ['conn', '连通性测试', (c) => c('tools.diag')],
  ['speed', '内网测速', (c) => c('tools.diag')],
  ['monitor', '定时监控', (c) => c('tools.diag')],
  ['scan', '局域网扫描', (c) => c('tools.diag')],
  ['capture', '抓包', (c) => c('tools.capture')],
  ['lan', '唤醒 · UPnP · 解析', (c) => c('tools.wol') || c('system.view')],
]

export default function Tools() {
  const { can } = useAuth()
  const tabs = TABS.filter(([, , ok]) => ok(can))
  const saved = (() => { try { return localStorage.getItem('owp-tools-tab') } catch { return null } })()
  const [tab, setTab] = useState(tabs.some(([k]) => k === saved) ? saved! : tabs[0]?.[0] ?? 'lan')
  const pick = (v: string) => { setTab(v); try { localStorage.setItem('owp-tools-tab', v) } catch { /* private mode */ } }
  return (
    <>
      <PageHeader title="网络工具" desc="路由追踪、连通性测试、内网测速、定时监控、局域网扫描、抓包、网络唤醒、UPnP、自定义解析" />
      <Tabs value={tab} onValueChange={(v) => pick(String(v))} className="mb-4">
        <TabsList>{tabs.map(([k, l]) => <TabsTrigger key={k} value={k} className="px-3">{l}</TabsTrigger>)}</TabsList>
      </Tabs>
      {tab === 'trace' && <TraceTool />}
      {tab === 'conn' && <ConnTools />}
      {tab === 'speed' && <SpeedTools />}
      {tab === 'monitor' && <Monitors />}
      {tab === 'scan' && <ScanTool />}
      {tab === 'capture' && <CaptureTool />}
      {tab === 'lan' && (
        <div className="grid items-start gap-4 xl:grid-cols-2">
          {can('tools.wol') && <WakeOnLAN />}
          <div className="grid min-w-0 gap-4">
            {can('system.view') && <UPnP />}
            {can('system.view') && <Hosts />}
          </div>
        </div>
      )}
    </>
  )
}

const MAC_RE = /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i

function WakeOnLAN() {
  const { can } = useAuth()
  const { data } = useApi<Device[]>(can('devices.view') ? '/devices' : null, 30000)
  const [q, setQ] = useState('')
  const [mac, setMac] = useState('')
  const wake = async (m: string, name?: string) => {
    try { if (await runAction('wol.send', { mac: m.replace(/-/g, ':'), name })) toast.success(`已向 ${name || m} 发送唤醒包`, { description: '设备需在 BIOS / 网卡设置中开启 Wake-on-LAN' }) } catch (e) { toast.error((e as Error).message) }
  }
  const s = q.trim().toLowerCase()
  // offline wired-looking devices first: those are the ones you'd want to wake
  const list = (data ?? []).filter((d) => !d.random_mac && (!s || [d.name, d.ip, d.mac, d.vendor].some((x) => x?.toLowerCase().includes(s))))
    .sort((a, b) => Number(a.online) - Number(b.online) || (a.name || '').localeCompare(b.name || ''))
  return (
    <Section title="网络唤醒（WOL）" desc="向局域网设备发送 Magic Packet，远程开机电脑 / NAS">
      <DepHint ids={['etherwake']} className="mx-4 mt-3" />
      <div className="flex flex-wrap gap-2 border-b px-4 py-3">
        <Input placeholder="手动输入 MAC，如 AA:BB:CC:DD:EE:FF" value={mac} onChange={(e) => setMac(e.target.value.trim())} className="h-8 min-w-0 flex-1 font-mono text-xs" />
        <Button size="sm" disabled={!MAC_RE.test(mac)} onClick={() => wake(mac)}><Power /> 唤醒</Button>
      </div>
      {data && (
        <>
          <div className="relative px-4 pt-3">
            <Search className="absolute left-6.5 top-1/2 mt-1.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="搜索设备" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 pl-8" />
          </div>
          <div className="max-h-[520px] divide-y overflow-auto py-1">
            {list.length ? list.map((d) => (
              <div key={d.mac} className="flex items-center gap-3 px-4 py-2">
                <DeviceIcon type={d.type} online={d.online} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 text-sm"><span className="truncate font-medium">{d.name || '未知设备'}</span><VMTag tag={d.vm_tag} /></div>
                  <div className="truncate font-mono text-[11px] text-muted-foreground">{d.mac} · {d.online ? '在线' : '离线'}</div>
                </div>
                <Button variant={d.online ? 'ghost' : 'outline'} size="sm" onClick={() => wake(d.mac, d.name)}><Power /> 唤醒</Button>
              </div>
            )) : <Empty>没有匹配的设备</Empty>}
          </div>
        </>
      )}
    </Section>
  )
}

function UPnP() {
  const { can } = useAuth()
  const { data, reload } = useApi<{ enabled: boolean; running: boolean; rules: UPnPRule[] | null }>('/upnp', 15000)
  const [busy, setBusy] = useState(false)
  const { confirm, dialog } = useConfirm()
  const toggle = async (on: boolean) => {
    if (on && !(await confirm('开启 UPnP？', '开启后，局域网里的任何设备（包括被感染的设备）都能自行在路由器上打开端口，暴露到公网。游戏机、BT 下载需要时再开。', { ok: '开启' }))) return
    setBusy(true)
    try { await runAction('system.service', { name: 'miniupnpd', action: on ? 'on' : 'off' }); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const del = async (r: UPnPRule) => {
    try { await runAction('upnp.delete', { num: r.num, label: `${r.proto} ${r.extport} → ${r.intaddr}:${r.intport}（${r.descr || r.device}）` }); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const rules = data?.rules ?? []
  return (
    <Section title="UPnP / NAT-PMP" desc={data ? (data.enabled ? (data.running ? `运行中 · ${rules.length} 条设备自动创建的映射` : '已开启，但服务未运行') : '已关闭（推荐：需要时再开）') : ''}
      action={can('system.manage') && data ? <Switch checked={data.enabled} disabled={busy} onCheckedChange={toggle} /> : undefined}>
      <DepHint ids={['upnp']} className="mx-4 mt-3" />
      {!rules.length ? <Empty>{data?.enabled ? '目前没有设备申请端口映射' : 'UPnP 关闭时，设备无法自动打开端口'}</Empty> : (
        <div className="divide-y">
          {rules.map((r) => (
            <div key={r.num} className="flex items-center gap-3 px-4 py-2.5 text-sm">
              <Pill tone="blue">{r.proto}</Pill>
              <div className="min-w-0 flex-1">
                <div className="font-mono text-xs">公网 {r.extport} → {r.intaddr}:{r.intport}</div>
                <div className="truncate text-xs text-muted-foreground">{r.device || r.intaddr}{r.descr ? ` · ${r.descr}` : ''}{r.expires ? ` · ${duration(r.expires)}后过期` : ''}</div>
              </div>
              {can('system.manage') && <Button variant="ghost" size="icon-sm" title="删除映射" onClick={() => del(r)}><Trash2 /></Button>}
            </div>
          ))}
        </div>
      )}
      {dialog}
    </Section>
  )
}

function Hosts() {
  const { can } = useAuth()
  const { data, reload } = useApi<Host[]>('/hosts')
  const [edit, setEdit] = useState<{ section: string; name: string; ip: string } | null>(null)
  const { confirm, dialog } = useConfirm()
  const save = async () => {
    if (!edit) return
    try { await runAction('hosts.save', edit); setEdit(null); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const del = async (h: Host) => {
    if (!(await confirm(`删除 ${h.name}？`, `局域网设备将不再把 ${h.name} 解析到 ${h.ip}。`, { danger: true, ok: '删除' }))) return
    try { await runAction('hosts.save', { section: h.section, name: h.name, delete: true }); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const list = (data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name))
  return (
    <Section title="自定义解析（hosts）" desc="让局域网设备把某个域名解析到指定 IP，例如 nas.home → 192.168.1.159"
      action={can('system.manage') ? <Button variant="ghost" size="sm" onClick={() => setEdit({ section: '', name: '', ip: '' })}><Plus /> 添加</Button> : undefined}>
      {!list.length ? <Empty>还没有自定义解析</Empty> : (
        <div className="divide-y">
          {list.map((h) => (
            <div key={h.section} className="flex items-center gap-3 px-4 py-2.5 text-sm">
              <span className="min-w-0 flex-1 truncate font-medium">{h.name}</span>
              <span className="font-mono text-xs text-muted-foreground">{h.ip}</span>
              <div className={cn('flex', !h.editable && 'invisible')}>
                <Button variant="ghost" size="icon-sm" title="修改" onClick={() => setEdit({ section: h.section, name: h.name, ip: h.ip })}><Pencil /></Button>
                <Button variant="ghost" size="icon-sm" title="删除" onClick={() => del(h)}><Trash2 /></Button>
              </div>
            </div>
          ))}
        </div>
      )}
      <Dialog open={!!edit} onOpenChange={(o) => { if (!o) setEdit(null) }}>
        <DialogContent>
          <DialogHeader><DialogTitle>{edit?.section ? '修改解析' : '添加解析'}</DialogTitle></DialogHeader>
          {edit && (
            <div className="grid gap-3">
              <Field label="域名" hint="可以是内网名称（nas.home）或覆盖公网域名"><Input value={edit.name} placeholder="nas.home" onChange={(e) => setEdit({ ...edit, name: e.target.value.trim() })} /></Field>
              <Field label="IP 地址"><Input value={edit.ip} placeholder="192.168.1.159" className="font-mono" onChange={(e) => setEdit({ ...edit, ip: e.target.value.trim() })} /></Field>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEdit(null)}>取消</Button>
            <Button disabled={!edit?.name || !edit?.ip} onClick={save}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {dialog}
    </Section>
  )
}
