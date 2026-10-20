import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CornerDownLeft, Search } from 'lucide-react'
import { get } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import type { Device } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { DeviceIcon } from '@/components/device-icon'

interface Item { key: string; label: string; sub?: string; to: string; device?: Device }

const PAGES: { to: string; label: string; perm?: string; super?: boolean; kw: string }[] = [
  { to: '/', label: '概览', perm: 'dashboard.view', kw: 'dashboard overview gailan' },
  { to: '/screen', label: '大屏模式', perm: 'dashboard.view', kw: 'screen dapin' },
  { to: '/network', label: '网络（延迟 / 掉线 / 测速）', perm: 'dashboard.view', kw: 'network wangluo ping speedtest cesu' },
  { to: '/devices', label: '设备', perm: 'devices.view', kw: 'devices shebei' },
  { to: '/traffic', label: '流量统计', perm: 'traffic.view', kw: 'traffic liuliang' },
  { to: '/world', label: '全球流量地图', perm: 'traffic.view', kw: 'world map ditu quanqiu' },
  { to: '/dns', label: 'DNS 与 NextDNS', perm: 'traffic.view', kw: 'dns nextdns lanjie' },
  { to: '/alerts', label: '告警推送', super: true, kw: 'alerts gaojing telegram serverchan' },
  { to: '/forwards', label: '端口转发', perm: 'forwards.view', kw: 'forward port zhuanfa' },
  { to: '/controls', label: '设备管控', perm: 'access.manage', kw: 'control block duanwang guankong' },
  { to: '/system', label: '系统维护', perm: 'system.view', kw: 'system reboot chongqi log rizhi backup beifen cpu disk plugin chajian' },
  { to: '/tools', label: '网络工具', perm: 'system.view', kw: 'tools wol wake huanxing upnp hosts jiexi' },
  { to: '/users', label: '用户与权限', super: true, kw: 'users yonghu' },
  { to: '/approvals', label: '审批', super: true, kw: 'approval shenpi' },
  { to: '/audit', label: '操作审计', super: true, kw: 'audit shenji' },
  { to: '/visitors', label: '访问记录', super: true, kw: 'visitors fangwen' },
  { to: '/access', label: '面板访问控制', super: true, kw: 'access' },
  { to: '/settings', label: '系统设置', super: true, kw: 'settings shezhi' },
]

export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const [devices, setDevices] = useState<Device[]>([])
  const { can, isSuper } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setOpen((o) => !o) }
    }
    const onOpen = () => setOpen(true)
    window.addEventListener('keydown', onKey)
    window.addEventListener('owp:search', onOpen)
    return () => { window.removeEventListener('keydown', onKey); window.removeEventListener('owp:search', onOpen) }
  }, [])
  useEffect(() => {
    if (open) { setQ(''); setSel(0); if (can('devices.view')) get<Device[]>('/devices').then(setDevices).catch(() => {}) }
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  const items = useMemo<Item[]>(() => {
    const s = q.trim().toLowerCase()
    const pages = PAGES.filter((p) => (p.super ? isSuper : !p.perm || can(p.perm)))
      .filter((p) => !s || p.label.toLowerCase().includes(s) || p.kw.includes(s))
      .map((p) => ({ key: 'p' + p.to, label: p.label, sub: '页面', to: p.to }))
    const devs = !s ? [] : devices.filter((d) => [d.name, d.ip, d.mac, d.vendor, d.alias, d.hostname, d.type, d.os].some((v) => (v ?? '').toLowerCase().includes(s)))
      .slice(0, 8).map((d) => ({ key: 'd' + d.mac, label: d.name || d.ip, sub: `${d.ip} · ${d.type}`, to: `/devices/${d.mac}`, device: d }))
    return [...devs, ...pages].slice(0, 14)
  }, [q, devices, can, isSuper])

  const go = (it?: Item) => { if (!it) return; setOpen(false); navigate(it.to) }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent showCloseButton={false} className="top-[20%] translate-y-0 gap-0 p-0 sm:max-w-lg">
        <DialogTitle className="sr-only">搜索</DialogTitle>
        <div className="flex items-center gap-2 border-b px-3">
          <Search className="size-4 text-muted-foreground" />
          <input autoFocus className="h-11 flex-1 bg-transparent text-sm outline-none" placeholder="搜索设备（名称 / IP / MAC / 厂商）或页面…" value={q}
            onChange={(e) => { setQ(e.target.value); setSel(0) }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setSel((x) => Math.min(x + 1, items.length - 1)) }
              if (e.key === 'ArrowUp') { e.preventDefault(); setSel((x) => Math.max(x - 1, 0)) }
              if (e.key === 'Enter') { e.preventDefault(); go(items[sel]) }
            }} />
          <kbd className="rounded border px-1.5 text-[10px] text-muted-foreground">Esc</kbd>
        </div>
        <div className="max-h-80 overflow-y-auto py-1">
          {items.map((it, i) => (
            <button key={it.key} type="button" onMouseEnter={() => setSel(i)} onClick={() => go(it)}
              className={cn('flex w-full items-center gap-3 px-3 py-2 text-left text-sm', i === sel && 'bg-accent text-accent-foreground')}>
              {it.device ? <DeviceIcon type={it.device.type} online={it.device.online} className="size-7" /> : <span className="grid size-7 place-items-center rounded-lg bg-muted text-xs text-muted-foreground">页</span>}
              <span className="flex-1 truncate">{it.label}</span>
              <span className="text-xs text-muted-foreground">{it.sub}</span>
              {i === sel && <CornerDownLeft className="size-3.5 text-muted-foreground" />}
            </button>
          ))}
          {!items.length && <div className="px-3 py-6 text-center text-sm text-muted-foreground">没有结果</div>}
        </div>
      </DialogContent>
    </Dialog>
  )
}
