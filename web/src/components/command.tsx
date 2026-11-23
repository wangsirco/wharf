import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CornerDownLeft, Search } from 'lucide-react'
import { get } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import type { Device } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import { DeviceIcon } from '@/components/device-icon'
import { tocId } from '@/components/page-toc'

interface Item { key: string; label: string; sub?: string; to: string; device?: Device; setting?: boolean }

const PAGES: { to: string; label: string; perm?: string; super?: boolean; kw: string }[] = [
  { to: '/', label: '概览', perm: 'dashboard.view', kw: 'dashboard overview gailan' },
  { to: '/screen', label: '大屏模式', perm: 'dashboard.view', kw: 'screen dapin' },
  { to: '/network', label: '网络（延迟 / 掉线 / 测速）', perm: 'dashboard.view', kw: 'network wangluo ping speedtest cesu' },
  { to: '/interfaces', label: '网络接口（WAN / LAN / 公网 IP）', perm: 'network.view', kw: 'interface jiekou wan lan pppoe ip gongwang duanwang' },
  { to: '/dhcp', label: 'DHCP 与 DNS（固定 IP / 上游 DNS）', perm: 'network.view', kw: 'dhcp dns guding static lease shangyou' },
  { to: '/firewall', label: '防火墙（区域 / 通信规则）', perm: 'network.view', kw: 'firewall fanghuoqiang zone rule guize' },
  { to: '/plugins', label: '插件（已安装 / 插件商店）', perm: 'plugins.view', kw: 'plugin chajian luci openclash passwall store shangdian' },
  { to: '/devices', label: '设备', perm: 'devices.view', kw: 'devices shebei' },
  { to: '/traffic', label: '流量统计', perm: 'traffic.view', kw: 'traffic liuliang' },
  { to: '/world', label: '全球流量地图', perm: 'traffic.view', kw: 'world map ditu quanqiu' },
  { to: '/dns', label: 'NextDNS 统计（拦截原因 / 查询记录）', perm: 'traffic.view', kw: 'dns nextdns lanjie tongji' },
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
  { to: '/remote', label: '外网访问（从外面打开面板）', super: true, kw: 'remote waiwang gongwang yuming domain tunnel suidao chengseyun' },
  { to: '/cloudflare', label: 'Cloudflare（隧道 / 防攻击 / Access）', super: true, kw: 'cloudflare cf tunnel suidao attack access' },
  { to: '/berth', label: 'Berth 服务器面板', super: true, kw: 'berth bowei server fuwuqi' },
  { to: '/ddns', label: '动态域名 DDNS', super: true, kw: 'ddns dongtai yuming' },
]

// Settings and sections inside pages: Enter goes to the page and scrolls to the section.
const at = (page: string, title: string) => page + '#' + tocId(title)
const SETTINGS: { to: string; label: string; where: string; perm?: string; super?: boolean; kw: string }[] = [
  { to: at('/settings', '面板名称'), label: '面板名称、副标题、时区', where: '系统设置', super: true, kw: 'name mingcheng subtitle timezone shiqu brand' },
  { to: at('/settings', '敏感操作二次确认'), label: '敏感操作二次确认（审批）', where: '系统设置', super: true, kw: 'approval shenpi queren erci' },
  { to: at('/settings', '日志保留与判定'), label: '日志保留天数、离开网络判定', where: '系统设置', super: true, kw: 'retention log rizhi baoliu likai away' },
  { to: at('/settings?tab=data', '设备识别'), label: '设备识别（DHCP 指纹、mDNS）', where: '系统设置 · 数据源', super: true, kw: 'identity dhcp fingerprint zhiwen mdns bonjour upnp shibie' },
  { to: at('/settings?tab=data', 'NextDNS'), label: 'NextDNS API Key', where: '系统设置 · 数据源', super: true, kw: 'nextdns api key profile' },
  { to: at('/settings?tab=data', 'Proxmox VE（可选）'), label: 'Proxmox VE 连接', where: '系统设置 · 数据源', super: true, kw: 'pve proxmox xuniji vm' },
  { to: at('/settings?tab=data', 'IP 离线库'), label: 'IP 离线库', where: '系统设置 · 数据源', super: true, kw: 'geo ip dbip ku' },
  { to: at('/settings?tab=data', '内容识别规则库'), label: '内容识别规则库', where: '系统设置 · 数据源', super: true, kw: 'rules guize shibie' },
  { to: at('/settings?tab=update', '版本与更新'), label: '版本与更新', where: '系统设置 · 更新与维护', super: true, kw: 'update gengxin version banben shengji upgrade' },
  { to: at('/settings?tab=update', '路由器 Agent'), label: '路由器 Agent 状态', where: '系统设置 · 更新与维护', super: true, kw: 'agent' },
  { to: '/remote#panel-names', label: '面板域名、公网证书', where: '外网访问', super: true, kw: 'yuming domain cert zhengshu 443 passkey gongwang' },
  { to: '/cloudflare?tab=tunnel', label: 'Cloudflare 隧道', where: 'Cloudflare', super: true, kw: 'tunnel suidao cloudflared' },
  { to: '/cloudflare?tab=zones', label: '受攻击模式、清除缓存', where: 'Cloudflare', super: true, kw: 'attack gongji under fangyu cache huancun purge' },
  { to: '/cloudflare?tab=access', label: 'Access 登录保护（邮箱验证码）', where: 'Cloudflare', super: true, kw: 'access email youxiang yanzhengma baohu' },
  { to: at('/account', 'Passkey'), label: 'Passkey', where: '我的账号', kw: 'passkey touchid faceid tongxingmiyao' },
  { to: at('/account', '登录方式'), label: '登录方式（密码 / Passkey / 两步）', where: '我的账号', kw: 'login denglu two step liangbu' },
  { to: at('/account', '修改密码'), label: '修改密码', where: '我的账号', kw: 'password mima xiugai' },
  { to: at('/dhcp', 'DNS 缓存与排查'), label: 'DNS 缓存与排查（刷新缓存）', where: 'DHCP 与 DNS', perm: 'network.view', kw: 'dns cache huancun shuaxin flush jiexi trace nextdns' },
  { to: at('/dhcp', 'DNS'), label: '上游 DNS、重绑定保护', where: 'DHCP 与 DNS', perm: 'network.view', kw: 'dns upstream shangyou server rebind chongbangding' },
  { to: at('/dhcp', '静态分配（固定 IP）'), label: '固定 IP（静态分配）', where: 'DHCP 与 DNS', perm: 'network.view', kw: 'static guding ip dhcp host' },
  { to: at('/access', '公网访问'), label: '公网访问地区限制', where: '面板访问控制', super: true, kw: 'region diqu geo country guojia gongwang' },
  { to: at('/access', 'IP 白名单 / 黑名单'), label: 'IP 白名单 / 黑名单', where: '面板访问控制', super: true, kw: 'whitelist blacklist baimingdan heimingdan lahei ban' },
  { to: at('/alerts', '推送渠道'), label: '告警推送渠道（Telegram 等）', where: '告警推送', super: true, kw: 'telegram bark serverchan tuisong qudao' },
  { to: at('/tools', '自定义解析（hosts）'), label: '自定义域名解析（hosts）', where: '网络工具', perm: 'system.view', kw: 'hosts jiexi custom zidingyi domain lan' },
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
    const sets = !s ? [] : SETTINGS.filter((x) => (x.super ? isSuper : !x.perm || can(x.perm)))
      .filter((x) => x.label.toLowerCase().includes(s) || x.where.toLowerCase().includes(s) || x.kw.includes(s))
      .map((x) => ({ key: 's' + x.to, label: x.label, sub: x.where, to: x.to, setting: true }))
    return [...devs, ...sets, ...pages].slice(0, 16)
  }, [q, devices, can, isSuper])

  const go = (it?: Item) => { if (!it) return; setOpen(false); navigate(it.to) }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent showCloseButton={false} className="top-[20%] translate-y-0 gap-0 p-0 sm:max-w-lg">
        <DialogTitle className="sr-only">搜索</DialogTitle>
        <div className="flex items-center gap-2 border-b px-3">
          <Search className="size-4 text-muted-foreground" />
          <input autoFocus className="h-11 flex-1 bg-transparent text-sm outline-none" placeholder="搜索设备、页面或设置项（如 Passkey、DNS 缓存）…" value={q}
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
              {it.device ? <DeviceIcon type={it.device.type} online={it.device.online} className="size-7" /> : <span className="grid size-7 place-items-center rounded-lg bg-muted text-xs text-muted-foreground">{it.setting ? '设' : '页'}</span>}
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
