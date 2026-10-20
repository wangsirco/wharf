import { useEffect, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  Activity, ArrowLeftRight, BarChart3, Ban, BellRing, Earth, ShieldAlert, Search as SearchIcon, ClipboardCheck, Globe, LayoutDashboard, ShieldHalf, LogOut, Menu, Monitor, Moon, ScrollText, Settings, Sun, Users, X, KeyRound, Inbox, Wrench, Cpu, Sparkles, ArrowUpCircle,
} from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { useApi } from '@/lib/hooks'
import { useBrand } from '@/lib/brand'
import { applyTheme, getTheme, type Theme } from '@/lib/theme'
import { sendBeacon } from '@/lib/beacon'
import { cn } from '@/lib/utils'
import { BrandMark } from '@/components/brand-mark'
import { CommandPalette } from '@/components/command'
import { ModeSwitch, useMode } from '@/lib/mode'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

interface NavItem { to: string; label: string; icon: typeof Activity; perm?: string; super?: boolean }

const nav: { title?: string; items: NavItem[] }[] = [
  {
    items: [
      { to: '/', label: '概览', icon: LayoutDashboard, perm: 'dashboard.view' },
      { to: '/network', label: '网络', icon: Activity, perm: 'dashboard.view' },
      { to: '/devices', label: '设备', icon: Monitor, perm: 'devices.view' },
      { to: '/traffic', label: '流量统计', icon: BarChart3, perm: 'traffic.view' },
      { to: '/world', label: '全球流量', icon: Earth, perm: 'traffic.view' },
      { to: '/dns', label: 'DNS 拦截', icon: ShieldAlert, perm: 'traffic.view' },
      { to: '/forwards', label: '端口转发', icon: ArrowLeftRight, perm: 'forwards.view' },
      { to: '/controls', label: '设备管控', icon: Ban, perm: 'access.manage' },
      { to: '/tools', label: '网络工具', icon: Wrench, perm: 'tools.diag|tools.capture|tools.wol|system.view' },
      { to: '/system', label: '系统维护', icon: Cpu, perm: 'system.view' },
      { to: '/requests', label: '我的申请', icon: Inbox },
    ],
  },
  {
    title: '管理',
    items: [
      { to: '/users', label: '用户与权限', icon: Users, super: true },
      { to: '/approvals', label: '审批', icon: ClipboardCheck, super: true },
      { to: '/audit', label: '操作审计', icon: ScrollText, super: true },
      { to: '/visitors', label: '访问记录', icon: Globe, super: true },
      { to: '/alerts', label: '告警推送', icon: BellRing, super: true },
      { to: '/access', label: '面板访问控制', icon: ShieldHalf, super: true },
      { to: '/settings', label: '系统设置', icon: Settings, super: true },
    ],
  },
]

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const brand = useBrand()
  const { can, isSuper } = useAuth()
  return (
    <nav className="flex h-full flex-col gap-6 px-3 py-4">
      <div className="flex items-center gap-2.5 px-2">
        <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-gradient-to-b from-[#3b8bf6] to-[#1d5fe0] text-white"><BrandMark className="size-5" /></div>
        <div className="min-w-0 leading-tight">
          <div className="truncate text-sm font-semibold">{brand.name}</div>
          {brand.subtitle && <div className="truncate text-[11px] text-muted-foreground">{brand.subtitle}</div>}
        </div>
      </div>
      {nav.map((group, gi) => {
        const items = group.items.filter((i) => (i.super ? isSuper : !i.perm || i.perm.split('|').some((p) => can(p))))
        if (!items.length) return null
        return (
          <div key={gi} className="flex flex-col gap-0.5">
            {group.title && <div className="px-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{group.title}</div>}
            {items.map((i) => (
              <NavLink
                key={i.to}
                to={i.to}
                end={i.to === '/'}
                onClick={onNavigate}
                className={({ isActive }) => cn(
                  'flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm text-sidebar-foreground transition-colors hover:bg-muted',
                  isActive && 'bg-sidebar-accent font-medium text-sidebar-accent-foreground hover:bg-sidebar-accent',
                )}
              >
                <i.icon className="size-4" />
                {i.label}
              </NavLink>
            ))}
          </div>
        )
      })}
    </nav>
  )
}

function UserMenu() {
  const { user, logout } = useAuth()
  const [theme, setTheme] = useState<Theme>(getTheme())
  const pick = (t: Theme) => { setTheme(t); applyTheme(t) }
  if (!user) return null
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" size="sm" className="shrink-0 gap-2" />}>
        <span className="grid size-6 place-items-center rounded-full bg-accent text-[11px] font-semibold text-accent-foreground">
          {user.display_name.slice(0, 1).toUpperCase()}
        </span>
        <span className="hidden max-w-32 truncate sm:inline">{user.display_name}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <div className="px-2 py-1.5 text-xs text-muted-foreground">
          {user.username} · ID {user.id} · {user.role === 'super' ? '超级管理员' : '管理员'}
        </div>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => pick(theme === 'dark' ? 'light' : 'dark')}>
          {theme === 'dark' ? <Sun /> : <Moon />} {theme === 'dark' ? '浅色模式' : '深色模式'}
        </DropdownMenuItem>
        <DropdownMenuItem render={<NavLink to="/account" />}><KeyRound /> 修改密码</DropdownMenuItem>
        <DropdownMenuItem onClick={() => window.dispatchEvent(new Event('owp:welcome'))}><Sparkles /> 使用向导</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onClick={logout}><LogOut /> 退出登录</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function Layout() {
  const [open, setOpen] = useState(false)
  const loc = useLocation()
  useEffect(() => { sendBeacon(loc.pathname) }, [loc.pathname])

  return (
    <div className="flex min-h-svh">
      <aside className="sticky top-0 hidden h-svh w-56 shrink-0 border-r border-sidebar-border bg-sidebar lg:block">
        <Sidebar />
      </aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/30" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-60 border-r bg-sidebar">
            <Button variant="ghost" size="icon-sm" className="absolute right-2 top-3" onClick={() => setOpen(false)}><X /></Button>
            <Sidebar onNavigate={() => setOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-12 items-center gap-2 border-b bg-background/85 px-3 backdrop-blur sm:px-4">
          <Button variant="ghost" size="icon-sm" className="lg:hidden" onClick={() => setOpen(true)}><Menu /></Button>
          <button type="button" onClick={() => window.dispatchEvent(new Event('owp:search'))}
            className="flex h-8 shrink-0 items-center gap-2 rounded-lg border bg-card px-2.5 text-sm text-muted-foreground hover:bg-muted/60 sm:w-full sm:max-w-72 sm:shrink" title="搜索">
            <SearchIcon className="size-3.5" /><span className="hidden flex-1 text-left sm:inline">搜索设备或页面</span>
            <kbd className="hidden rounded border px-1 text-[10px] sm:inline">⌘K</kbd>
          </button>
          <div className="flex-1" />
          <UpdateBadge />
          <ModeSwitch />
          <UserMenu />
        </header>
        <main className="min-w-0 flex-1 p-3 sm:p-4 md:p-6">
          <Outlet />
        </main>
        <CommandPalette />
      </div>
    </div>
  )
}

export function PageHeader({ title, desc, children }: { title: string; desc?: string; children?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3 sm:mb-5">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {desc && <p className="mt-0.5 text-sm text-muted-foreground">{desc}</p>}
      </div>
      {children && <div className="flex max-w-full flex-wrap items-center gap-2">{children}</div>}
    </div>
  )
}

// SimpleLayout: no sidebar — just the device wall and device pages.
export function SimpleLayout() {
  const loc = useLocation()
  useEffect(() => { sendBeacon(loc.pathname) }, [loc.pathname])
  return (
    <div className="min-h-svh">
      <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/85 px-3 backdrop-blur sm:gap-3 md:px-8">
        <NavLink to="/" className="flex items-center gap-2.5">
          <div className="grid size-8 place-items-center rounded-lg bg-gradient-to-b from-[#3b8bf6] to-[#1d5fe0] text-white"><BrandMark className="size-5" /></div>
          <span className="font-semibold whitespace-nowrap">家庭网络</span>
        </NavLink>
        <div className="flex-1" />
        <ModeSwitch />
        <UserMenu />
      </header>
      <main className="mx-auto max-w-[1600px] p-3 sm:p-4 md:p-8"><Outlet /></main>
    </div>
  )
}

export function useIsSimple() { return useMode().mode === 'simple' }

// UpdateBadge: tells the super admin a newer release is on GitHub.
function UpdateBadge() {
  const { isSuper } = useAuth()
  const { data } = useApi<{ newer: boolean; latest?: string }>(isSuper ? '/update' : null, 30 * 60 * 1000)
  if (!data?.newer) return null
  return (
    <NavLink to="/settings#update" className="hidden shrink-0 items-center gap-1 rounded-full bg-success/12 px-2.5 py-1 text-xs font-medium text-success hover:bg-success/20 sm:flex">
      <ArrowUpCircle className="size-3.5" />新版本 {data.latest}
    </NavLink>
  )
}
