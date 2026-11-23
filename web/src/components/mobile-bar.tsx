import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import { toast } from 'sonner'
import { Anchor, Ban, Home, MonitorSmartphone, RefreshCw, Search } from 'lucide-react'
import { post } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { openBerth, useBerth } from '@/lib/berth'
import { cn } from '@/lib/utils'
import { useConfirm } from '@/components/common'

// MobileBar: on phones, the things people reach for most sit under the thumb — overview,
// devices, cutting a device off, refreshing DNS, and Berth (or search when not paired).
export function MobileBar() {
  const { can } = useAuth()
  const berth = useBerth()
  const { confirm, dialog } = useConfirm()
  const [busy, setBusy] = useState(false)
  const flush = async () => {
    if (!(await confirm('刷新 DNS 缓存？', '清空路由器的 DNS 缓存（含 NextDNS 等本地上游），不会断网。新建的域名打不开时用它。', { ok: '刷新' }))) return
    setBusy(true)
    try {
      const r = await post<{ results: { ok: boolean; error?: string }[] }>('/net/dns/flush', { targets: ['upstream', 'dnsmasq'] })
      const bad = r.results.filter((x) => !x.ok && !x.error?.includes('不是 Wharf 能清缓存')) // no local upstream: dnsmasq alone is enough
      if (bad.length) toast.error(bad.map((x) => x.error).join('；'))
      else toast.success('DNS 缓存已刷新')
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const item = 'flex flex-1 flex-col items-center gap-0.5 py-1.5 text-[11px] text-muted-foreground'
  const link = ({ isActive }: { isActive: boolean }) => cn(item, isActive && 'text-primary')
  return (
    <>
      <nav aria-label="常用操作" className="fixed inset-x-0 bottom-0 z-30 flex border-t bg-background/95 pb-[env(safe-area-inset-bottom)] backdrop-blur md:hidden">
        <NavLink to="/" end className={link}><Home className="size-5" />概览</NavLink>
        {can('devices.view') && <NavLink to="/devices" className={link}><MonitorSmartphone className="size-5" />设备</NavLink>}
        {can('access.manage') && <NavLink to="/controls" className={link}><Ban className="size-5" />断网</NavLink>}
        {can('network.manage') && <button type="button" className={item} disabled={busy} onClick={flush}><RefreshCw className={cn('size-5', busy && 'animate-spin')} />刷新 DNS</button>}
        {berth.paired && berth.state === 'active'
          ? <button type="button" className={item} onClick={() => openBerth().catch((e) => toast.error((e as Error).message))}><Anchor className="size-5" />Berth</button>
          : <button type="button" className={item} onClick={() => window.dispatchEvent(new Event('owp:search'))}><Search className="size-5" />搜索</button>}
      </nav>
      {dialog}
    </>
  )
}
