import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { toast } from 'sonner'
import { Check, CloudOff, Loader2, RotateCcw, ShieldAlert, Undo2, X } from 'lucide-react'
import { get, post } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { duration } from '@/lib/format'
import type { NetHealthResp } from '@/lib/netcfg'
import { Button } from '@/components/ui/button'

// Shown on every page: "外网断了" when the router itself can't reach the internet,
// and the confirm bar for a network change that rolls back unless confirmed.
export function NetBanner() {
  const { can } = useAuth()
  const [h, setH] = useState<NetHealthResp | null>(null)
  const [skew, setSkew] = useState(0) // router clock - browser clock
  const [now, setNow] = useState(() => Date.now() / 1000)
  const [busy, setBusy] = useState(false)
  const [hideRb, setHideRb] = useState(() => Number(localStorage.getItem('owp-rb-seen') || 0))
  const enabled = can('dashboard.view')

  useEffect(() => {
    if (!enabled) return
    let t: number | undefined
    let alive = true
    const load = async () => {
      try {
        const r = await get<NetHealthResp>('/net/health')
        if (!alive) return
        setH(r)
        if (r.ts) setSkew(r.ts - Date.now() / 1000)
      } catch { /* panel unreachable: keep the last state */ }
      if (alive) t = window.setTimeout(load, document.hidden ? 30000 : 10000)
    }
    load()
    const kick = () => { clearTimeout(t); load() }
    window.addEventListener('owp:net-changed', kick)
    return () => { alive = false; clearTimeout(t); window.removeEventListener('owp:net-changed', kick) }
  }, [enabled])

  const pending = h?.pending
  useEffect(() => {
    if (!pending) return
    const i = window.setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(i)
  }, [pending])

  if (!h) return null
  const down = h.checked && h.internet === false
  const left = pending ? Math.max(0, Math.round(pending.deadline - (now + skew))) : 0
  const act = async (keep: boolean) => {
    if (!pending) return
    setBusy(true)
    try {
      await post(keep ? '/net/confirm' : '/net/rollback', { token: pending.token })
      toast.success(keep ? '已确认，改动会保留' : '已撤销，恢复为改动前的设置')
      window.dispatchEvent(new Event('owp:net-changed'))
      window.dispatchEvent(new Event('owp:net-confirmed'))
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const rb = h.rollback && h.rollback.at > hideRb && Date.now() / 1000 + skew - h.rollback.at < 1800 ? h.rollback : null
  const wanDown = (h.wans ?? []).length > 0 && (h.wans ?? []).every((w) => !w.up)
  const reason = wanDown ? 'WAN 口断开了' : h.gateway && !h.gateway_ok ? '运营商的网关也没有回应' : '运营商网关之后不通'

  return (
    <>
      {down && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive">
          <CloudOff className="size-4 shrink-0" />
          <span className="font-medium">外网断了</span>
          <span className="text-destructive/80">{h.down_since ? `已经 ${duration(Math.max(0, Math.round(now + skew - h.down_since)))}` : ''} · {reason}</span>
          <span className="flex-1" />
          {can('network.view') || can('dashboard.view') ? (
            <Link to="/interfaces?diagnose=1" className="rounded-md bg-destructive px-2.5 py-1 text-xs font-medium text-white hover:bg-destructive/90">查找原因</Link>
          ) : null}
        </div>
      )}
      {pending && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-warning/40 bg-warning/15 px-4 py-2 text-sm">
          <ShieldAlert className="size-4 shrink-0 text-warning" />
          <span><span className="font-medium">网络改动已生效，等待确认</span>{pending.summary && <span className="text-muted-foreground">（{pending.summary}）</span>}</span>
          <span className="text-muted-foreground">{left > 0 ? `${left} 秒内不确认就自动撤销` : '正在撤销…'}</span>
          <span className="flex-1" />
          <Button size="sm" variant="outline" disabled={busy} onClick={() => act(false)}><Undo2 /> 撤销</Button>
          <Button size="sm" disabled={busy} onClick={() => act(true)}>{busy ? <Loader2 className="animate-spin" /> : <Check />} 一切正常，保留</Button>
        </div>
      )}
      {!pending && rb && (
        <div className="flex items-center gap-3 border-b bg-muted/60 px-4 py-2 text-sm">
          <RotateCcw className="size-4 shrink-0 text-muted-foreground" />
          <span>刚才的网络改动没有被确认，路由器已经自动恢复成改动前的设置{rb.why === 'restart' ? '（路由器或 Wharf 在等待确认时重启了）' : ''}。</span>
          <span className="flex-1" />
          <Button variant="ghost" size="icon-sm" onClick={() => { localStorage.setItem('owp-rb-seen', String(rb.at)); setHideRb(rb.at) }}><X /></Button>
        </div>
      )}
    </>
  )
}
