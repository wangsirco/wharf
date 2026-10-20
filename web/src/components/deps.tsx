import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Link } from 'react-router-dom'
import { CheckCircle2, CircleDashed, Download, Loader2, PackageX, Puzzle, Trash2 } from 'lucide-react'
import { get, post } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'
import { Pill, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'

export interface Dep {
  id: string; name: string; pkg: string; level: 'core' | 'recommended' | 'optional'; purpose: string; features: string[] | null
  installed: boolean; by_panel: boolean; note?: string; kind?: string
}
interface Job { running: boolean; started: number; ended?: number; ids: string[] | null; log: string[] | null; error?: string; action: string }
interface DepsResp { deps: Dep[]; job: Job }

// one shared, lazily refreshed copy for the hints sprinkled over the tool pages
let cache: DepsResp | null = null
let inflight: Promise<DepsResp> | null = null
const subs = new Set<(d: DepsResp) => void>()
function load(force = false) {
  if (!force && (cache || inflight)) return inflight ?? Promise.resolve(cache!)
  inflight = get<DepsResp>('/deps').then((d) => { cache = d; subs.forEach((f) => f(d)); return d }).finally(() => { inflight = null })
  return inflight
}

export function useDeps(enabled = true) {
  const [d, setD] = useState<DepsResp | null>(cache)
  useEffect(() => {
    if (!enabled) return
    subs.add(setD)
    load().catch(() => {})
    return () => { subs.delete(setD) }
  }, [enabled])
  return { data: d, reload: () => load(true) }
}

const LEVEL: Record<Dep['level'], [string, 'red' | 'blue' | 'muted']> = { core: ['核心', 'red'], recommended: ['推荐', 'blue'], optional: ['可选', 'muted'] }

// DepHint: shown at the top of a feature when a component it needs is missing.
export function DepHint({ ids, className }: { ids: string[]; className?: string }) {
  const { can, isSuper } = useAuth()
  const { data } = useDeps(can('system.view'))
  const missing = (data?.deps ?? []).filter((d) => ids.includes(d.id) && !d.installed)
  if (!missing.length) return null
  return (
    <div className={cn('flex flex-wrap items-center gap-2 rounded-lg border border-warning/40 bg-warning/5 px-3 py-2 text-sm', className)}>
      <PackageX className="size-4 shrink-0 text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning" />
      <span className="min-w-0 flex-1">这个功能需要路由器上的组件：{missing.map((d) => <b key={d.id} className="mx-0.5">{d.name}</b>)}，目前没有安装。</span>
      {isSuper ? <Link to="/system#deps" className="text-xs font-medium text-primary hover:underline">去安装 →</Link> : <span className="text-xs text-muted-foreground">请联系超级管理员安装</span>}
    </div>
  )
}

// DepsPanel: the full component list with one-click install. compact = inside the welcome wizard.
export function DepsPanel({ compact }: { compact?: boolean }) {
  const { isSuper } = useAuth()
  const { data, reload } = useDeps()
  const [sel, setSel] = useState<string[] | null>(null)
  const { confirm, dialog } = useConfirm()
  const job = data?.job
  const deps = data?.deps ?? []
  const missing = deps.filter((d) => !d.installed)
  const chosen = sel ?? missing.filter((d) => d.level !== 'optional').map((d) => d.id)

  useEffect(() => { // follow a running job
    if (!job?.running) return
    const t = setInterval(() => reload(), 1500)
    return () => clearInterval(t)
  }, [job?.running]) // eslint-disable-line react-hooks/exhaustive-deps

  const run = async (action: 'install' | 'remove', ids: string[]) => {
    if (action === 'remove' && !(await confirm('移除这个组件？', '只会移除由面板安装的软件包，依赖它的功能将不可用。', { danger: true, ok: '移除' }))) return
    try { await post('/deps', { action, ids }); await reload(); setSel(null) } catch (e) { toast.error((e as Error).message) }
  }
  useEffect(() => {
    if (job && !job.running && job.ended && Date.now() / 1000 - job.ended < 5) {
      if (job.error) toast.error(job.error); else toast.success(job.action === 'install' ? '组件安装完成' : '组件已移除')
    }
  }, [job?.running]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!data) return <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />检查组件…</div>
  const list = compact ? deps.filter((d) => !d.installed) : deps
  return (
    <div className="grid gap-3">
      {compact && !missing.length && <div className="flex items-center gap-2 rounded-lg border bg-success/5 px-3 py-3 text-sm"><CheckCircle2 className="size-4 text-success" />所有组件都已就绪，全部功能可用。</div>}
      {!!list.length && (
        <div className="divide-y rounded-xl border">
          {list.map((d) => {
            const [lv, tone] = LEVEL[d.level]
            return (
              <div key={d.id} className="flex gap-3 px-3 py-2.5">
                {!d.installed && isSuper
                  ? <Checkbox className="mt-0.5" checked={chosen.includes(d.id)} disabled={job?.running} onCheckedChange={(c) => setSel(c ? [...chosen, d.id] : chosen.filter((x) => x !== d.id))} />
                  : d.installed ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" /> : <CircleDashed className="mt-0.5 size-4 shrink-0 text-muted-foreground" />}
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-1.5 text-sm">
                    <span className="font-medium">{d.name}</span><Pill tone={tone}>{lv}</Pill>
                    {d.pkg && <span className="font-mono text-[11px] text-muted-foreground">{d.pkg}</span>}
                    {d.by_panel && <Pill tone="green">由面板安装</Pill>}
                  </div>
                  <div className="text-xs text-muted-foreground">{d.purpose}{d.features?.length ? ` · 用于：${d.features.join('、')}` : ''}</div>
                  {d.note && <div className="text-[11px] text-muted-foreground">{d.note}</div>}
                </div>
                {!compact && isSuper && d.installed && d.by_panel && (
                  <Button variant="ghost" size="icon-sm" title="移除（由面板安装的）" disabled={job?.running} onClick={() => run('remove', [d.id])}><Trash2 /></Button>
                )}
              </div>
            )
          })}
        </div>
      )}
      {isSuper && missing.length > 0 && (
        <div className="flex flex-wrap items-center gap-3">
          <Button disabled={job?.running || !chosen.length} onClick={() => run('install', chosen)}>
            {job?.running ? <Loader2 className="animate-spin" /> : <Download />} {job?.running ? '正在安装…' : `安装选中的 ${chosen.length} 个组件`}
          </Button>
          <span className="text-xs text-muted-foreground">通过 opkg 从官方软件源安装，需要路由器能上网，约 1 分钟</span>
        </div>
      )}
      {job && (job.running || (job.log?.length && Date.now() / 1000 - (job.ended ?? 0) < 600)) && (
        <pre className="max-h-48 overflow-auto rounded-lg bg-muted/60 p-2.5 font-mono text-[11px] leading-relaxed text-muted-foreground">{(job.log ?? []).join('\n') || '准备中…'}</pre>
      )}
      <p className="flex gap-1.5 text-[11px] text-muted-foreground">
        <Puzzle className="mt-px size-3.5 shrink-0" />
        这些都是 OpenWrt 官方软件包，不会被强制捆绑：面板没有它们也能运行，缺少时对应功能会提示。由面板安装的组件会被记录下来，卸载面板时一并移除（若有其他软件在用则保留）；你原本就装着的组件不会被动到。
      </p>
      {dialog}
    </div>
  )
}
