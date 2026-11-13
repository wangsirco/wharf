import { useEffect, useRef, useState } from 'react'
import { CheckCircle2, CircleDashed, Loader2, Puzzle, XCircle } from 'lucide-react'
import { importPlugin, type ImportedPage } from '@/lib/plugin-import'
import type { PluginItem } from '@/lib/plugins'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

interface Row { p: PluginItem; state: 'wait' | 'run' | 'done' | 'error'; done: number; total: number; pages: ImportedPage[]; error?: string }

/** Imports the given plugins one after another, converting every page of each. */
export function ImportDialog({ plugins, onClose }: { plugins: PluginItem[]; onClose: (changed: boolean) => void }) {
  const [rows, setRows] = useState<Row[]>(() => plugins.map((p) => ({ p, state: 'wait', done: 0, total: 0, pages: [] })))
  const [running, setRunning] = useState(true)
  const started = useRef(false)
  useEffect(() => {
    if (started.current) return
    started.current = true
    const upd = (i: number, f: (r: Row) => Row) => setRows((rs) => rs.map((r, j) => (j === i ? f(r) : r)))
    ;(async () => {
      for (let i = 0; i < plugins.length; i++) {
        upd(i, (r) => ({ ...r, state: 'run' }))
        try {
          await importPlugin(plugins[i], (done, total, page) => upd(i, (r) => ({ ...r, done, total, pages: page ? [...r.pages, page] : r.pages })))
          upd(i, (r) => ({ ...r, state: 'done' }))
        } catch (e) {
          upd(i, (r) => ({ ...r, state: 'error', error: (e as Error).message }))
        }
      }
      setRunning(false)
    })()
  }, [plugins])

  const ok = rows.reduce((n, r) => n + r.pages.filter((g) => g.status === 'ok').length, 0)
  const other = rows.reduce((n, r) => n + r.pages.filter((g) => g.status !== 'ok').length, 0)
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !running) onClose(true) }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Puzzle className="size-4" />导入到 Wharf</DialogTitle>
          <DialogDescription>
            {running ? '正在把插件的每个设置页换成 Wharf 的样式，只需做这一次；之后打开就是现成的。请不要关闭这个页面。'
              : `完成：${ok} 个页面已换成 Wharf 样式${other ? `，${other} 个是插件自己画的界面或没能转换，会提供 LuCI 原页面入口` : ''}。`}
          </DialogDescription>
        </DialogHeader>
        <div className="grid max-h-[50vh] gap-2 overflow-y-auto">
          {rows.map((r) => (
            <div key={r.p.pkg} className="rounded-lg border px-3 py-2 text-sm">
              <div className="flex items-center gap-2">
                {r.state === 'wait' ? <CircleDashed className="size-4 text-muted-foreground" /> : r.state === 'run' ? <Loader2 className="size-4 animate-spin text-primary" />
                  : r.state === 'done' ? <CheckCircle2 className="size-4 text-success" /> : <XCircle className="size-4 text-destructive" />}
                <span className="font-medium">{r.p.title}</span>
                <span className="flex-1" />
                <span className="text-xs text-muted-foreground">{r.total ? `${r.done} / ${r.total} 页` : r.state === 'done' ? '没有设置页' : ''}</span>
              </div>
              {r.error && <div className="mt-1 text-xs text-destructive">{r.error}</div>}
              {r.pages.length > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {r.pages.map((g) => (
                    <span key={g.path} title={g.error} className={g.status === 'ok' ? 'rounded bg-success/12 px-1.5 py-0.5 text-[11px] text-success' : 'rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground'}>
                      {g.title}{g.status === 'custom' ? '（原界面）' : g.status === 'failed' ? '（未转换）' : ''}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
        <DialogFooter><Button disabled={running} onClick={() => onClose(true)}>{running ? '导入中…' : '完成'}</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
