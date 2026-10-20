import { useState, type ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'

// HalfPanel: the right-hand half-screen detail/edit panel used across the app.
export function HalfPanel({ open, onOpenChange, title, desc, children, footer }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: ReactNode; desc?: ReactNode; children: ReactNode; footer?: ReactNode
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="data-[side=right]:w-full data-[side=right]:sm:max-w-none data-[side=right]:md:w-1/2 gap-0">
        <SheetHeader className="border-b px-6 py-4">
          <SheetTitle className="text-base">{title}</SheetTitle>
          {desc && <SheetDescription>{desc}</SheetDescription>}
        </SheetHeader>
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
        {footer && <SheetFooter className="flex-row justify-end border-t px-6 py-3">{footer}</SheetFooter>}
      </SheetContent>
    </Sheet>
  )
}

export function Field({ label, hint, children, className }: { label: string; hint?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cn('grid gap-1.5', className)}>
      <Label className="text-xs font-medium text-muted-foreground">{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

export function Section({ title, desc, children, action, className }: { title: string; desc?: string; children: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <section className={cn('rounded-xl border bg-card', className)}>
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b px-4 py-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">{title}</h2>
          {desc && <p className="text-xs text-muted-foreground">{desc}</p>}
        </div>
        {action}
      </div>
      <div>{children}</div>
    </section>
  )
}

export function Dot({ tone }: { tone: 'ok' | 'warn' | 'bad' | 'off' }) {
  const c = { ok: 'bg-success', warn: 'bg-warning', bad: 'bg-destructive', off: 'bg-muted-foreground/40' }[tone]
  return <span className={cn('inline-block size-2 shrink-0 rounded-full', c)} />
}

export function Pill({ tone = 'muted', children }: { tone?: 'muted' | 'blue' | 'green' | 'amber' | 'red'; children: ReactNode }) {
  const c = {
    muted: 'bg-muted text-muted-foreground',
    blue: 'bg-accent text-accent-foreground',
    green: 'bg-success/12 text-success',
    amber: 'bg-warning/18 text-[color-mix(in_oklch,var(--warning),black_35%)] dark:text-warning',
    red: 'bg-destructive/10 text-destructive',
  }[tone]
  return <span className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium whitespace-nowrap', c)}>{children}</span>
}

// VMTag marks a virtual machine / container next to its own name ("PVE 虚拟机 #105").
export function VMTag({ tag }: { tag?: string }) {
  if (!tag) return null
  return <span className="inline-flex shrink-0 items-center rounded-md border border-violet-500/30 bg-violet-500/10 px-1.5 py-px text-[10px] font-medium whitespace-nowrap text-violet-600 dark:text-violet-300">{tag}</span>
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="px-4 py-12 text-center text-sm text-muted-foreground">{children}</div>
}

export function ErrorBox({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">{children}</div>
}

// useConfirm: promise-based confirmation dialog.
export function useConfirm() {
  const [state, setState] = useState<{ title: string; desc?: ReactNode; danger?: boolean; ok?: string; resolve: (v: boolean) => void } | null>(null)
  const confirm = (title: string, desc?: ReactNode, opts: { danger?: boolean; ok?: string } = {}) =>
    new Promise<boolean>((resolve) => setState({ title, desc, ...opts, resolve }))
  const close = (v: boolean) => { state?.resolve(v); setState(null) }
  const dialog = (
    <Dialog open={!!state} onOpenChange={(o) => { if (!o) close(false) }}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{state?.title}</DialogTitle>
          {state?.desc && <DialogDescription render={<div />}>{state.desc}</DialogDescription>}
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => close(false)}>取消</Button>
          <Button variant={state?.danger ? 'destructive' : 'default'} onClick={() => close(true)}>{state?.ok ?? '确定'}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
  return { confirm, dialog }
}

// ValueDiff shows before/after of an audit entry key by key.
export function ValueDiff({ before, after }: { before: unknown; after: unknown }) {
  const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
  const fmt = (v: unknown) => (v === undefined ? '' : typeof v === 'string' ? v : JSON.stringify(v))
  if (!isObj(before) && !isObj(after)) {
    if (before == null && after == null) return <p className="text-sm text-muted-foreground">无数值变更</p>
    return (
      <div className="grid gap-2 text-sm">
        <div><span className="text-muted-foreground">原值：</span><code className="rounded bg-destructive/8 px-1">{fmt(before) || '（空）'}</code></div>
        <div><span className="text-muted-foreground">新值：</span><code className="rounded bg-success/10 px-1">{fmt(after) || '（空）'}</code></div>
      </div>
    )
  }
  const b = isObj(before) ? before : {}
  const a = isObj(after) ? after : {}
  const keys = [...new Set([...Object.keys(b), ...Object.keys(a)])].filter((k) => !k.startsWith('.')).sort()
  return (
    <div className="overflow-hidden rounded-lg border text-xs">
      <div className="grid grid-cols-[minmax(6rem,auto)_1fr_1fr] bg-muted font-medium text-muted-foreground">
        <div className="px-3 py-1.5">字段</div><div className="px-3 py-1.5">原值</div><div className="px-3 py-1.5">新值</div>
      </div>
      {keys.map((k) => {
        const bv = fmt(b[k]), av = fmt(a[k]), changed = bv !== av
        return (
          <div key={k} className={cn('grid grid-cols-[minmax(6rem,auto)_1fr_1fr] border-t', !changed && 'text-muted-foreground')}>
            <div className="px-3 py-1.5 font-mono">{k}</div>
            <div className={cn('break-all px-3 py-1.5 font-mono', changed && 'bg-destructive/6 text-destructive')}>{bv || '—'}</div>
            <div className={cn('break-all px-3 py-1.5 font-mono', changed && 'bg-success/8 text-success')}>{av || '—'}</div>
          </div>
        )
      })}
      {!keys.length && <div className="border-t px-3 py-2 text-muted-foreground">（无）</div>}
    </div>
  )
}

// TargetName renders a service name; probe-derived names get a 「模拟判定」 tag and
// uncertain ones are greyed out.
export function TargetName({ name, guess, uncertain, className }: { name: string; guess?: boolean; uncertain?: boolean; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5', uncertain && 'text-muted-foreground', className)}>
      <span className="truncate">{name}</span>
      {guess && <span title="规则库无法识别，由面板主动访问目标后推断" className="shrink-0 rounded border border-dashed px-1 text-[10px] leading-4 text-muted-foreground">模拟判定</span>}
    </span>
  )
}
