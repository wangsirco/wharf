import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, CheckCircle2, Info, XCircle } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { bytes } from '@/lib/format'
import { cn } from '@/lib/utils'

interface Todo { level: 'bad' | 'warn' | 'info'; text: string; to?: string }

// Verdict: the overview answers "现在好不好" in one line before any chart — "一切正常 · 23
// 台设备在线 · 今天 1.2 GB", or the worst problem and where to fix it, then the rest.
export function Verdict({ online, total, today }: { online?: number; total?: number; today?: number }) {
  const { data } = useApi<{ items: Todo[] }>('/overview/todo', 30000)
  if (!data) return null
  const items = data.items ?? []
  const worst = items.find((i) => i.level === 'bad') ?? items.find((i) => i.level === 'warn')
  const facts = [online !== undefined && `${online} 台设备在线${total ? `（共 ${total} 台）` : ''}`, today !== undefined && `今天 ${bytes(today)}`].filter(Boolean).join(' · ')
  const tone = worst?.level === 'bad' ? 'bad' : worst ? 'warn' : 'ok'
  const Icon = tone === 'bad' ? XCircle : tone === 'warn' ? AlertTriangle : CheckCircle2
  return (
    <section className={cn('mb-4 rounded-2xl border px-4 py-3',
      tone === 'bad' ? 'border-destructive/40 bg-destructive/8' : tone === 'warn' ? 'border-warning/40 bg-warning/8' : 'border-success/30 bg-success/6')}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Icon className={cn('size-5 shrink-0', tone === 'bad' ? 'text-destructive' : tone === 'warn' ? 'text-warning' : 'text-success')} />
        <span className="font-semibold">{worst ? worst.text : '一切正常'}</span>
        {worst?.to && <Link to={worst.to} className="flex items-center gap-0.5 text-sm text-primary hover:underline">去看看 <ArrowRight className="size-3.5" /></Link>}
        {facts && <span className="text-sm text-muted-foreground">{worst ? '· ' : ''}{facts}</span>}
      </div>
      {items.filter((i) => i !== worst).length > 0 && (
        <ul className="mt-2 grid gap-1 border-t pt-2 text-sm">
          {items.filter((i) => i !== worst).map((i) => (
            <li key={i.text} className="flex items-center gap-2">
              {i.level === 'bad' ? <XCircle className="size-3.5 shrink-0 text-destructive" /> : i.level === 'warn' ? <AlertTriangle className="size-3.5 shrink-0 text-warning" /> : <Info className="size-3.5 shrink-0 text-primary" />}
              <span className="min-w-0 flex-1">{i.text}</span>
              {i.to && <Link to={i.to} className="shrink-0 text-xs text-primary hover:underline">去处理</Link>}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
