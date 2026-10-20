import { useState } from 'react'
import { toast } from 'sonner'
import { Check, X } from 'lucide-react'
import { post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import type { Approval } from '@/lib/types'
import { datetime } from '@/lib/format'
import { actionLabels, approvalStatus } from '@/lib/labels'
import { PageHeader } from '@/components/layout'
import { Empty, Pill, Section } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

export function ApprovalList({ items, actions }: { items: Approval[]; actions?: (a: Approval) => React.ReactNode }) {
  if (!items.length) return <Empty>暂无记录</Empty>
  return (
    <div className="divide-y">
      {items.map((a) => (
        <div key={a.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">{actionLabels[a.action] ?? a.action}</span>
              <Pill tone={approvalStatus[a.status]?.tone}>{approvalStatus[a.status]?.label ?? a.status}</Pill>
              <span className="text-xs text-muted-foreground">#{a.id}</span>
            </div>
            <div className="mt-0.5 truncate text-sm text-muted-foreground">{a.summary}</div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {a.username}（ID {a.user_id}）· {datetime(a.ts)} · {a.ip}
              {a.note && <> · 备注：{a.note}</>}
              {a.status === 'failed' && a.result && <span className="text-destructive"> · {a.result}</span>}
            </div>
          </div>
          {actions?.(a)}
        </div>
      ))}
    </div>
  )
}

export default function Approvals() {
  const [tab, setTab] = useState('pending')
  const { data, reload } = useApi<Approval[]>(tab === 'pending' ? '/approvals?status=pending' : '/approvals', 15000)
  const [notes, setNotes] = useState<Record<number, string>>({})
  const [busy, setBusy] = useState<number | null>(null)

  const decide = async (a: Approval, d: 'approve' | 'reject') => {
    setBusy(a.id)
    try {
      await post(`/approvals/${a.id}/${d}`, { note: notes[a.id] ?? '' })
      toast.success(d === 'approve' ? '已批准并执行' : '已驳回')
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(null); reload() }
  }

  return (
    <>
      <PageHeader title="审批" desc="在「系统设置」中勾选需要二次确认的敏感操作。普通管理员提交后，需超级管理员批准才会真正执行。" />
      <Section title="审批队列" action={
        <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
          <TabsList><TabsTrigger value="pending">待审批</TabsTrigger><TabsTrigger value="all">全部</TabsTrigger></TabsList>
        </Tabs>
      }>
        <ApprovalList items={data ?? []} actions={(a) => a.status === 'pending' && (
          <div className="flex items-center gap-2">
            <Input placeholder="备注（可选）" className="h-8 w-40" value={notes[a.id] ?? ''} onChange={(e) => setNotes({ ...notes, [a.id]: e.target.value })} />
            <Button size="sm" variant="outline" disabled={busy === a.id} onClick={() => decide(a, 'reject')}><X /> 驳回</Button>
            <Button size="sm" disabled={busy === a.id} onClick={() => decide(a, 'approve')}><Check /> 批准</Button>
          </div>
        )} />
      </Section>
    </>
  )
}
