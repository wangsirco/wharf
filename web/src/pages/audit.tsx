import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { History, RotateCcw, Search } from 'lucide-react'
import { ApiError, get, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import type { AuditEntry, User } from '@/lib/types'
import { datetime } from '@/lib/format'
import { actionLabels } from '@/lib/labels'
import { PageHeader } from '@/components/layout'
import { Empty, HalfPanel, Pill, Section, ValueDiff, useConfirm } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

const PAGE = 50

export default function Audit() {
  const { data: users } = useApi<User[]>('/users')
  const [userId, setUserId] = useState('all')
  const [q, setQ] = useState('')
  const [items, setItems] = useState<AuditEntry[]>([])
  const [more, setMore] = useState(false)
  const [sel, setSel] = useState<AuditEntry | null>(null)

  const query = (beforeId?: number) => {
    const p = new URLSearchParams({ limit: String(PAGE) })
    if (userId !== 'all') p.set('user_id', userId)
    if (q.trim()) p.set('q', q.trim())
    if (beforeId) p.set('before_id', String(beforeId))
    return get<AuditEntry[]>('/audit?' + p)
  }
  const load = async () => { const r = await query(); setItems(r); setMore(r.length === PAGE) }
  const loadMore = async () => { const r = await query(items[items.length - 1]?.id); setItems([...items, ...r]); setMore(r.length === PAGE) }
  useEffect(() => { const t = setTimeout(load, 250); return () => clearTimeout(t) }, [userId, q]) // eslint-disable-line

  return (
    <>
      <PageHeader title="操作审计" desc="记录所有管理员的操作：谁、何时、从哪个 IP、改了什么、原值与新值。可还原的记录支持一键还原。" />
      <Section title="审计记录" action={
        <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
          <Select value={userId} onValueChange={(v) => setUserId(String(v))}>
            <SelectTrigger size="sm" className="w-40"><SelectValue>{(v: string) => v === 'all' ? '全部用户' : users?.find((u) => String(u.id) === v)?.display_name ?? v}</SelectValue></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部用户</SelectItem>
              {users?.map((u) => <SelectItem key={u.id} value={String(u.id)}>{u.display_name}（{u.username}）</SelectItem>)}
            </SelectContent>
          </Select>
          <div className="relative min-w-40 flex-1 sm:flex-none">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="搜索内容 / 对象" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-full pl-8 sm:w-48" />
          </div>
        </div>
      }>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-4">时间</TableHead><TableHead>管理员</TableHead><TableHead>操作</TableHead>
              <TableHead>内容</TableHead><TableHead>来源 IP</TableHead><TableHead className="pr-4">状态</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((e) => (
              <TableRow key={e.id} className="cursor-pointer" onClick={() => setSel(e)}>
                <TableCell className="whitespace-nowrap pl-4 text-xs tabular-nums text-muted-foreground">{datetime(e.ts)}</TableCell>
                <TableCell className="whitespace-nowrap">{e.username}<span className="ml-1 text-xs text-muted-foreground">#{e.user_id}</span></TableCell>
                <TableCell className="whitespace-nowrap">{actionLabels[e.action] ?? e.action}</TableCell>
                <TableCell className="max-w-md truncate text-muted-foreground">{e.summary}</TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{e.ip}</TableCell>
                <TableCell className="space-x-1 whitespace-nowrap pr-4">
                  {e.approval_id && <Pill tone="amber">审批 #{e.approval_id}</Pill>}
                  {e.restored_at ? <Pill tone="green">已还原</Pill> : e.restorable ? <Pill tone="blue">可还原</Pill> : null}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!items.length && <Empty>暂无记录</Empty>}
        {more && <div className="border-t p-3 text-center"><Button variant="ghost" size="sm" onClick={loadMore}>加载更多</Button></div>}
      </Section>
      <AuditPanel entry={sel} onClose={() => setSel(null)} onRestored={() => { setSel(null); load() }} />
    </>
  )
}

function AuditPanel({ entry: e, onClose, onRestored }: { entry: AuditEntry | null; onClose: () => void; onRestored: () => void }) {
  const { confirm, dialog } = useConfirm()
  const [busy, setBusy] = useState(false)

  const restore = async (force = false) => {
    if (!e) return
    if (!force && !(await confirm('还原到原值？', '将把该记录涉及的内容恢复为修改前的值，还原操作本身也会记入审计。', { ok: '还原' }))) return
    setBusy(true)
    try {
      await post(`/audit/${e.id}/restore`, { force })
      toast.success('已还原')
      onRestored()
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setBusy(false)
        if (await confirm('当前值已被再次修改', <>{String(err.data.conflict ?? '')}<br />仍要覆盖为该记录的原值吗？</>, { danger: true, ok: '强制还原' })) return restore(true)
        return
      }
      toast.error((err as Error).message)
    } finally { setBusy(false) }
  }

  return (
    <HalfPanel open={!!e} onOpenChange={(o) => { if (!o) onClose() }}
      title={e ? `${actionLabels[e.action] ?? e.action} · #${e.id}` : ''}
      desc={e?.summary}
      footer={e?.restorable && (
        <Button disabled={busy} onClick={() => restore()}>
          <RotateCcw /> {e.restored_at ? '再次还原' : '还原到原值'}
        </Button>
      )}>
      {e && (
        <div className="grid gap-6">
          <dl className="grid grid-cols-[7rem_1fr] gap-y-2.5 text-sm">
            <dt className="text-muted-foreground">时间</dt><dd className="tabular-nums">{datetime(e.ts)}</dd>
            <dt className="text-muted-foreground">管理员</dt><dd>{e.username}（ID {e.user_id}）</dd>
            <dt className="text-muted-foreground">来源 IP</dt><dd className="font-mono">{e.ip}</dd>
            <dt className="text-muted-foreground">操作对象</dt><dd className="font-mono text-xs">{e.target_type} · {e.target_id}</dd>
            {e.approval_id && <><dt className="text-muted-foreground">审批</dt><dd>经超级管理员批准（审批 #{e.approval_id}）</dd></>}
            {e.restore_of && <><dt className="text-muted-foreground">还原自</dt><dd>审计 #{e.restore_of}</dd></>}
            {e.restored_at && <><dt className="text-muted-foreground"><History className="mr-1 inline size-3.5" />已还原</dt><dd>{datetime(e.restored_at)}</dd></>}
          </dl>
          <div className="grid gap-2">
            <h3 className="text-sm font-semibold">变更内容</h3>
            <ValueDiff before={e.before} after={e.after} />
          </div>
        </div>
      )}
      {dialog}
    </HalfPanel>
  )
}
