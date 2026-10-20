import { useState } from 'react'
import { toast } from 'sonner'
import { Plus, ShieldCheck } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { post, put } from '@/lib/api'
import type { ForwardGrants, Meta, User } from '@/lib/types'
import { emptyGrants, GrantsEditor, grantLabel } from '@/components/grants'
import { ago } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { Dot, Empty, Field, HalfPanel, Pill, Section } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

export default function Users() {
  const { data, reload } = useApi<User[]>('/users')
  const { meta } = useAuth()
  const [sel, setSel] = useState<User | 'new' | null>(null)

  return (
    <>
      <PageHeader title="用户与权限" desc="只有超级管理员可以新增用户、分配权限；新增的用户均为普通管理员，彼此之间无法查看或修改对方创建的内容。">
        <Button size="sm" onClick={() => setSel('new')}><Plus /> 新增管理员</Button>
      </PageHeader>
      <Section title="管理员">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-4">名称</TableHead><TableHead>用户名</TableHead><TableHead>ID</TableHead><TableHead>角色</TableHead>
              <TableHead>权限</TableHead><TableHead className="hidden md:table-cell">端口段</TableHead><TableHead>最近登录</TableHead><TableHead className="pr-4">状态</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data?.map((u) => (
              <TableRow key={u.id} className="cursor-pointer" onClick={() => setSel(u)}>
                <TableCell className="max-w-56 truncate pl-4 font-medium">{u.display_name}</TableCell>
                <TableCell className="text-muted-foreground">{u.username}</TableCell>
                <TableCell className="tabular-nums text-muted-foreground">{u.id}</TableCell>
                <TableCell>{u.role === 'super' ? <Pill tone="blue"><ShieldCheck className="size-3" />超级管理员</Pill> : <Pill>管理员</Pill>}</TableCell>
                <TableCell className="text-muted-foreground">{u.role === 'super' ? '全部' : `${u.perms.length} 项`}</TableCell>
                <TableCell className="hidden max-w-48 truncate font-mono text-xs text-muted-foreground md:table-cell">
                  {u.role === 'super' ? '不限' : !u.perms.includes('forwards.manage') ? '—' : u.grants?.ports.length ? u.grants.ports.map((g) => grantLabel(g)).join(', ') : '不限'}
                </TableCell>
                <TableCell className="text-muted-foreground">{ago(u.last_login_at)}</TableCell>
                <TableCell className="pr-4"><span className="flex items-center gap-2"><Dot tone={u.disabled ? 'off' : 'ok'} />{u.disabled ? '已停用' : '正常'}</span></TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {data && !data.length && <Empty>暂无用户</Empty>}
      </Section>
      {meta && <UserPanel meta={meta} target={sel} onClose={() => setSel(null)} onSaved={() => { setSel(null); reload() }} />}
    </>
  )
}

function UserPanel({ meta, target, onClose, onSaved }: { meta: Meta; target: User | 'new' | null; onClose: () => void; onSaved: () => void }) {
  const isNew = target === 'new'
  const u = isNew ? null : target
  const [form, setForm] = useState({ username: '', display_name: '', password: '', perms: [] as string[], quotas: {} as Record<string, number>, grants: emptyGrants as ForwardGrants, disabled: false })
  const [newPw, setNewPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [loadedFor, setLoadedFor] = useState<unknown>(null)
  if (target && loadedFor !== target) {
    setLoadedFor(target)
    setNewPw('')
    setForm(u
      ? { username: u.username, display_name: u.display_name, password: '', perms: u.perms, quotas: u.quotas, grants: { ports: u.grants?.ports ?? [], lan: u.grants?.lan ?? [] }, disabled: u.disabled }
      : { username: '', display_name: '', password: '', perms: ['dashboard.view', 'devices.view'], quotas: {}, grants: emptyGrants, disabled: false })
  }
  const isSuper = u?.role === 'super'
  const groups = [...new Set(meta.permissions.map((p) => p.group))]
  const toggle = (k: string, on: boolean) => setForm((f) => ({ ...f, perms: on ? [...f.perms, k] : f.perms.filter((p) => p !== k) }))

  const save = async () => {
    setBusy(true)
    const grants = { ...form.grants, ports: form.grants.ports.filter((p) => p.from || p.to) }
    try {
      if (isNew) await post('/users', { ...form, grants })
      else await put(`/users/${u!.id}`, { display_name: form.display_name, perms: form.perms, quotas: form.quotas, grants, disabled: form.disabled })
      toast.success('已保存')
      onSaved()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const resetPw = async () => {
    setBusy(true)
    try { await post(`/users/${u!.id}/password`, { password: newPw }); toast.success('密码已重置，该用户需要重新登录'); setNewPw('') }
    catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }

  return (
    <HalfPanel open={!!target} onOpenChange={(o) => { if (!o) { onClose(); setLoadedFor(null) } }}
      title={isNew ? '新增管理员' : form.display_name}
      desc={isNew ? '新用户为普通管理员，只能使用下面勾选的功能' : `${u?.username} · 用户 ID ${u?.id}`}
      footer={<><Button variant="outline" onClick={onClose}>取消</Button><Button disabled={busy} onClick={save}>{isNew ? '创建' : '保存'}</Button></>}>
      <div className="grid gap-6">
        <div className="grid gap-4 sm:grid-cols-2">
          {isNew && <Field label="用户名" hint="登录用，3-32 位字母数字"><Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>}
          <Field label="显示名称"><Input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></Field>
          {isNew && <Field label="初始密码" hint="至少 8 位"><Input type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>}
        </div>

        {isSuper ? (
          <p className="rounded-lg bg-accent px-4 py-3 text-sm text-accent-foreground">超级管理员拥有全部权限，不受配额限制。</p>
        ) : (
          <>
            <div className="grid gap-3">
              <h3 className="text-sm font-semibold">功能权限</h3>
              <div className="grid gap-2 rounded-xl border p-4">
                {groups.map((g) => (
                  <div key={g} className="grid gap-2 border-b pb-3 last:border-0 last:pb-0 sm:grid-cols-[6rem_1fr]">
                    <div className="text-xs font-medium text-muted-foreground">{g}</div>
                    <div className="grid gap-2">
                      {meta.permissions.filter((p) => p.group === g).map((p) => (
                        <label key={p.key} className="flex cursor-pointer items-start gap-2.5">
                          <Checkbox className="mt-0.5" checked={form.perms.includes(p.key)} onCheckedChange={(c) => toggle(p.key, !!c)} />
                          <span><span className="text-sm">{p.label}</span><span className="block text-xs text-muted-foreground">{p.desc}</span></span>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="grid gap-3">
              <h3 className="text-sm font-semibold">配额</h3>
              <div className="grid gap-4 rounded-xl border p-4 sm:grid-cols-2">
                {meta.quotas.map((q) => (
                  <Field key={q.key} label={q.label} hint={`默认 ${q.default}；0 = 不允许，-1 = 不限`}>
                    <Input type="number" min={-1} value={form.quotas[q.key] ?? q.default}
                      onChange={(e) => setForm({ ...form, quotas: { ...form.quotas, [q.key]: Number(e.target.value) } })} />
                  </Field>
                ))}
              </div>
            </div>
            {form.perms.includes('forwards.manage') && (
              <GrantsEditor key={u?.id ?? 'new'} userId={u?.id} value={form.grants} onChange={(g) => setForm((f) => ({ ...f, grants: g }))} />
            )}
            {!isNew && (
              <label className="flex items-center justify-between rounded-xl border p-4">
                <span><span className="text-sm font-medium">停用账号</span><span className="block text-xs text-muted-foreground">停用后立即退出所有登录，无法再登录</span></span>
                <Switch checked={form.disabled} onCheckedChange={(c) => setForm({ ...form, disabled: !!c })} />
              </label>
            )}
          </>
        )}

        {!isNew && (
          <div className="grid gap-3">
            <h3 className="text-sm font-semibold">重置密码</h3>
            <div className="flex gap-2">
              <Input type="password" autoComplete="new-password" placeholder="新密码（至少 8 位）" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
              <Button variant="outline" disabled={busy || newPw.length < 8} onClick={resetPw}>重置</Button>
            </div>
          </div>
        )}
      </div>
    </HalfPanel>
  )
}
