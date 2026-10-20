import { useState } from 'react'
import { toast } from 'sonner'
import { post } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { PageHeader } from '@/components/layout'
import { Field, Section } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

export default function Account() {
  const { refresh } = useAuth()
  const [f, setF] = useState({ old: '', new: '', confirm: '' })
  const [busy, setBusy] = useState(false)
  const save = async () => {
    if (f.new !== f.confirm) return toast.error('两次输入的新密码不一致')
    setBusy(true)
    try { await post('/me/password', { old: f.old, new: f.new }); toast.success('密码已修改，请重新登录'); refresh() }
    catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <>
      <PageHeader title="修改密码" />
      <Section title="新密码" className="max-w-lg">
        <div className="grid gap-4 p-4">
          <Field label="当前密码"><Input type="password" autoComplete="current-password" value={f.old} onChange={(e) => setF({ ...f, old: e.target.value })} /></Field>
          <Field label="新密码" hint="至少 8 位"><Input type="password" autoComplete="new-password" value={f.new} onChange={(e) => setF({ ...f, new: e.target.value })} /></Field>
          <Field label="确认新密码"><Input type="password" autoComplete="new-password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} /></Field>
          <div><Button disabled={busy || !f.old || f.new.length < 8} onClick={save}>修改密码</Button></div>
        </div>
      </Section>
    </>
  )
}
