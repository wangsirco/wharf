import { useApi } from '@/lib/hooks'
import type { Approval } from '@/lib/types'
import { PageHeader } from '@/components/layout'
import { Section } from '@/components/common'
import { ApprovalList } from './approvals'

export default function Requests() {
  const { data } = useApi<Approval[]>('/my/approvals', 15000)
  return (
    <>
      <PageHeader title="我的申请" desc="需要超级管理员确认的操作会出现在这里。" />
      <Section title="申请记录"><ApprovalList items={data ?? []} /></Section>
    </>
  )
}
