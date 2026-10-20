import { toast } from 'sonner'
import { post } from './api'
import type { ActionResult } from './types'

// runAction calls a router action; returns true if it was executed (false if queued for approval).
export async function runAction(key: string, payload: unknown): Promise<boolean> {
  const r = await post<ActionResult>(`/actions/${key}`, payload)
  if (r.pending) {
    toast.info(r.message ?? '已提交超级管理员审批', { description: `审批编号 #${r.approval_id}` })
    return false
  }
  toast.success('操作已生效')
  return true
}
