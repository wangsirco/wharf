import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { useApi } from '@/lib/hooks'
import { runAction } from '@/lib/actions'
import type { Device, DevicePolicy } from '@/lib/types'
import { PageHeader } from '@/components/layout'
import { Empty, ErrorBox, Pill, Section } from '@/components/common'
import { policyLabel } from '@/components/policy'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

export default function Controls() {
  const { data, error, reload } = useApi<DevicePolicy[]>('/policies', 20000)
  const { data: devices } = useApi<Device[]>('/devices')
  const navigate = useNavigate()
  const nameOf = (p: DevicePolicy) => p.name || devices?.find((d) => d.mac === p.mac)?.hostname || p.mac
  const toggle = async (p: DevicePolicy, on: boolean) => {
    try { await runAction('device.policy.save', { ...p, block: on }) } catch (e) { toast.error((e as Error).message) } finally { reload() }
  }
  return (
    <>
      <PageHeader title="设备管控" desc="断网、黑白名单、定时断网、禁止访问路由器端口。在「设备」里点开任意设备 →「访问控制」即可添加规则。" />
      {error && <div className="mb-4"><ErrorBox>{error}</ErrorBox></div>}
      <Section title="已设置管控的设备">
        <Table>
          <TableHeader><TableRow>
            <TableHead className="pl-4">设备</TableHead><TableHead>状态</TableHead><TableHead>名单</TableHead><TableHead>定时</TableHead>
            <TableHead>设置者</TableHead><TableHead className="pr-4 text-right">断网</TableHead>
          </TableRow></TableHeader>
          <TableBody>
            {data?.map((p) => (
              <TableRow key={p.mac} className="cursor-pointer" onClick={() => navigate(`/devices/${p.mac}?tab=control`)}>
                <TableCell className="pl-4"><div className="font-medium">{nameOf(p)}</div><div className="font-mono text-xs text-muted-foreground">{p.mac}</div></TableCell>
                <TableCell><Pill tone={p.status?.blocked ? 'red' : 'green'}>{policyLabel(p)}</Pill></TableCell>
                <TableCell className="text-muted-foreground">{p.mode === 'none' ? '—' : `${p.mode === 'blacklist' ? '黑名单' : '白名单'} ${p.targets.length} 项`}</TableCell>
                <TableCell className="text-muted-foreground">{p.schedules.length ? p.schedules.map((s) => `${s.start}–${s.end}`).join('、') : '—'}</TableCell>
                <TableCell className="text-muted-foreground">{p.owner_name || '超级管理员'}</TableCell>
                <TableCell className="pr-4 text-right" onClick={(e) => e.stopPropagation()}>
                  <Switch checked={p.block} disabled={!p.editable} onCheckedChange={(c) => toggle(p, !!c)} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {data && !data.length && <Empty>还没有设备被管控</Empty>}
      </Section>
    </>
  )
}
