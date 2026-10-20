import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Plus, Send, Trash2 } from 'lucide-react'
import { api, post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import type { Device } from '@/lib/types'
import { datetime } from '@/lib/format'
import { PageHeader } from '@/components/layout'
import { Empty, Field, Section } from '@/components/common'
import { DevicePicker } from '@/components/pickers'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

interface Rules {
  new_device: boolean; wan_down: boolean; wan_down_minutes: number; offline_watch: string[]; offline_minutes: number
  traffic_spike: boolean; spike_mb_per_hour: number; panel_denied: boolean; approval_pending: boolean; quiet_from: string; quiet_to: string
}
interface Channel { id: number; name: string; masked: string; enabled: boolean }
interface Resp { rules: Rules; channels: Channel[] | null; log: { ts: number; kind: string; title: string; body: string; result: string }[] | null }

export default function Alerts() {
  const { data, reload } = useApi<Resp>('/alerts')
  const { data: devices } = useApi<Device[]>('/devices')
  const [rules, setRules] = useState<Rules | null>(null)
  const [type, setType] = useState<'serverchan' | 'telegram'>('telegram')
  const [ch, setCh] = useState({ name: '', key: '', token: '', chat_id: '' })
  useEffect(() => { if (data && !rules) setRules(data.rules) }, [data, rules])

  const saveRules = async () => {
    try { setRules(await put<Rules>('/alerts/rules', rules)); toast.success('告警规则已保存') } catch (e) { toast.error((e as Error).message) }
  }
  const addChannel = async () => {
    try { await post('/alerts/channels', { type, ...ch }); setCh({ name: '', key: '', token: '', chat_id: '' }); toast.success('已添加'); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const test = async (id?: number) => {
    try {
      const r = await post<{ name: string; result: string }[]>('/alerts/test', { id: id ?? 0 })
      r.forEach((x) => (x.result === '已发送' ? toast.success(`${x.name}：已发送`) : toast.error(`${x.name}：${x.result}`)))
      if (!r.length) toast.info('还没有推送渠道')
    } catch (e) { toast.error((e as Error).message) }
  }
  const sw = (k: keyof Rules, label: string, desc: string) => rules && (
    <label className="flex items-start justify-between gap-4 py-2">
      <span><span className="text-sm">{label}</span><span className="block text-xs text-muted-foreground">{desc}</span></span>
      <Switch checked={!!rules[k]} onCheckedChange={(c) => setRules({ ...rules, [k]: !!c })} />
    </label>
  )

  return (
    <>
      <PageHeader title="告警推送" desc="发生重要事件时推送到手机。支持 Server 酱和 Telegram。">
        <Button variant="outline" size="sm" onClick={() => test()}><Send /> 发送测试消息</Button>
      </PageHeader>
      <div className="grid items-start gap-4 xl:grid-cols-2">
        <Section title="推送渠道">
          <div className="divide-y">
            {data?.channels?.map((c) => (
              <div key={c.id} className="flex items-center gap-3 px-4 py-2.5">
                <div className="min-w-0 flex-1"><div className="text-sm font-medium">{c.name}</div><div className="font-mono text-xs text-muted-foreground">{c.masked}</div></div>
                <Button variant="ghost" size="xs" onClick={() => test(c.id)}>测试</Button>
                <Switch checked={c.enabled} onCheckedChange={async () => { await post(`/alerts/channels/${c.id}/toggle`); reload() }} />
                <Button variant="ghost" size="icon-sm" onClick={async () => { await api('DELETE', `/alerts/channels/${c.id}`); reload() }}><Trash2 /></Button>
              </div>
            ))}
            {!data?.channels?.length && <Empty>还没有推送渠道，添加后才会发送告警</Empty>}
          </div>
          <div className="grid gap-3 border-t p-4">
            <Tabs value={type} onValueChange={(v) => setType(v as 'serverchan' | 'telegram')}>
              <TabsList><TabsTrigger value="telegram">Telegram</TabsTrigger><TabsTrigger value="serverchan">Server 酱</TabsTrigger></TabsList>
            </Tabs>
            {type === 'telegram' ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Bot Token" hint="找 @BotFather 创建机器人获得"><Input type="password" autoComplete="off" value={ch.token} onChange={(e) => setCh({ ...ch, token: e.target.value.trim() })} placeholder="123456:ABC-DEF…" /></Field>
                <Field label="Chat ID" hint="个人 ID 或群组 ID（群组以 - 开头），先给机器人发一条消息"><Input value={ch.chat_id} onChange={(e) => setCh({ ...ch, chat_id: e.target.value.trim() })} placeholder="123456789" /></Field>
              </div>
            ) : (
              <Field label="SendKey" hint="在 sct.ftqq.com 登录后获取"><Input type="password" autoComplete="off" value={ch.key} onChange={(e) => setCh({ ...ch, key: e.target.value.trim() })} placeholder="SCT…" /></Field>
            )}
            <div className="flex gap-2">
              <Input placeholder="名称（可选），例如：我的手机" value={ch.name} onChange={(e) => setCh({ ...ch, name: e.target.value })} />
              <Button onClick={addChannel}><Plus /> 添加</Button>
            </div>
          </div>
        </Section>

        <Section title="告警规则" action={<Button size="sm" onClick={saveRules} disabled={!rules}>保存规则</Button>}>
          {rules && (
            <div className="grid gap-1 p-4">
              {sw('new_device', '新设备接入', '有没见过的设备连上家里网络时')}
              {sw('wan_down', '断网 / 恢复', `所有检测目标连续 ${rules.wan_down_minutes} 分钟不可达时（不受免打扰限制）`)}
              {sw('traffic_spike', '流量异常', `某台设备 1 小时内用量超过 ${rules.spike_mb_per_hour} MB`)}
              {sw('panel_denied', '面板访问被拒', '有人尝试从不允许的地区 / 设备打开面板')}
              {sw('approval_pending', '待审批', '普通管理员提交了需要你确认的操作')}
              <div className="grid gap-3 pt-3 sm:grid-cols-3">
                <Field label="断网判定（分钟）"><Input type="number" min={1} value={rules.wan_down_minutes} onChange={(e) => setRules({ ...rules, wan_down_minutes: Number(e.target.value) })} /></Field>
                <Field label="流量阈值（MB / 小时）"><Input type="number" min={100} value={rules.spike_mb_per_hour} onChange={(e) => setRules({ ...rules, spike_mb_per_hour: Number(e.target.value) })} /></Field>
                <Field label="离线判定（分钟）"><Input type="number" min={1} value={rules.offline_minutes} onChange={(e) => setRules({ ...rules, offline_minutes: Number(e.target.value) })} /></Field>
              </div>
              <div className="grid gap-3 pt-3 sm:grid-cols-2">
                <Field label="免打扰开始" hint="留空则不启用"><Input type="time" value={rules.quiet_from} onChange={(e) => setRules({ ...rules, quiet_from: e.target.value })} /></Field>
                <Field label="免打扰结束"><Input type="time" value={rules.quiet_to} onChange={(e) => setRules({ ...rules, quiet_to: e.target.value })} /></Field>
              </div>
              <Field label="离线提醒的设备" hint="例如摄像头、NAS：离线超过设定时间就提醒，恢复后再告诉你" className="pt-3">
                <DevicePicker devices={(devices ?? []).filter((d) => d.ip).map((d) => ({ ip: d.ip, mac: d.mac, name: d.name, online: d.online }))}
                  value={rules.offline_watch} onChange={(v) => setRules({ ...rules, offline_watch: v })} />
              </Field>
            </div>
          )}
        </Section>

        <Section title="发送记录" className="xl:col-span-2">
          <div className="divide-y">
            {data?.log?.map((l, i) => (
              <div key={i} className="flex items-start gap-3 px-4 py-2.5 text-sm">
                <span className="w-32 shrink-0 text-xs tabular-nums text-muted-foreground">{datetime(l.ts)}</span>
                <div className="min-w-0 flex-1"><div className="font-medium">{l.title}</div>{l.body && <div className="whitespace-pre-line text-xs text-muted-foreground">{l.body}</div>}</div>
                <span className="max-w-72 text-right text-xs text-muted-foreground">{l.result}</span>
              </div>
            ))}
            {!data?.log?.length && <Empty>还没有发送过告警</Empty>}
          </div>
        </Section>
      </div>
    </>
  )
}

