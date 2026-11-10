import { useEffect, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { Anchor, Check, Plus, Send, Trash2 } from 'lucide-react'
import { api, get, post, put } from '@/lib/api'
import { useBerth } from '@/lib/berth'
import { cn } from '@/lib/utils'
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
  new_device: boolean; wan_down: boolean; wan_down_minutes: number
  device_left: boolean; device_back: boolean; presence_all: boolean; presence_watch: string[]; away_minutes: number
  traffic_spike: boolean; spike_mb_per_hour: number; spike_window: 'hour' | 'day'; spike_exclude: string[]; spike_custom: Record<string, number>
  new_device_skip_random: boolean; wan_line: boolean; ddns_fail: boolean; monitor: boolean; proxy_users: boolean; proxy_cert: boolean
  panel_denied: boolean; approval_pending: boolean; quiet_from: string; quiet_to: string
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
  const [chats, setChats] = useState<{ bot: string; chats: { id: number; type: string; title: string; name: string }[] } | null>(null)
  const [finding, setFinding] = useState(false)
  const findChats = async () => {
    setFinding(true)
    try {
      const r = await post<{ bot: string; chats: { id: number; type: string; title: string; name: string }[] }>('/alerts/telegram/chats', { token: ch.token })
      setChats(r)
      if (r.chats.length === 1) setCh((c) => ({ ...c, chat_id: String(r.chats[0].id) }))
    } catch (e) { toast.error((e as Error).message) } finally { setFinding(false) }
  }
  const addChannel = async () => {
    try { await post('/alerts/channels', { type, ...ch }); setCh({ name: '', key: '', token: '', chat_id: '' }); setChats(null); toast.success('已添加，可以点「发送测试消息」试一下'); reload() } catch (e) { toast.error((e as Error).message) }
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

  const pickable = (devices ?? []).filter((d) => d.ip).map((d) => ({ ip: d.ip, mac: d.mac, name: d.name, online: d.online }))
  return (
    <>
      <PageHeader title="告警推送" desc="发生重要事件时推送到手机。支持 Server 酱和 Telegram。">
        <Button variant="outline" size="sm" onClick={() => test()}><Send /> 发送测试消息</Button>
      </PageHeader>
      <div className="grid items-start gap-4 xl:grid-cols-2">
        <PrimaryNotifier />
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
              <div className="grid gap-3">
                <ol className="list-decimal space-y-0.5 pl-5 text-xs text-muted-foreground">
                  <li>在 Telegram 找 @BotFather，发送 /newbot 创建机器人，复制它给的 Token</li>
                  <li>打开你的机器人，点「开始」或随便发一条消息（推送到群组：把机器人拉进群并在群里发一条）</li>
                  <li>粘贴 Token 后点「添加」，Chat ID 会自动找到；有多个聊天时点「自动获取」选择</li>
                </ol>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label="Bot Token" hint="直接粘贴即可，带不带 bot 前缀、整段 getUpdates 网址都行">
                    <Input type="password" autoComplete="off" value={ch.token} onChange={(e) => { setCh({ ...ch, token: e.target.value }); setChats(null) }} placeholder="123456789:AAE…" />
                  </Field>
                  <Field label="Chat ID（可留空）" hint="留空自动获取；也可以手动填，群组以 - 开头">
                    <div className="flex gap-2">
                      <Input value={ch.chat_id} onChange={(e) => setCh({ ...ch, chat_id: e.target.value.trim() })} placeholder="自动" />
                      <Button variant="outline" disabled={!ch.token.trim() || finding} onClick={findChats}>{finding ? '查找中…' : '自动获取'}</Button>
                    </div>
                  </Field>
                </div>
                {chats && (
                  <div className="grid gap-1 rounded-lg border p-2 text-sm">
                    <div className="px-1 text-xs text-muted-foreground">
                      {chats.chats.length ? `@${chats.bot} 最近收到的聊天，选择推送到哪里：` : `@${chats.bot} 还没收到消息：请先在 Telegram 里给它发一条，再点「自动获取」`}
                    </div>
                    {chats.chats.map((c) => (
                      <button key={c.id} type="button" onClick={() => setCh({ ...ch, chat_id: String(c.id) })}
                        className={`flex items-center justify-between rounded-md px-2 py-1.5 text-left hover:bg-muted ${ch.chat_id === String(c.id) ? 'bg-accent' : ''}`}>
                        <span>{c.title || c.name || '（无名称）'} <span className="text-xs text-muted-foreground">{({ private: '个人', group: '群组', supergroup: '群组', channel: '频道' } as Record<string, string>)[c.type] ?? c.type}</span></span>
                        <span className="font-mono text-xs text-muted-foreground">{c.id}</span>
                      </button>
                    ))}
                  </div>
                )}
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
              <Group title="网络">
                {sw('wan_down', '家里断网 / 网络恢复', `整个家的外网：所有检测目标连续 ${rules.wan_down_minutes} 分钟连不上时提醒，恢复后再告诉你（不受免打扰限制）`)}
                {sw('wan_line', '单条线路掉线 / 恢复', `有多条 WAN（多线路 / mwan3）时，其中一条断开 ${rules.wan_down_minutes} 分钟以上就提醒，即使家里还能上网。只有一条线路时不会发`)}
                <Field label="断网判定（分钟）" className="max-w-48 pt-1"><Input type="number" min={1} value={rules.wan_down_minutes} onChange={(e) => setRules({ ...rules, wan_down_minutes: Number(e.target.value) })} /></Field>
              </Group>
              <Group title="新设备">
                {sw('new_device', '新设备接入', '有没见过的设备连上家里网络时')}
                {rules.new_device && sw('new_device_skip_random', '忽略随机 MAC 的设备', '手机 / 电脑开启「私有地址」后会定期换 MAC。和已知设备同名的会自动认出、不提醒；打开这项后，其他随机 MAC 设备也不提醒')}
              </Group>
              <Group title="设备离开 / 回来">
                <p className="text-xs text-muted-foreground">
                  某台设备超过 {rules.away_minutes || 10} 分钟没在家里网络出现，算作离开（手机息屏短暂掉线不会误报）；再出现时算作回来，并告诉你离开了多久。和「概览」里的进出记录是同一套判断。同一分钟里有多台设备，会合并成一条消息。
                </p>
                {sw('device_left', '设备离开', '例如：孩子的手机离开了家、摄像头 / NAS 掉线')}
                {sw('device_back', '设备回来', '例如：家人回到家、掉线的设备恢复')}
                <div className="grid gap-3 pt-2 sm:grid-cols-2">
                  <Field label="提醒哪些设备">
                    <div className="flex flex-wrap gap-1.5">
                      {([[false, '只提醒选中的设备'], [true, '所有设备']] as const).map(([v, l]) => (
                        <button key={l} type="button" onClick={() => setRules({ ...rules, presence_all: v })}
                          className={`rounded-md border px-2.5 py-1 text-xs ${rules.presence_all === v ? 'border-primary bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted'}`}>{l}</button>
                      ))}
                    </div>
                  </Field>
                  <Field label="离开判定（分钟）" hint="3–240，同时用于概览的进出记录">
                    <Input type="number" min={3} max={240} value={rules.away_minutes || 10} onChange={(e) => setRules({ ...rules, away_minutes: Number(e.target.value) })} />
                  </Field>
                </div>
                {rules.presence_all
                  ? <p className="pt-1 text-xs text-muted-foreground">设备多时消息会比较多，可以开启上方的免打扰时段。</p>
                  : (
                    <Field label="选中的设备" className="pt-2">
                      <DevicePicker devices={pickable}
                        value={rules.presence_watch} onChange={(v) => setRules({ ...rules, presence_watch: v })} />
                    </Field>
                  )}
              </Group>
              <Group title="流量">
                {sw('traffic_spike', '流量异常', `某台设备${rules.spike_window === 'day' ? '今天' : '这个小时'}的用量超过阈值`)}
                {rules.traffic_spike && <SpikeOptions rules={rules} setRules={setRules} devices={pickable} />}
              </Group>
              <Group title="服务">
                {sw('ddns_fail', 'DDNS 更新失败', '每个域名连续失败时只在第一次提醒')}
                {sw('monitor', '定时监控异常 / 恢复', '「网络工具 → 定时监控」里的目标连续两次异常或恢复时')}
                {sw('proxy_users', '代理用户', '流量用到 80% 和用完、3 天内到期和已到期、超出同时在线 IP 限制')}
                {sw('proxy_cert', '代理证书没有续期', "Let's Encrypt 证书剩不到 20 天还没续上时，每天提醒一次")}
              </Group>
              <Group title="安全">
                {sw('panel_denied', '面板访问被拒', '有人尝试从不允许的地区 / 设备打开面板')}
                {sw('approval_pending', '待审批', '普通管理员提交了需要你确认的操作')}
              </Group>
              <div className="grid gap-3 pt-3 sm:grid-cols-2">
                <Field label="免打扰开始" hint="留空则不启用"><Input type="time" value={rules.quiet_from} onChange={(e) => setRules({ ...rules, quiet_from: e.target.value })} /></Field>
                <Field label="免打扰结束"><Input type="time" value={rules.quiet_to} onChange={(e) => setRules({ ...rules, quiet_to: e.target.value })} /></Field>
              </div>
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


function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="grid gap-0.5 border-b pb-2 pt-2 first:pt-0">
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      {children}
    </div>
  )
}

type Pickable = { ip: string; mac: string; name: string; online: boolean }

// SpikeOptions: window, the default threshold, devices left out, and per-device thresholds.
function SpikeOptions({ rules, setRules, devices }: { rules: Rules; setRules: (r: Rules) => void; devices: Pickable[] }) {
  const [pick, setPick] = useState('')
  const unit = rules.spike_window === 'day' ? 'MB / 天' : 'MB / 小时'
  const custom = Object.entries(rules.spike_custom ?? {})
  const nameOf = (mac: string) => devices.find((d) => d.mac === mac)?.name || mac
  return (
    <div className="grid gap-3 rounded-lg bg-muted/40 p-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="统计时段">
          <div className="flex gap-1.5">
            {([['hour', '每小时（整点重新算）'], ['day', '每天（零点重新算）']] as const).map(([k, l]) => (
              <button key={k} type="button" onClick={() => setRules({ ...rules, spike_window: k })}
                className={`rounded-md border px-2.5 py-1 text-xs ${rules.spike_window === k ? 'border-primary bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted'}`}>{l}</button>
            ))}
          </div>
        </Field>
        <Field label={`默认阈值（${unit}）`}>
          <Input type="number" min={100} value={rules.spike_mb_per_hour} onChange={(e) => setRules({ ...rules, spike_mb_per_hour: Number(e.target.value) })} />
        </Field>
      </div>
      <Field label="单独设阈值的设备" hint="例如电视、游戏机用得多，可以给更高的阈值">
        <div className="grid gap-1.5">
          {custom.map(([mac, mb]) => (
            <div key={mac} className="flex items-center gap-2 text-sm">
              <span className="min-w-0 flex-1 truncate">{nameOf(mac)}</span>
              <Input type="number" min={100} className="h-8 w-28" value={mb}
                onChange={(e) => setRules({ ...rules, spike_custom: { ...rules.spike_custom, [mac]: Number(e.target.value) } })} />
              <span className="text-xs text-muted-foreground">{unit}</span>
              <Button variant="ghost" size="icon-sm" onClick={() => { const c = { ...rules.spike_custom }; delete c[mac]; setRules({ ...rules, spike_custom: c }) }}><Trash2 /></Button>
            </div>
          ))}
          <div className="flex gap-2">
            <select className="h-8 min-w-0 flex-1 rounded-md border bg-background px-2 text-sm" value={pick} onChange={(e) => setPick(e.target.value)}>
              <option value="">选择设备…</option>
              {devices.filter((d) => !(d.mac in (rules.spike_custom ?? {}))).map((d) => <option key={d.mac} value={d.mac}>{d.name || d.mac} · {d.ip}</option>)}
            </select>
            <Button size="sm" variant="outline" disabled={!pick} onClick={() => { setRules({ ...rules, spike_custom: { ...rules.spike_custom, [pick]: rules.spike_mb_per_hour * 2 } }); setPick('') }}><Plus /> 添加</Button>
          </div>
        </div>
      </Field>
      <Field label="不提醒的设备" hint="例如 NAS、备份机、PVE：大流量是正常的">
        <DevicePicker devices={devices} value={rules.spike_exclude ?? []} onChange={(v) => setRules({ ...rules, spike_exclude: v })} />
      </Field>
    </div>
  )
}

// PrimaryNotifier: with Berth paired, one side sends every alert so each thing arrives once.
function PrimaryNotifier() {
  const berth = useBerth()
  const [v, setV] = useState<string | null>(null)
  useEffect(() => { if (berth.paired) get<Record<string, string>>('/settings').then((s) => setV(s['alerts.primary'] || 'wharf')) }, [berth.paired])
  if (!berth.paired || v === null) return null
  const pick = async (next: string) => {
    try { await put('/settings', { 'alerts.primary': next }); setV(next); toast.success(next === 'berth' ? 'Wharf 的告警今后转交给 Berth 发送' : 'Berth 的告警今后由 Wharf 发送') }
    catch (e) { toast.error((e as Error).message) }
  }
  return (
    <Section title="主通知方" desc={`已和 Berth「${berth.name}」配对。选一方负责发送，另一方的告警转交给它，同一件事只收到一份通知。`} className="xl:col-span-2">
      <div className="grid gap-2 sm:grid-cols-2">
        {([['wharf', 'Wharf 发送', 'Berth 的告警转交到这里，用上面的渠道发出，标题前加「[Berth · 名称]」'], ['berth', 'Berth 发送', 'Wharf 的告警转交给 Berth；Wharf 自己的渠道不再重复发送（审批请求除外，仍由 Wharf 发）']] as const).map(([k, t, d]) => (
          <button key={k} type="button" onClick={() => pick(k)}
            className={cn('grid gap-1 rounded-xl border p-3 text-left transition-colors hover:border-primary/50', v === k && 'border-primary bg-accent/50 ring-2 ring-primary/20')}>
            <span className="flex items-center gap-2 text-sm font-medium">{k === 'berth' && <Anchor className="size-4 text-primary" />}{t}{v === k && <Check className="ml-auto size-4 text-primary" />}</span>
            <span className="text-xs text-muted-foreground">{d}</span>
          </button>
        ))}
      </div>
    </Section>
  )
}
