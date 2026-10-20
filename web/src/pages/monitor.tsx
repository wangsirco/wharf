import { useState } from 'react'
import { toast } from 'sonner'
import { Activity, Download, Pencil, Play, Plus, Trash2 } from 'lucide-react'
import { api, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { ago, datetime } from '@/lib/format'
import { cn } from '@/lib/utils'
import { Dot, Empty, Field, HalfPanel, Pill, Section, useConfirm } from '@/components/common'
import { AreaChart } from '@/components/chart'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

interface MonRow { ts: number; sent: number; recv: number; min: number; avg: number; max: number; jitter: number; ip?: string; error?: string }
interface MonAgg { t: number; sent: number; recv: number; loss: number; avg: number; min: number; max: number; jitter: number; rounds: number }
interface Monitor {
  id: number; name: string; target: string; mode: 'icmp' | 'tcp'; port: number; count: number; interval_min: number
  loss_alert: number; rtt_alert: number; enabled: boolean; state: 'ok' | 'bad' | 'unknown'; state_since: number; last?: MonRow; day?: MonAgg
}

const blank: Omit<Monitor, 'id' | 'state' | 'state_since'> & { id?: number } = { name: '', target: '', mode: 'icmp', port: 443, count: 10, interval_min: 5, loss_alert: 20, rtt_alert: 0, enabled: true }

const PRESETS: [string, Partial<Monitor>][] = [
  ['Telegram 新加坡（DC5）', { name: 'Telegram 新加坡 DC5', target: '91.108.56.130', mode: 'tcp', port: 443, count: 20, loss_alert: 10 }],
  ['Telegram 迈阿密（DC1）', { name: 'Telegram 迈阿密 DC1', target: '149.154.175.53', mode: 'tcp', port: 443, count: 10, loss_alert: 10 }],
  ['Cloudflare', { name: 'Cloudflare 1.1.1.1', target: '1.1.1.1', mode: 'icmp', count: 10, loss_alert: 10, rtt_alert: 50 }],
  ['阿里 DNS', { name: '阿里 DNS（中国）', target: '223.5.5.5', mode: 'icmp', count: 10, loss_alert: 10 }],
  ['AWS 新加坡', { name: 'AWS 新加坡', target: 'ec2.ap-southeast-1.amazonaws.com', mode: 'tcp', port: 443, count: 10, loss_alert: 10 }],
  ['AWS 悉尼', { name: 'AWS 悉尼', target: 'ec2.ap-southeast-2.amazonaws.com', mode: 'tcp', port: 443, count: 10, loss_alert: 10 }],
]

const lossOf = (r?: { sent: number; recv: number }) => (r && r.sent ? (100 * (r.sent - r.recv)) / r.sent : 0)
const lossTone = (l: number) => (l >= 20 ? 'text-destructive' : l > 0 ? 'text-[color-mix(in_oklch,var(--warning),black_25%)] dark:text-warning' : 'text-success')

export function Monitors() {
  const { data, reload } = useApi<Monitor[]>('/monitors', 20000)
  const [edit, setEdit] = useState<typeof blank | null>(null)
  const [view, setView] = useState<Monitor | null>(null)
  const { confirm, dialog } = useConfirm()
  const save = async () => {
    if (!edit) return
    try { await post('/monitors', edit); setEdit(null); reload(); toast.success('已保存，马上开始第一轮检测') } catch (e) { toast.error((e as Error).message) }
  }
  const del = async (m: Monitor) => {
    if (!(await confirm(`删除监控「${m.name}」？`, '历史数据也会一起删除。', { danger: true, ok: '删除' }))) return
    try { await api('DELETE', `/monitors/${m.id}`); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const runNow = async (m: Monitor) => {
    try {
      const r = await post<MonRow>(`/monitors/${m.id}/run`)
      toast.success(`${m.name}：收到 ${r.recv}/${r.sent}${r.recv ? `，平均 ${r.avg} ms` : ''}`, { description: r.error })
      reload()
    } catch (e) { toast.error((e as Error).message) }
  }
  const list = data ?? []
  return (
    <div className="grid gap-4">
      <Section title="定时监控" desc="路由器每隔几分钟自动测一次，保存 30 天；连续两次异常就通过告警渠道（Telegram / Server 酱）通知你。TCP 监控每次都换新的源端口，能发现 ping 看不出来的「部分连接被丢」问题"
        action={<Button size="sm" onClick={() => setEdit({ ...blank })}><Plus /> 添加监控</Button>}>
        {!list.length ? <Empty>{data ? '还没有监控。可以先添加「Telegram 新加坡」和「Cloudflare」做对照。' : '加载中…'}</Empty> : (
          <div className="divide-y">
            {list.map((m) => {
              const l = lossOf(m.last), dl = m.day?.loss ?? 0
              return (
                <div key={m.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                  <button type="button" className="flex min-w-0 flex-1 items-center gap-3 text-left" onClick={() => setView(m)}>
                    <Dot tone={!m.enabled ? 'off' : m.state === 'bad' ? 'bad' : m.state === 'ok' ? 'ok' : 'warn'} />
                    <span className="min-w-0">
                      <span className="flex items-center gap-1.5 text-sm font-medium"><span className="truncate">{m.name}</span>{!m.enabled && <Pill>已暂停</Pill>}{m.state === 'bad' && <Pill tone="red">异常 {ago(m.state_since)}</Pill>}</span>
                      <span className="block truncate font-mono text-[11px] text-muted-foreground">{m.mode === 'tcp' ? `TCP ${m.target}:${m.port}` : `Ping ${m.target}`} · 每 {m.interval_min} 分钟 × {m.count} 次</span>
                    </span>
                  </button>
                  <div className="grid grid-cols-3 gap-4 text-right text-xs tabular-nums">
                    <div><div className="text-muted-foreground">最近</div>{m.last ? <span className={lossTone(l)}>{m.last.recv ? `${m.last.avg.toFixed(0)} ms` : '不通'}{l > 0 && m.last.recv ? ` · ${l.toFixed(0)}%` : ''}</span> : '–'}</div>
                    <div><div className="text-muted-foreground">24h 丢包</div><span className={lossTone(dl)}>{m.day ? `${dl.toFixed(1)}%` : '–'}</span></div>
                    <div><div className="text-muted-foreground">24h 延迟</div>{m.day?.avg ? `${m.day.avg.toFixed(0)} ms` : '–'}</div>
                  </div>
                  <div className="flex">
                    <Button variant="ghost" size="icon-sm" title="立即检测" onClick={() => runNow(m)}><Play /></Button>
                    <Button variant="ghost" size="icon-sm" title="修改" onClick={() => setEdit({ ...m })}><Pencil /></Button>
                    <Button variant="ghost" size="icon-sm" title="删除" onClick={() => del(m)}><Trash2 /></Button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Section>
      <MonitorEditor value={edit} onChange={setEdit} onSave={save} />
      <MonitorDetail m={view} onClose={() => setView(null)} />
      {dialog}
    </div>
  )
}

function MonitorEditor({ value: v, onChange, onSave }: { value: typeof blank | null; onChange: (v: typeof blank | null) => void; onSave: () => void }) {
  const set = (p: Partial<typeof blank>) => v && onChange({ ...v, ...p })
  const num = (s: string) => Number(s.replace(/\D/g, '')) || 0
  return (
    <HalfPanel open={!!v} onOpenChange={(o) => { if (!o) onChange(null) }} title={v?.id ? '修改监控' : '添加监控'}
      footer={<><Button variant="outline" onClick={() => onChange(null)}>取消</Button><Button disabled={!v?.name || !v?.target} onClick={onSave}>保存</Button></>}>
      {v && (
        <div className="grid gap-4">
          {!v.id && (
            <Field label="常用模板">
              <div className="flex flex-wrap gap-1.5">
                {PRESETS.map(([l, p]) => <button key={l} type="button" onClick={() => set({ ...blank, ...p })} className="rounded-full border px-2.5 py-0.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground">{l}</button>)}
              </div>
            </Field>
          )}
          <Field label="名称"><Input value={v.name} maxLength={40} onChange={(e) => set({ name: e.target.value })} placeholder="例如 NAS、Telegram 新加坡" /></Field>
          <Field label="目标" hint="IP 或域名；局域网设备填它的 IP"><Input value={v.target} onChange={(e) => set({ target: e.target.value.trim() })} placeholder="192.168.1.159 / 1.1.1.1 / example.com" /></Field>
          <div className="flex flex-wrap items-end gap-3">
            <Field label="方式">
              <Tabs value={v.mode} onValueChange={(m) => set({ mode: m as 'icmp' | 'tcp' })}>
                <TabsList><TabsTrigger value="icmp" className="px-3">Ping</TabsTrigger><TabsTrigger value="tcp" className="px-3">TCP 连接</TabsTrigger></TabsList>
              </Tabs>
            </Field>
            {v.mode === 'tcp' && <Field label="端口" className="w-24"><Input value={v.port || ''} inputMode="numeric" onChange={(e) => set({ port: num(e.target.value) })} /></Field>}
            <Field label="每轮次数" className="w-24"><Input value={v.count || ''} inputMode="numeric" onChange={(e) => set({ count: num(e.target.value) })} /></Field>
          </div>
          <Field label="检测间隔">
            <div className="flex flex-wrap gap-1.5">
              {[1, 2, 5, 10, 15, 30, 60].map((n) => (
                <button key={n} type="button" onClick={() => set({ interval_min: n })} className={cn('rounded-md border px-2.5 py-1 text-xs', v.interval_min === n ? 'border-primary bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted')}>{n} 分钟</button>
              ))}
            </div>
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="丢包告警阈值 %" hint="0 = 只有完全不通才告警"><Input value={v.loss_alert} inputMode="numeric" onChange={(e) => set({ loss_alert: num(e.target.value) })} /></Field>
            <Field label="延迟告警阈值 ms" hint="0 = 不按延迟告警"><Input value={v.rtt_alert} inputMode="numeric" onChange={(e) => set({ rtt_alert: num(e.target.value) })} /></Field>
          </div>
          <label className="flex items-center gap-2 text-sm"><Switch checked={v.enabled} onCheckedChange={(c) => set({ enabled: c })} />启用</label>
          <p className="text-xs text-muted-foreground">
            Ping 适合看延迟和普通丢包；很多服务器和骨干路由不回 ping，这时用「TCP 连接」（例如 443 端口）更接近真实应用体验。
            TCP 方式每次都从新端口发起连接，如果线路在负载均衡的某一条路径上丢包，会表现为固定比例的连接失败。
          </p>
        </div>
      )}
    </HalfPanel>
  )
}

function MonitorDetail({ m, onClose }: { m: Monitor | null; onClose: () => void }) {
  const [range, setRange] = useState('24h')
  const { data } = useApi<{ from: number; to: number; bucket: number; points: MonAgg[] | null }>(m ? `/monitors/${m.id}/history?range=${range}` : null, 60000)
  const pts = data?.points ?? []
  const lossMax = Math.max(5, ...pts.map((p) => p.loss))
  const total = pts.reduce((a, p) => ({ sent: a.sent + p.sent, recv: a.recv + p.recv }), { sent: 0, recv: 0 })
  const avg = pts.length ? pts.reduce((a, p) => a + p.avg * p.recv, 0) / Math.max(1, total.recv) : 0
  return (
    <HalfPanel open={!!m} onOpenChange={(o) => { if (!o) onClose() }} title={m?.name ?? ''}
      desc={m ? `${m.mode === 'tcp' ? `TCP ${m.target}:${m.port}` : `Ping ${m.target}`} · 每 ${m.interval_min} 分钟 × ${m.count} 次` : ''}
      footer={m && <a href={`/api/monitors/${m.id}/export`} className="inline-flex h-8 items-center gap-1.5 rounded-lg border px-3 text-sm hover:bg-muted"><Download className="size-4" /> 导出 CSV（给运营商）</a>}>
      {m && (
        <div className="grid gap-5">
          <Tabs value={range} onValueChange={(v) => setRange(String(v))}>
            <TabsList>{[['6h', '6 小时'], ['24h', '24 小时'], ['7d', '7 天'], ['30d', '30 天']].map(([k, l]) => <TabsTrigger key={k} value={k} className="px-3">{l}</TabsTrigger>)}</TabsList>
          </Tabs>
          <div className="grid grid-cols-3 gap-3 text-sm">
            <div className="rounded-xl border p-3"><div className="text-xs text-muted-foreground">丢包 / 失败</div><div className={cn('text-xl font-semibold tabular-nums', lossTone(lossOf(total)))}>{total.sent ? `${lossOf(total).toFixed(1)}%` : '–'}</div><div className="text-[11px] text-muted-foreground">{total.recv}/{total.sent}</div></div>
            <div className="rounded-xl border p-3"><div className="text-xs text-muted-foreground">平均延迟</div><div className="text-xl font-semibold tabular-nums">{avg ? avg.toFixed(0) : '–'}<span className="ml-0.5 text-xs font-normal text-muted-foreground">ms</span></div></div>
            <div className="rounded-xl border p-3"><div className="text-xs text-muted-foreground">检测轮数</div><div className="text-xl font-semibold tabular-nums">{pts.reduce((a, p) => a + p.rounds, 0)}</div></div>
          </div>
          {!pts.length ? <Empty>这个时间段还没有数据</Empty> : (
            <>
              <div>
                <div className="mb-1 flex items-center gap-1.5 text-xs text-muted-foreground"><Activity className="size-3.5" />延迟（ms）</div>
                <AreaChart height={160} times={pts.map((p) => p.t)} format={(v) => `${v.toFixed(0)} ms`}
                  series={[{ label: '平均', color: '#3b82f6', values: pts.map((p) => p.avg) }, { label: '最高', color: '#f59e0b', values: pts.map((p) => p.max) }]} />
              </div>
              <div>
                <div className="mb-1 text-xs text-muted-foreground">丢包 / 失败率（最高 {lossMax.toFixed(0)}%）</div>
                <div className="flex h-16 items-end gap-px">
                  {pts.map((p) => (
                    <div key={p.t} title={`${datetime(p.t)} · ${p.loss}%（${p.recv}/${p.sent}）`} className={cn('min-w-px flex-1 rounded-t-sm', p.loss >= 20 ? 'bg-destructive/80' : p.loss > 0 ? 'bg-warning/80' : 'bg-success/30')}
                      style={{ height: `${Math.max(4, (p.loss / lossMax) * 100)}%` }} />
                  ))}
                </div>
                <div className="mt-1 flex justify-between text-[10px] text-muted-foreground"><span>{datetime(pts[0].t)}</span><span>{datetime(pts[pts.length - 1].t)}</span></div>
              </div>
            </>
          )}
          {m.last?.error && <p className="text-xs text-destructive">最近一次：{m.last.error}</p>}
        </div>
      )}
    </HalfPanel>
  )
}
