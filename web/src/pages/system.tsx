import { useEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import { Cpu, Download, HardDrive, Loader2, MemoryStick, Power, RefreshCw, RotateCcw, Search, Thermometer, Upload } from 'lucide-react'
import { post } from '@/lib/api'
import { runAction } from '@/lib/actions'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { bytes, duration } from '@/lib/format'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Empty, Pill, Section, useConfirm } from '@/components/common'
import { Kpi } from '@/components/monitor'
import { DepsPanel } from '@/components/deps'
import { Button, buttonVariants } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

interface HW {
  hw: { cpu_model: string; cores: number; cpu: number; per_core: number[] | null; temps: { name: string; c: number }[] | null; disks: { mount: string; dev: string; total: number; used: number }[] | null }
  system: { hostname: string; release: string; kernel: string; model: string; uptime: number; load: number[]; mem_total: number; mem_available: number; conntrack: number; conntrack_max: number }
}
interface Svc { name: string; label: string; desc?: string; enabled: boolean; running: boolean; critical?: boolean }
interface LogLine { ts?: string; level?: string; proc?: string; msg: string }
interface Sched { enabled: boolean; time: string; days: number[] | null }

const WEEK = ['日', '一', '二', '三', '四', '五', '六']

function Meter({ value, tone }: { value: number; tone?: string }) {
  return (
    <div className="h-1.5 w-full rounded-full bg-muted">
      <div className={cn('h-1.5 rounded-full transition-all', tone ?? (value > 90 ? 'bg-destructive' : value > 70 ? 'bg-warning' : 'bg-primary'))} style={{ width: `${Math.min(100, value)}%` }} />
    </div>
  )
}

export default function SystemPage() {
  const { can, isSuper } = useAuth()
  const { data } = useApi<HW>('/system/hw', 5000)
  const { confirm, dialog } = useConfirm()
  const hw = data?.hw
  const sys = data?.system
  const memUsed = sys ? ((sys.mem_total - sys.mem_available) / sys.mem_total) * 100 : 0
  const hot = hw?.temps?.length ? Math.max(...hw.temps.map((t) => t.c)) : null

  useEffect(() => { if (location.hash === '#deps') setTimeout(() => document.getElementById('deps')?.scrollIntoView({ behavior: 'smooth' }), 300) }, [])

  const reboot = async () => {
    if (!(await confirm('重启路由器？', '重启期间（通常 1～2 分钟）全家断网，面板也会暂时无法访问。', { danger: true, ok: '立即重启' }))) return
    try { if (await runAction('system.reboot', {})) toast.info('路由器正在重启，约 1～2 分钟后刷新页面') } catch (e) { toast.error((e as Error).message) }
  }

  return (
    <>
      <PageHeader title="系统维护" desc={sys ? `${sys.model || sys.hostname} · ${sys.release} · 内核 ${sys.kernel}` : '硬件状态、插件服务、日志、重启与备份'}>
        {can('system.manage') && <Button variant="outline" size="sm" className="text-destructive" onClick={reboot}><Power /> 重启路由器</Button>}
      </PageHeader>
      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <Kpi icon={Cpu} label="CPU" value={hw ? `${hw.cpu}%` : '–'} sub={hw ? `${hw.cores} 核 · 负载 ${sys?.load?.map((l) => l.toFixed(2)).join(' / ') ?? ''}` : ''} tone={hw && hw.cpu > 80 ? 'amber' : undefined} />
        <Kpi icon={MemoryStick} label="内存" value={sys ? `${memUsed.toFixed(0)}%` : '–'} sub={sys ? `${bytes(sys.mem_total - sys.mem_available)} / ${bytes(sys.mem_total)}` : ''} tone={memUsed > 85 ? 'amber' : undefined} />
        <Kpi icon={Thermometer} label="温度" value={hot !== null ? `${hot.toFixed(0)}°C` : '–'} sub={hot !== null ? hw!.temps!.map((t) => t.name).slice(0, 2).join('、') : '没有温度传感器（虚拟机常见）'} tone={hot !== null && hot > 80 ? 'red' : undefined} />
        <Kpi icon={RotateCcw} label="已运行" value={sys ? duration(sys.uptime) : '–'} sub={sys ? `连接数 ${sys.conntrack} / ${sys.conntrack_max}` : ''} />
      </div>

      <div id="deps" className="mt-4 scroll-mt-20">
        <Section title="依赖组件" desc="面板用到的 OpenWrt 官方软件包。缺少时对应功能会提示；超级管理员可以在这里一键安装">
          <div className="p-4"><DepsPanel /></div>
        </Section>
      </div>

      <div className="mt-4 grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_400px]">
        <div className="grid min-w-0 gap-4">
          <Services />
          <Logs />
        </div>
        <div className="grid min-w-0 gap-4">
          <Section title="CPU 与磁盘" desc={hw?.cpu_model}>
            <div className="grid gap-4 p-4">
              {hw?.per_core && (
                <div className="grid grid-cols-4 gap-x-3 gap-y-2">
                  {hw.per_core.map((v, i) => (
                    <div key={i} className="grid gap-1">
                      <div className="flex justify-between text-[11px] text-muted-foreground"><span>核 {i}</span><span className="tabular-nums">{v.toFixed(0)}%</span></div>
                      <Meter value={v} />
                    </div>
                  ))}
                </div>
              )}
              {(hw?.disks ?? []).map((d) => {
                const p = d.total ? (d.used / d.total) * 100 : 0
                return (
                  <div key={d.dev + d.mount} className="grid gap-1">
                    <div className="flex items-center gap-2 text-sm">
                      <HardDrive className="size-3.5 text-muted-foreground" />
                      <span className="font-medium">{d.mount}</span>
                      <span className="truncate text-xs text-muted-foreground">{d.dev}</span>
                      <span className="ml-auto shrink-0 text-xs tabular-nums text-muted-foreground">{bytes(d.used)} / {bytes(d.total)}</span>
                    </div>
                    <Meter value={p} />
                  </div>
                )
              })}
            </div>
          </Section>
          <RebootSchedule />
          {isSuper && <Backup />}
        </div>
      </div>
      {dialog}
    </>
  )
}

function Services() {
  const { can } = useAuth()
  const { data, reload } = useApi<Svc[]>('/system/services', 15000)
  const [busy, setBusy] = useState('')
  const { confirm, dialog } = useConfirm()
  const act = async (s: Svc, action: 'on' | 'off' | 'restart') => {
    if (action === 'off' && s.critical && !(await confirm(`关闭 ${s.label}？`, `${s.label} 关闭后，依赖它的 DNS 解析或分流会立即失效，可能导致全家无法上网。`, { danger: true, ok: '仍然关闭' }))) return
    setBusy(s.name)
    try { await runAction('system.service', { name: s.name, action }); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy('') }
  }
  return (
    <Section title="插件服务" desc="开关 iStore / OpenWrt 插件；普通管理员的操作需超级管理员批准">
      {!data ? <Empty>加载中…</Empty> : !data.length ? <Empty>没有检测到支持的插件</Empty> : (
        <div className="divide-y">
          {data.map((s) => (
            <div key={s.name} className="flex items-center gap-3 px-4 py-2.5">
              <span className={cn('size-2 shrink-0 rounded-full', s.running ? 'bg-success' : 'bg-muted-foreground/40')} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5 text-sm font-medium">{s.label}{s.critical && <Pill tone="amber">关键</Pill>}</div>
                <div className="truncate text-xs text-muted-foreground">{s.running ? '运行中' : s.enabled ? '已开启，未运行' : '已关闭'}{s.desc ? ` · ${s.desc}` : ''}</div>
              </div>
              {busy === s.name && <Loader2 className="size-4 animate-spin text-muted-foreground" />}
              {can('system.manage') && (
                <>
                  <Button variant="ghost" size="icon-sm" title="重启服务" disabled={!!busy || !s.enabled} onClick={() => act(s, 'restart')}><RefreshCw /></Button>
                  <Switch checked={s.enabled} disabled={!!busy} onCheckedChange={(on) => act(s, on ? 'on' : 'off')} />
                </>
              )}
            </div>
          ))}
        </div>
      )}
      {dialog}
    </Section>
  )
}

function Logs() {
  const [source, setSource] = useState('system')
  const [q, setQ] = useState('')
  const [query, setQuery] = useState('')
  const { data, reload } = useApi<LogLine[]>(`/system/log?source=${source}&lines=400&q=${encodeURIComponent(query)}`, 10000)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight }, [data])
  useEffect(() => { const t = setTimeout(() => setQuery(q), 400); return () => clearTimeout(t) }, [q])
  const tone = (lv?: string) => (lv?.match(/\.(err|crit|alert|emerg)$/) ? 'text-destructive' : lv?.endsWith('.warn') ? 'text-warning' : '')
  return (
    <Section title="系统日志" desc="最近 400 条，每 10 秒刷新"
      action={<Button variant="ghost" size="icon-sm" onClick={reload} title="刷新"><RefreshCw /></Button>}>
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-2">
        <Tabs value={source} onValueChange={(v) => setSource(String(v))}>
          <TabsList><TabsTrigger value="system">系统</TabsTrigger><TabsTrigger value="kernel">内核</TabsTrigger></TabsList>
        </Tabs>
        <div className="relative min-w-40 flex-1">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="过滤关键字，如 dnsmasq、error" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 pl-8" />
        </div>
      </div>
      <div ref={box} className="max-h-[420px] overflow-auto px-4 py-2 font-mono text-[11px] leading-5">
        {!data ? <Empty>加载中…</Empty> : !data.length ? <Empty>没有匹配的日志</Empty> : data.map((l, i) => (
          <div key={i} className={cn('break-all', tone(l.level))}>
            {l.ts && <span className="mr-2 text-muted-foreground">{l.ts.replace(/^\w{3}\s+\d+ /, '')}</span>}
            {l.proc && <span className="mr-1 text-primary">{l.proc}:</span>}{l.msg}
          </div>
        ))}
      </div>
    </Section>
  )
}

function RebootSchedule() {
  const { can } = useAuth()
  const { data, reload } = useApi<Sched>('/system/reboot-schedule')
  const [d, setD] = useState<Sched | null>(null)
  useEffect(() => { if (data) setD({ ...data, days: data.days ?? [] }) }, [data])
  if (!d) return null
  const days = d.days ?? []
  const dirty = JSON.stringify({ ...d, days: [...days].sort() }) !== JSON.stringify({ ...data, days: [...(data?.days ?? [])].sort() })
  const save = async () => {
    try { await runAction('system.reboot_schedule', d); reload() } catch (e) { toast.error((e as Error).message) }
  }
  const editable = can('system.manage')
  return (
    <Section title="定时重启" desc="长期运行的路由器定期重启可以释放内存；不选星期则每天执行"
      action={<Switch checked={d.enabled} disabled={!editable} onCheckedChange={(v) => setD({ ...d, enabled: v })} />}>
      <div className={cn('grid gap-3 p-4', !d.enabled && 'opacity-50')}>
        <div className="flex items-center gap-2 text-sm">
          时间 <Input type="time" value={d.time} disabled={!d.enabled || !editable} onChange={(e) => setD({ ...d, time: e.target.value })} className="h-8 w-28" />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {WEEK.map((w, i) => {
            const on = days.includes(i)
            return (
              <button key={i} type="button" disabled={!d.enabled || !editable}
                onClick={() => setD({ ...d, days: on ? days.filter((x) => x !== i) : [...days, i] })}
                className={cn('size-8 rounded-lg border text-xs transition-colors', on ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted')}>{w}</button>
            )
          })}
        </div>
        {editable && <div><Button size="sm" disabled={!dirty} onClick={save}>保存</Button></div>}
      </div>
    </Section>
  )
}

function Backup() {
  const [file, setFile] = useState<{ name: string; data: string } | null>(null)
  const [files, setFiles] = useState<string[] | null>(null)
  const [busy, setBusy] = useState(false)
  const { confirm, dialog } = useConfirm()
  const pick = (f?: File) => {
    if (!f) return
    if (f.size > 40 << 20) { toast.error('备份文件不能超过 40 MB'); return }
    const r = new FileReader()
    r.onload = async () => {
      const data = String(r.result).split(',')[1] ?? ''
      setFile({ name: f.name, data }); setBusy(true)
      try { const res = await post<{ files: string[] }>('/system/restore', { data, check: true, name: f.name }); setFiles(res.files) } catch (e) { toast.error((e as Error).message); setFile(null) } finally { setBusy(false) }
    }
    r.readAsDataURL(f)
  }
  const restore = async () => {
    if (!file || !(await confirm('从备份恢复并重启？', `将用 ${file.name} 覆盖路由器上的 ${files?.length} 个配置文件，然后立即重启。如果备份来自其他设备，可能导致无法联网。`, { danger: true, ok: '恢复并重启' }))) return
    setBusy(true)
    try { await post('/system/restore', { data: file.data, name: file.name }); toast.info('配置已恢复，路由器正在重启'); setFile(null); setFiles(null) } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  return (
    <Section title="配置备份" desc="备份包含 /etc 下的全部配置（含 Wi-Fi 密码、密钥），请妥善保管">
      <div className="grid gap-3 p-4">
        <div className="flex flex-wrap gap-2">
          <a href="/api/system/backup" download className={buttonVariants({ variant: 'outline', size: 'sm' })}><Download /> 下载备份</a>
          <label className={cn('inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-lg border px-2.5 text-[0.8rem] font-medium hover:bg-muted', busy && 'pointer-events-none opacity-50')}>
            <Upload className="size-3.5" /> 从备份恢复…
            <input type="file" accept=".tar.gz,.tgz,application/gzip" className="hidden" onChange={(e) => { pick(e.target.files?.[0]); e.target.value = '' }} />
          </label>
        </div>
        {files && file && (
          <div className="grid gap-2 rounded-lg border border-warning/40 bg-warning/5 p-3 text-xs">
            <div><b>{file.name}</b> 包含 {files.length} 个配置文件：</div>
            <div className="max-h-32 overflow-auto font-mono text-muted-foreground">{files.join('  ')}</div>
            <div className="flex gap-2">
              <Button size="sm" variant="destructive" disabled={busy} onClick={restore}>恢复并重启</Button>
              <Button size="sm" variant="ghost" onClick={() => { setFile(null); setFiles(null) }}>取消</Button>
            </div>
          </div>
        )}
      </div>
      {dialog}
    </Section>
  )
}
