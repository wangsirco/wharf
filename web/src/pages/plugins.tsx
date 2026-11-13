import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { AlertTriangle, ArrowRight, CheckCircle2, Download, Loader2, Package, Puzzle, RefreshCw, Search, ShieldAlert, Trash2, XCircle } from 'lucide-react'
import { get, post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { ago, bytes } from '@/lib/format'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Dot, Empty, ErrorBox, Pill } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { pluginState, type PluginItem } from '@/lib/plugins'
import { formPages } from '@/lib/plugin-import'
import { ImportDialog } from '@/components/plugin-import'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'

interface StoreApp { pkg: string; version: string; size: number; desc: string; feed: string; installed: string; i18n: string; name: string; about: string; group: string; group_label: string; covered: string; known: boolean }
interface StoreResp { apps: StoreApp[] | null; lists_at: number; arch: string; free_bytes: number; job: Job }
interface Job { running: boolean; action: string; pkgs: string[] | null; started: number; ended: number; log: string[] | null; error?: string }
interface Check { check: { pkg: string; installs: string[] | null; bytes: number; free_bytes: number; errors: string[] | null; output: string }; verdict: 'ok' | 'warn' | 'block'; notes: string[] | null }

const catLabel: Record<string, string> = { services: '服务', network: '网络', system: '系统', nas: '存储', vpn: 'VPN', status: '状态', control: '管控', docker: 'Docker', other: '其他' }


export default function PluginsPage() {
  const [q, setQ] = useSearchParams()
  const tab = q.get('tab') === 'store' ? 'store' : 'installed'
  return (
    <div className="grid gap-4">
      <PageHeader title="插件" desc="路由器上装的 OpenWrt 插件，在这里看状态、改设置、管端口，不用再打开 LuCI。">
        <Tabs value={tab} onValueChange={(v) => { q.set('tab', String(v)); setQ(q, { replace: true }) }}>
          <TabsList><TabsTrigger value="installed">已安装</TabsTrigger><TabsTrigger value="store">插件商店</TabsTrigger></TabsList>
        </Tabs>
      </PageHeader>
      {tab === 'installed' ? <Installed /> : <Store />}
    </div>
  )
}

function Installed() {
  const { can } = useAuth()
  const manage = can('plugins.manage')
  const { data, error, loading, reload } = useApi<{ plugins: PluginItem[] | null }>('/plugins', 30000)
  const [search, setSearch] = useState('')
  const [importing, setImporting] = useState<PluginItem[] | null>(null)
  const list = useMemo(() => {
    const s = search.trim().toLowerCase()
    return (data?.plugins ?? []).filter((p) => !s || (p.title + p.pkg + p.about + p.luci_title).toLowerCase().includes(s))
      .sort((a, b) => Number(!!a.covered) - Number(!!b.covered) || (pluginState(a)[1] === 'ok' ? 0 : 1) - (pluginState(b)[1] === 'ok' ? 0 : 1) || a.title.localeCompare(b.title))
  }, [data, search])
  const mine = list.filter((p) => p.imported)
  const native = list.filter((p) => !p.imported)
  const warn = (data?.plugins ?? []).flatMap((p) => (p.warnings ?? []).map((w) => `${p.title}：${w}`))
  return (
    <>
      {error && <ErrorBox>{error}</ErrorBox>}
      {warn.length > 0 && (
        <div className="grid gap-1 rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
          {[...new Set(warn)].map((w) => <div key={w} className="flex gap-2"><AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" />{w}</div>)}
        </div>
      )}
      <div className="flex items-center gap-2">
        <div className="relative max-w-sm flex-1"><Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" /><Input className="pl-8" placeholder="搜索插件" value={search} onChange={(e) => setSearch(e.target.value)} /></div>
        <Button variant="ghost" size="sm" onClick={() => reload()}><RefreshCw className={cn(loading && 'animate-spin')} /> 刷新</Button>
      </div>

      <div className="grid gap-2">
        <h2 className="text-sm font-semibold">由 Wharf 管理 <span className="font-normal text-muted-foreground">· {mine.length}</span></h2>
        {mine.length ? (
          <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">{mine.map((p) => <PluginCard key={p.pkg} p={p} />)}</div>
        ) : data ? <Empty>{native.length ? '还没有导入插件。导入后，插件的设置页会一次性换成 Wharf 的样式。' : '没有找到插件'}</Empty> : null}
      </div>

      {native.length > 0 && (
        <div className="grid gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold">OpenWrt 原有插件 <span className="font-normal text-muted-foreground">· {native.length}</span></h2>
            <span className="text-xs text-muted-foreground">还在用 LuCI 的界面。导入后由 Wharf 管理，所有设置页提前换好样式，打开即用。</span>
            <span className="flex-1" />
            {manage && <Button size="sm" onClick={() => setImporting(native.filter((p) => !p.covered))}><Puzzle /> 全部导入</Button>}
          </div>
          <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
            {native.map((p) => <PluginCard key={p.pkg} p={p} onImport={manage ? () => setImporting([p]) : undefined} />)}
          </div>
        </div>
      )}
      {importing && importing.length > 0 && <ImportDialog plugins={importing} onClose={() => { setImporting(null); reload() }} />}
    </>
  )
}

function PluginCard({ p, onImport }: { p: PluginItem; onImport?: () => void }) {
  const [st, tone] = pluginState(p)
  const pages = formPages(p).length
  return (
    <Link to={`/plugins/${p.pkg}`} className={cn('group grid content-start gap-2 rounded-xl border bg-card p-4 transition-colors hover:border-primary/40', p.covered && 'opacity-75')}>
      <div className="flex items-start gap-3">
        <span className={cn('grid size-10 shrink-0 place-items-center rounded-xl', p.imported ? 'bg-accent text-accent-foreground' : 'bg-muted text-muted-foreground')}><Package className="size-5" /></span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 font-semibold">{p.title}<ArrowRight className="size-3.5 opacity-0 transition-opacity group-hover:opacity-60" /></div>
          <div className="truncate text-xs text-muted-foreground">{p.pkg} · {p.version}</div>
        </div>
        <span className="flex items-center gap-1.5 text-xs"><Dot tone={tone} />{st}</span>
      </div>
      {(p.about || p.desc) && <p className="line-clamp-2 text-sm text-muted-foreground">{p.about || p.desc}</p>}
      <div className="flex flex-wrap items-center gap-1.5">
        {p.group_label && <Pill>{p.group_label}</Pill>}
        {!p.group_label && <Pill>{catLabel[p.category] ?? p.category}</Pill>}
        {(p.ports ?? []).filter((x) => !x.local).slice(0, 4).map((x) => <Pill key={x.port + x.proto} tone={x.wan_open ? 'amber' : 'blue'}>{x.port}/{x.proto}{x.wan_open ? ' 外网可访问' : ''}</Pill>)}
        {p.covered && <Pill tone="green">Wharf 已自带</Pill>}
        {!!p.warnings?.length && <Pill tone="amber">{p.warnings.length} 个提醒</Pill>}
        {p.by_wharf && <Pill>经 Wharf 安装</Pill>}
        {p.imported && p.imported.version !== p.version && <Pill tone="amber">插件已升级，需重新导入</Pill>}
        {!p.imported && pages > 0 && <Pill>{pages} 个设置页</Pill>}
        <span className="flex-1" />
        {onImport && <Button size="xs" variant="outline" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onImport() }}><Puzzle /> 导入</Button>}
      </div>
    </Link>
  )
}

function Store() {
  const { can } = useAuth()
  const install = can('plugins.install')
  const { data, error, reload } = useApi<StoreResp>('/store')
  const [search, setSearch] = useState('')
  const [group, setGroup] = useState('all')
  const [checking, setChecking] = useState<StoreApp | null>(null)
  const [job, setJob] = useState<Job | null>(null)
  const [removing, setRemoving] = useState<StoreApp | null>(null)
  const [importing, setImporting] = useState<PluginItem[] | null>(null)

  useEffect(() => { if (data?.job?.running) setJob(data.job) }, [data])
  const apps = useMemo(() => {
    const s = search.trim().toLowerCase()
    return (data?.apps ?? []).filter((a) => (group === 'all' || a.group === group) && (!s || (a.name + a.pkg + a.about + a.desc).toLowerCase().includes(s)))
      .sort((a, b) => Number(b.known) - Number(a.known) || Number(!!b.installed) - Number(!!a.installed) || a.name.localeCompare(b.name))
  }, [data, search, group])
  const groups = useMemo(() => [...new Map((data?.apps ?? []).map((a) => [a.group, a.group_label])).entries()].sort(), [data])

  const start = async (action: string, pkgs: string[] = []) => {
    try {
      await post('/store', { action, pkgs })
      setJob({ running: true, action, pkgs, started: Date.now() / 1000, ended: 0, log: [] })
    } catch (e) { toast.error((e as Error).message) }
  }

  return (
    <>
      {error && <ErrorBox>{error}</ErrorBox>}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border bg-card px-4 py-3 text-sm">
        <span>软件来源：路由器自己的 opkg 软件源（{data?.arch}）</span>
        <span className="text-muted-foreground">{data?.lists_at ? `列表更新于 ${ago(data.lists_at)}` : '还没有下载软件列表（路由器重启后会清空）'}</span>
        <span className="text-muted-foreground">· 系统分区剩余 {bytes(data?.free_bytes ?? 0)}</span>
        <span className="flex-1" />
        {install && <Button size="sm" variant="outline" disabled={job?.running} onClick={() => start('update')}><RefreshCw /> 刷新软件列表</Button>}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1"><Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" /><Input className="pl-8" placeholder="搜索，如 adguard、zerotier" value={search} onChange={(e) => setSearch(e.target.value)} /></div>
        <select className="h-9 rounded-md border bg-background px-2 text-sm" value={group} onChange={(e) => setGroup(e.target.value)}>
          <option value="all">全部分类</option>{groups.map(([g, l]) => <option key={g} value={g}>{l}</option>)}
        </select>
      </div>
      <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
        {apps.map((a) => {
          const upd = a.installed && a.installed !== a.version && a.feed !== 'local'
          return (
            <div key={a.pkg} className="grid content-start gap-2 rounded-xl border bg-card p-4">
              <div className="flex items-start gap-3">
                <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-muted"><Package className="size-5 text-muted-foreground" /></span>
                <div className="min-w-0 flex-1">
                  <div className="font-semibold">{a.name}</div>
                  <div className="truncate text-xs text-muted-foreground">{a.pkg} · {a.version}{a.size ? ` · ${bytes(a.size)}` : ''}</div>
                </div>
                {a.installed ? <Pill tone={upd ? 'amber' : 'green'}>{upd ? '有更新' : '已安装'}</Pill> : null}
              </div>
              <p className="line-clamp-2 text-sm text-muted-foreground">{a.about || a.desc || '没有说明'}</p>
              <div className="flex flex-wrap items-center gap-1.5">
                <Pill>{a.group_label}</Pill>
                {a.covered && <Pill tone="green">Wharf 已自带</Pill>}
                {a.i18n && <Pill tone="blue">有中文</Pill>}
                <span className="flex-1" />
                {a.installed ? (
                  <>
                    <Button size="sm" variant="ghost" render={<Link to={`/plugins/${a.pkg}`} />}>打开</Button>
                    {install && upd && <Button size="sm" variant="outline" disabled={job?.running} onClick={() => setChecking(a)}><Download /> 更新</Button>}
                    {install && <Button size="sm" variant="ghost" className="text-destructive" disabled={job?.running} onClick={() => setRemoving(a)}><Trash2 /></Button>}
                  </>
                ) : install && data?.lists_at ? <Button size="sm" variant="outline" disabled={job?.running} onClick={() => setChecking(a)}><Download /> 安装</Button> : null}
              </div>
            </div>
          )
        })}
      </div>
      {data && !apps.length && <Empty>{data.lists_at ? '没有找到' : '先点「刷新软件列表」下载可安装的插件'}</Empty>}
      {checking && <CheckDialog app={checking} onClose={() => setChecking(null)} onInstall={(pkgs) => { setChecking(null); start('install', pkgs) }} />}
      {removing && (
        <Dialog open onOpenChange={(o) => { if (!o) setRemoving(null) }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>卸载 {removing.name}？</DialogTitle>
              <DialogDescription>会运行 opkg remove --autoremove，只为它装的依赖一并删除；它的配置文件保留在 /etc/config。别的软件依赖它时会卸载失败。</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setRemoving(null)}>取消</Button>
              <Button variant="destructive" onClick={() => { const a = removing; setRemoving(null); start('remove', [a.pkg, ...(a.i18n ? [a.i18n] : [])]) }}>卸载</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
      {job && <JobDialog job={job} onClose={async () => {
        const j = job
        setJob(null); reload()
        // a plugin installed here is managed by Wharf right away: convert its pages now
        if (j.action === 'install' && !j.error && can('plugins.manage')) {
          try {
            const r = await get<{ plugins: PluginItem[] | null }>('/plugins?fresh=1')
            const fresh = (r.plugins ?? []).filter((p) => j.pkgs?.includes(p.pkg) && !p.imported)
            if (fresh.length) setImporting(fresh)
          } catch { /* the user can import from the list */ }
        }
      }} />}
      {importing && <ImportDialog plugins={importing} onClose={() => { setImporting(null); reload() }} />}
    </>
  )
}

function CheckDialog({ app, onClose, onInstall }: { app: StoreApp; onClose: () => void; onInstall: (pkgs: string[]) => void }) {
  const [c, setC] = useState<Check | null>(null)
  const [err, setErr] = useState('')
  useEffect(() => { get<Check>(`/store/check?pkg=${encodeURIComponent(app.pkg)}`).then(setC, (e) => setErr((e as Error).message)) }, [app.pkg])
  const icon = c?.verdict === 'ok' ? <CheckCircle2 className="size-5 text-success" /> : c?.verdict === 'warn' ? <ShieldAlert className="size-5 text-warning" /> : <XCircle className="size-5 text-destructive" />
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>安装 {app.name}</DialogTitle>
          <DialogDescription>先让路由器模拟一遍安装，检查依赖、架构、空间和与现有插件的冲突。</DialogDescription>
        </DialogHeader>
        {!c && !err && <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> 正在检查…</div>}
        {err && <ErrorBox>{err}</ErrorBox>}
        {c && (
          <div className="grid gap-3 text-sm">
            <div className="flex items-center gap-2 font-medium">{icon}{{ ok: '可以安装', warn: '可以安装，但请留意', block: '不建议安装' }[c.verdict]}</div>
            {!!c.notes?.length && <ul className="grid gap-1 pl-1">{c.notes.map((n) => <li key={n} className="flex gap-2"><span className="text-muted-foreground">•</span>{n}</li>)}</ul>}
            {!!c.check.installs?.length && (
              <div className="rounded-lg bg-muted/40 px-3 py-2">
                <div className="mb-1 text-xs text-muted-foreground">将安装 {c.check.installs.length} 个软件包（下载约 {bytes(c.check.bytes)}，剩余空间 {bytes(c.check.free_bytes)}）</div>
                <div className="max-h-32 overflow-y-auto font-mono text-xs">{c.check.installs.map((i) => <div key={i}>{i}</div>)}</div>
              </div>
            )}
            {c.check.output && <details><summary className="cursor-pointer text-xs text-muted-foreground">opkg 原始输出</summary><pre className="mt-1 max-h-40 overflow-auto rounded bg-muted p-2 text-[11px]">{c.check.output}</pre></details>}
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>取消</Button>
          <Button disabled={!c || c.verdict === 'block'} onClick={() => onInstall([app.pkg, ...(app.i18n ? [app.i18n] : [])])}>安装{app.i18n ? '（含中文）' : ''}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function JobDialog({ job: initial, onClose }: { job: Job; onClose: () => void }) {
  const [job, setJob] = useState(initial)
  const end = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!job.running) return
    const t = window.setInterval(async () => { try { setJob(await get<Job>('/store/job')) } catch { /* keep polling */ } }, 1500)
    return () => clearInterval(t)
  }, [job.running])
  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }) }, [job.log?.length])
  const title = { update: '刷新软件列表', install: '安装插件', remove: '卸载插件' }[job.action] ?? job.action
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !job.running) onClose() }}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">{job.running ? <Loader2 className="size-4 animate-spin" /> : job.error ? <XCircle className="size-4 text-destructive" /> : <CheckCircle2 className="size-4 text-success" />}{title}</DialogTitle>
          <DialogDescription>{job.running ? '正在进行，请不要关闭路由器电源。' : job.error || '完成。'}</DialogDescription>
        </DialogHeader>
        <pre className="max-h-80 overflow-auto rounded-lg bg-muted p-3 text-[11px] leading-relaxed">{(job.log ?? []).join('\n') || '…'}<div ref={end} /></pre>
        <DialogFooter><Button disabled={job.running} onClick={onClose}>关闭</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
