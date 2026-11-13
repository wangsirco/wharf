import { useEffect, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { ArrowLeft, ExternalLink, Globe, Loader2, Lock, Package, Play, Puzzle, RefreshCw, Square } from 'lucide-react'
import { post, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { useAuth } from '@/lib/auth'
import { datetime } from '@/lib/format'
import { type FormBlock, type UciChange } from '@/lib/plugin-form'
import { convertPage, formPages, storePage, unimportPlugin, withCurrentValues, type ImportedPage, type PluginImport } from '@/lib/plugin-import'
import { ImportDialog } from '@/components/plugin-import'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Dot, Empty, ErrorBox, Pill, Section, useConfirm } from '@/components/common'
import { PluginForm } from '@/components/plugin-form'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { pluginState, type PluginItem } from '@/lib/plugins'

const luciBase = () => `${location.protocol}//${location.hostname}/cgi-bin/luci/`

export default function PluginPage() {
  const { pkg = '' } = useParams()
  const { can } = useAuth()
  const manage = can('plugins.manage')
  const { data, error, reload } = useApi<{ plugins: PluginItem[] | null }>('/plugins', 20000)
  const p = data?.plugins?.find((x) => x.pkg === pkg)
  const imported = !!p?.imported
  const { data: imp, reload: reloadImp } = useApi<PluginImport>(imported ? `/plugins/import?pkg=${encodeURIComponent(pkg)}` : null)
  const [importing, setImporting] = useState(false)
  const [q, setQ] = useSearchParams()
  // tabs come from the imported copy; keyed by path so the 20 s list refresh doesn't reload the page
  const pages = imported ? imp?.pages ?? [] : []
  const tab = q.get('page') ?? 'overview'
  const page = pages.find((g) => g.path === tab)
  const { confirm, dialog } = useConfirm()

  if (error) return <ErrorBox>{error}</ErrorBox>
  if (!data) return <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> 正在读取插件…</div>
  if (!p) return <div className="grid gap-3"><ErrorBox>没有安装 {pkg}</ErrorBox><Button variant="outline" className="w-fit" render={<Link to="/plugins" />}><ArrowLeft /> 返回插件</Button></div>
  const [st, tone] = pluginState(p)
  const native = formPages(p)
  const unimport = async () => {
    if (!(await confirm(`把 ${p.title} 交还给 LuCI？`, '只是删掉 Wharf 里转换好的页面，插件本身和它的设置都不受影响。之后可以随时再导入。', { ok: '取消导入' }))) return
    try { await unimportPlugin(p.pkg); q.delete('page'); setQ(q, { replace: true }); reload() } catch (e) { toast.error((e as Error).message) }
  }

  return (
    <div className="grid gap-4">
      <div>
        <Button variant="ghost" size="sm" className="-ml-2 mb-1" render={<Link to="/plugins" />}><ArrowLeft /> 插件</Button>
        <PageHeader title={p.title} desc={p.about || p.desc}>
          <span className="flex items-center gap-1.5 text-sm"><Dot tone={tone} />{st}</span>
          <Button variant="outline" size="sm" render={<a href={luciBase() + (native[0]?.path ?? '')} target="_blank" rel="noreferrer" />}><ExternalLink /> 在 LuCI 中打开</Button>
        </PageHeader>
      </div>
      {p.covered && (
        <div className="flex items-center gap-3 rounded-xl border border-success/40 bg-success/8 px-4 py-3 text-sm">
          Wharf 已经自带了这个功能，通常用 Wharf 自己的页面更方便。<Button size="sm" variant="outline" className="ml-auto" render={<Link to={p.covered} />}>打开 Wharf 的页面</Button>
        </div>
      )}
      {!imported && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-primary/30 bg-accent/40 px-4 py-3 text-sm">
          <Puzzle className="size-5 shrink-0 text-primary" />
          <div className="min-w-0 flex-1">
            <div className="font-medium">这个插件还在用 OpenWrt 原来的界面</div>
            <div className="text-muted-foreground">{native.length ? `导入后，它的 ${native.length} 个设置页会一次性换成 Wharf 的样式，以后打开即用。` : '它没有设置页；导入后同样由 Wharf 管理服务和端口。'}</div>
          </div>
          {manage ? <Button size="sm" onClick={() => setImporting(true)}><Puzzle /> 导入到 Wharf</Button> : <span className="text-xs text-muted-foreground">需要「管理插件」权限才能导入</span>}
        </div>
      )}
      {imported && imp && imp.version !== p.version && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm">
          插件从 {imp.version} 升级到了 {p.version}，设置页可能有变化。
          {manage && <Button size="sm" variant="outline" className="ml-auto" onClick={() => setImporting(true)}><RefreshCw /> 重新导入</Button>}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-1 border-b">
        {[{ path: 'overview', title: '服务与端口' }, ...pages].map((g) => (
          <button key={g.path} type="button" onClick={() => { q.set('page', g.path); setQ(q, { replace: true }) }}
            className={cn('-mb-px border-b-2 px-3 py-2 text-sm', tab === g.path ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>{g.title}</button>
        ))}
        <span className="flex-1" />
        {imported && manage && (
          <span className="flex gap-1 pb-1">
            <Button variant="ghost" size="xs" onClick={() => setImporting(true)}><RefreshCw /> 重新导入</Button>
            <Button variant="ghost" size="xs" onClick={unimport}>取消导入</Button>
          </span>
        )}
      </div>
      {tab === 'overview' || !page ? <Overview p={p} manage={manage} onChanged={reload} />
        : <PageView key={page.path + (imp?.imported_at ?? 0)} pkg={p.pkg} page={page} manage={manage} />}
      {importing && <ImportDialog plugins={[p]} onClose={() => { setImporting(false); reload(); reloadImp() }} />}
      {dialog}
    </div>
  )
}

function Overview({ p, manage, onChanged }: { p: PluginItem; manage: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState('')
  const { confirm, dialog } = useConfirm()
  const svc = async (name: string, action: string) => {
    setBusy(name + action)
    try {
      await post('/plugins/service', { pkg: p.pkg, name, action })
      toast.success('完成'); onChanged()
    } catch (e) { toast.error((e as Error).message) } finally { setBusy('') }
  }
  const port = async (port: number, proto: string, open: boolean) => {
    if (open && !(await confirm(`向外网开放 ${port}/${proto}？`, '外网的任何人都能连到这个端口。确认这个服务有密码保护、且确实需要从外面访问。', { ok: '开放' }))) return
    try { await post('/plugins/port', { pkg: p.pkg, port, proto, open }); toast.success(open ? '已开放' : '已关闭外网访问'); onChanged() } catch (e) { toast.error((e as Error).message) }
  }
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {!!p.warnings?.length && (
        <div className="grid gap-1 rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-sm lg:col-span-2">
          {p.warnings.map((w) => <div key={w}>⚠️ {w}</div>)}
        </div>
      )}
      <Section title="后台服务" desc="插件在路由器上运行的程序。">
        <div className="divide-y">
          {(p.services ?? []).map((s) => (
            <div key={s.name} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-sm">
              <Dot tone={s.running ? 'ok' : 'off'} />
              <span className="font-mono">{s.name}</span>
              <span className="text-muted-foreground">{s.running ? '运行中' : '已停止'}</span>
              <span className="flex-1" />
              {manage && (
                <>
                  <label className="flex items-center gap-1.5 text-xs text-muted-foreground">开机启动<Switch size="sm" checked={s.enabled} disabled={!!busy} onCheckedChange={(c) => svc(s.name, c ? 'enable' : 'disable')} /></label>
                  {s.running
                    ? <><Button variant="ghost" size="sm" disabled={!!busy} onClick={() => svc(s.name, 'restart')}>{busy === s.name + 'restart' ? <Loader2 className="animate-spin" /> : <RefreshCw />} 重启</Button>
                      <Button variant="ghost" size="sm" disabled={!!busy} onClick={() => svc(s.name, 'stop')}><Square /> 停止</Button></>
                    : <Button variant="ghost" size="sm" disabled={!!busy} onClick={() => svc(s.name, 'start')}>{busy === s.name + 'start' ? <Loader2 className="animate-spin" /> : <Play />} 启动</Button>}
                </>
              )}
            </div>
          ))}
          {!p.services?.length && <Empty>这个插件没有自己的后台服务（可能只是界面，或由别的服务提供功能）</Empty>}
        </div>
        {manage && !!p.services?.length && <p className="border-t px-4 py-2 text-xs text-muted-foreground">有些插件还有自己的「启用」开关（在设置页里）；只启动服务而插件开关关着时，服务会马上自己退出。</p>}
      </Section>
      <Section title="占用的端口" desc="插件的程序正在监听的端口。只监听 127.0.0.1 的只有路由器自己能访问。">
        <div className="divide-y">
          {(p.ports ?? []).map((x) => (
            <div key={x.port + x.proto + x.bind} className="flex flex-wrap items-center gap-3 px-4 py-2 text-sm">
              <span className="w-24 font-mono">{x.port}/{x.proto}</span>
              <span className="font-mono text-xs text-muted-foreground">{x.bind}</span>
              <span className="text-xs text-muted-foreground">{x.proc}</span>
              <span className="flex-1" />
              {x.local ? <Pill><Lock className="size-3" />仅本机</Pill> : x.wan_open ? <Pill tone="amber"><Globe className="size-3" />外网可访问</Pill> : <Pill tone="blue">局域网可访问</Pill>}
              {manage && !x.local && x.proto === 'tcp' && (
                x.wan_open
                  ? (x.wan_rule?.startsWith('owpplug_') ? <Button variant="ghost" size="sm" onClick={() => port(x.port, x.proto, false)}>关闭外网访问</Button> : <span className="text-xs text-muted-foreground">由防火墙规则开放</span>)
                  : <Button variant="ghost" size="sm" onClick={() => port(x.port, x.proto, true)}>向外网开放</Button>
              )}
            </div>
          ))}
          {!p.ports?.length && <Empty>没有监听端口</Empty>}
        </div>
      </Section>
      <Section title="详细信息">
        <div className="grid gap-2 p-4 text-sm sm:grid-cols-2">
          <Info k="软件包">{p.pkg}</Info>
          <Info k="版本">{p.version}</Info>
          <Info k="安装时间">{p.installed_at ? datetime(p.installed_at) : '—'}</Info>
          <Info k="中文翻译">{p.i18n ? '已安装' : '没有（部分文字可能是英文）'}</Info>
          <Info k="配置文件">{p.configs?.map((c) => '/etc/config/' + c).join('、') || '—'}</Info>
          <Info k="依赖">{p.depends?.filter((d) => !d.startsWith('lib') && d !== 'luci-base' && d !== 'luci-compat').join('、') || '—'}</Info>
        </div>
      </Section>
      <Section title="进程" desc="属于这个插件的程序（含它启动的子程序）。">
        <div className="max-h-72 divide-y overflow-y-auto">
          {(p.procs ?? []).map((x) => (
            <div key={x.pid} className="flex items-center gap-3 px-4 py-1.5 text-sm">
              <span className="w-14 font-mono text-xs text-muted-foreground">{x.pid}</span><span className="font-mono">{x.name}</span>
              <span className="min-w-0 flex-1 truncate text-right font-mono text-xs text-muted-foreground" title={x.exe}>{x.exe}</span>
            </div>
          ))}
          {!p.procs?.length && <Empty>没有在运行的进程</Empty>}
        </div>
      </Section>
      {dialog}
    </div>
  )
}

function Info({ k, children }: { k: string; children: React.ReactNode }) {
  return <div className="min-w-0 rounded-lg bg-muted/40 px-3 py-2"><div className="text-xs text-muted-foreground">{k}</div><div className="break-all">{children}</div></div>
}

function PageView({ pkg, page, manage }: { pkg: string; page: ImportedPage; manage: boolean }) {
  const [blocks, setBlocks] = useState<FormBlock[] | null>(null)
  const [formKey, setFormKey] = useState(0)
  const [err, setErr] = useState('')
  const [syncing, setSyncing] = useState(false)
  const [saving, setSaving] = useState(false)
  const [gen, setGen] = useState(0)
  const dirty = useRef(false)
  const luci = luciBase() + page.path
  const stored = page.blocks

  // 1) the copy made at import time + current uci values: instant
  // 2) a quiet re-conversion for the live parts (status lines etc.); swapped in only while nothing is being edited
  useEffect(() => {
    let alive = true
    setErr('')
    if (page.status !== 'ok') { setErr(page.status === 'custom' ? 'custom' : page.error || '导入时没能转换'); return }
    if (stored?.length) withCurrentValues(stored).then((b) => { if (alive && !dirty.current) { setBlocks(b); setFormKey((k) => k + 1) } }, () => {})
    setSyncing(true)
    convertPage(pkg, { path: page.path, title: page.title, kind: page.kind, target: page.target, order: 0 }).then((r) => {
      if (!alive) return
      setSyncing(false)
      if (r.status !== 'ok' || !r.blocks) { if (!stored?.length) setErr(r.error || '没能转换'); return }
      if (!dirty.current) { setBlocks(r.blocks); setFormKey((k) => k + 1) }
      if (manage) storePage(pkg, r)
    })
    return () => { alive = false }
  }, [pkg, page.path, gen]) // eslint-disable-line react-hooks/exhaustive-deps

  const save = async (changes: UciChange[]) => {
    setSaving(true)
    try {
      await put('/plugins/save', { pkg, title: page.title, changes })
      toast.success('已保存并应用，插件会按自己的方式重新加载')
      dirty.current = false
      setGen((g) => g + 1)
    } catch (e) { toast.error((e as Error).message) } finally { setSaving(false) }
  }

  if (err) {
    const custom = err === 'custom'
    return (
      <div className="grid justify-items-start gap-3 rounded-xl border border-dashed p-6 text-sm">
        <div className="flex items-center gap-2 font-medium"><Package className="size-4" />{custom ? '这个页面是插件自己设计的界面' : '这个页面没能转换'}</div>
        <p className="text-muted-foreground">{custom ? '它不是标准的设置表单（比如仪表盘、日志、文件管理），Wharf 无法换成自己的样式。' : `原因：${err}。`}可以在 LuCI 里打开原来的页面。</p>
        <Button variant="outline" size="sm" render={<a href={luci} target="_blank" rel="noreferrer" />}><ExternalLink /> 在 LuCI 中打开</Button>
      </div>
    )
  }
  if (!blocks) return <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> 正在读取设置…</div>
  return (
    <div className="grid gap-3">
      {!manage && <p className="rounded-lg bg-muted/50 px-3 py-2 text-xs text-muted-foreground">你只有查看权限，密码类内容已隐藏。</p>}
      <PluginForm key={formKey} blocks={blocks} editable={manage} luciURL={luci} saving={saving} onSave={save} onDirty={(d) => { dirty.current = d }} />
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        {syncing && <Loader2 className="size-3 animate-spin" />}
        由 Wharf 从插件的 {page.kind === 'view' ? 'JavaScript 页面' : 'Lua 页面'}转换{syncing ? '，正在同步最新状态' : ''}。如果显示不对，<a className="text-primary hover:underline" href={luci} target="_blank" rel="noreferrer">在 LuCI 中打开</a>原页面。
      </p>
    </div>
  )
}
