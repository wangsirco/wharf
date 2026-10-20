import { useEffect, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import {
  Anchor, ArrowLeftRight, Ban, BarChart3, BellRing, Check, Cpu, Earth, KeyRound, LayoutGrid, Monitor, Server, ShieldHalf, Sparkles, Users,
} from 'lucide-react'
import { post, put } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { refreshBrand, useBrand } from '@/lib/brand'
import { useMode } from '@/lib/mode'
import { cn } from '@/lib/utils'
import { Field } from '@/components/common'
import { BrandMark } from '@/components/brand-mark'
import { DepsPanel } from '@/components/deps'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'

// Welcome: a short visual tour shown after a user's first successful login.
// Every step can be skipped; it can be reopened from the user menu.
export function Welcome() {
  const { user, onboarded, setOnboarded, isSuper, can, refresh } = useAuth()
  const brand = useBrand()
  const { mode, setMode } = useMode()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [step, setStep] = useState(0)
  const [me, setMe] = useState('')
  const [panel, setPanel] = useState({ name: '', subtitle: '' })

  useEffect(() => { if (user && !onboarded) setOpen(true) }, [user, onboarded])
  useEffect(() => {
    const reopen = () => { setStep(0); setOpen(true) }
    window.addEventListener('owp:welcome', reopen)
    return () => window.removeEventListener('owp:welcome', reopen)
  }, [])
  useEffect(() => {
    if (open) { setMe(user?.display_name ?? ''); setPanel({ name: brand.name, subtitle: brand.subtitle }) }
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!user) return null

  const finish = async () => {
    setOpen(false)
    setOnboarded(true)
    await post('/me/onboarded').catch(() => {})
  }
  const saveNames = async () => {
    try {
      if (me.trim() && me.trim() !== user.display_name) { await put('/me/profile', { display_name: me.trim() }); refresh() }
      if (isSuper && (panel.name.trim() !== brand.name || panel.subtitle.trim() !== brand.subtitle) && panel.name.trim()) {
        await put('/settings', { 'ui.name': panel.name.trim(), 'ui.subtitle': panel.subtitle.trim() })
        refreshBrand()
      }
      setStep((s) => s + 1)
    } catch (e) { toast.error((e as Error).message) }
  }
  const go = (to: string) => { finish(); navigate(to) }

  const features = ([
    [Monitor, '设备', '谁在线、叫什么、在用多少网速；离开和回家都有记录', 'devices.view'],
    [BarChart3, '流量与画像', '每台设备访问了什么：视频、AI、游戏……一目了然', 'traffic.view'],
    [Earth, '全球流量', '流量飞向了哪些国家，像大屏一样实时看', 'traffic.view'],
    [ArrowLeftRight, '端口转发', '按地区 / IP 限制来源，端口段可分配给不同的人', 'forwards.view'],
    [Ban, '设备管控', '一键断网、定时断网、黑白名单', 'access.manage'],
    [Cpu, '系统维护', '插件开关、日志、重启、备份', 'system.view'],
    [Users, '多管理员', '权限、配额、审批，所有改动都能追溯和还原', 'super'],
  ] as const).filter(([, , , p]) => (p === 'super' ? isSuper : can(p)))

  const steps: { title: string; body: ReactNode; next?: () => void }[] = [
    {
      title: `欢迎使用 ${brand.name}`,
      body: (
        <div className="grid gap-4">
          <p className="text-sm text-muted-foreground">一个给全家人、多位管理员一起用的 OpenWrt 控制面板。不用懂 iptables，也能看清家里的网络。</p>
          <div className="grid gap-2.5 sm:grid-cols-3">
            {[[Sparkles, '看得懂', '设备、流量、去向都用人话和图表说'], [ShieldHalf, '管得住', '谁能改什么、改了什么，都有记录'], [Anchor, '靠得住', '只用 OpenWrt 原生机制，不改内核、不断网']].map(([I, t, d]) => {
              const Icon = I as typeof Sparkles
              return (
                <div key={t as string} className="rounded-xl border bg-muted/30 p-3">
                  <Icon className="mb-2 size-5 text-primary" />
                  <div className="text-sm font-medium">{t as string}</div>
                  <div className="text-xs text-muted-foreground">{d as string}</div>
                </div>
              )
            })}
          </div>
        </div>
      ),
    },
    {
      title: '怎么称呼你？',
      body: (
        <div className="grid gap-4">
          <Field label="你的称呼" hint="显示在右上角和操作记录里，随时可以再改">
            <Input autoFocus value={me} maxLength={64} onChange={(e) => setMe(e.target.value)} placeholder={user.username} />
          </Field>
          {isSuper && (
            <div className="grid gap-3 rounded-xl border bg-muted/30 p-3">
              <div className="text-sm font-medium">给面板起个名字</div>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="名称" hint="登录页、侧栏、浏览器标签都会显示"><Input maxLength={24} value={panel.name} placeholder="Wharf" onChange={(e) => setPanel({ ...panel, name: e.target.value })} /></Field>
                <Field label="副标题" hint="可留空"><Input maxLength={40} value={panel.subtitle} placeholder="OpenWrt 控制面板" onChange={(e) => setPanel({ ...panel, subtitle: e.target.value })} /></Field>
              </div>
            </div>
          )}
        </div>
      ),
      next: saveNames,
    },
    {
      title: '你可以用它做什么',
      body: (
        <div className="grid gap-2 sm:grid-cols-2">
          {features.map(([Icon, t, d]) => (
            <div key={t} className="flex items-start gap-3 rounded-xl border p-3">
              <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-accent text-accent-foreground"><Icon className="size-4" /></span>
              <span><span className="block text-sm font-medium">{t}</span><span className="text-xs text-muted-foreground">{d}</span></span>
            </div>
          ))}
        </div>
      ),
    },
    {
      title: '选一个你喜欢的样子',
      body: (
        <div className="grid gap-3 sm:grid-cols-2">
          {([['simple', '简要模式', '给家人看：网速、谁在用、在看什么。没有任何开关，不会误操作。', LayoutGrid], ['pro', '专业模式', '给折腾的人：完整的流量、转发、管控、审计和系统维护。', Server]] as const).map(([m, t, d, Icon]) => (
            <button key={m} type="button" onClick={() => setMode(m)}
              className={cn('grid gap-2 rounded-xl border p-4 text-left transition-colors hover:border-primary/50', mode === m && 'border-primary bg-accent/50 ring-2 ring-primary/20')}>
              <div className="flex items-center gap-2"><Icon className="size-4 text-primary" /><span className="text-sm font-medium">{t}</span>{mode === m && <Check className="ml-auto size-4 text-primary" />}</div>
              {/* tiny mock of the layout */}
              <div className="grid h-20 gap-1 rounded-lg bg-muted/60 p-1.5" style={{ gridTemplateColumns: m === 'pro' ? '1fr 3fr' : '1fr' }}>
                {m === 'pro' && <div className="rounded bg-background/80" />}
                <div className="grid grid-cols-3 gap-1">{Array.from({ length: m === 'pro' ? 6 : 3 }).map((_, i) => <div key={i} className="rounded bg-background/80" />)}</div>
              </div>
              <span className="text-xs text-muted-foreground">{d}</span>
            </button>
          ))}
          <p className="text-xs text-muted-foreground sm:col-span-2">右上角随时可以切换。</p>
        </div>
      ),
    },
    ...(isSuper ? [{
      title: '检查依赖组件',
      body: (
        <div className="grid gap-3">
          <p className="text-sm text-muted-foreground">部分功能要用到路由器上的官方软件包（例如抓包需要 tcpdump）。缺少的可以现在一键装上，也可以以后在「系统维护 → 依赖组件」里装。</p>
          <DepsPanel compact />
        </div>
      ),
    }] : []),
    {
      title: '准备好了',
      body: isSuper ? (
        <div className="grid gap-2">
          <p className="text-sm text-muted-foreground">作为超级管理员，建议先做这几件事：</p>
          {([[KeyRound, '修改初始密码', '/account'], [BellRing, '设置告警推送（Telegram / Server 酱）', '/alerts'], [ShieldHalf, '限制谁能从公网打开面板', '/access'], [Users, '给家人或朋友开个账号', '/users']] as const).map(([Icon, t, to]) => (
            <button key={to} type="button" onClick={() => go(to)} className="flex items-center gap-3 rounded-lg border px-3 py-2 text-left text-sm hover:bg-muted/50">
              <Icon className="size-4 text-primary" />{t}<span className="ml-auto text-xs text-muted-foreground">去设置 →</span>
            </button>
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">你能使用的功能都在左侧菜单里。看不到的功能，可以找超级管理员开通。按 ⌘K / Ctrl+K 可以随时搜索设备和页面。</p>
      ),
    },
  ]
  const cur = steps[step]
  const last = step === steps.length - 1

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) finish() }}>
      <DialogContent className="gap-0 overflow-hidden p-0 sm:max-w-xl" showCloseButton={false}>
        <div className="flex items-center gap-3 bg-gradient-to-br from-[#3b8bf6] to-[#1d5fe0] px-6 py-5 text-white">
          <span className="grid size-10 place-items-center rounded-xl bg-white/15"><BrandMark className="size-6" /></span>
          <div className="min-w-0">
            <DialogTitle className="text-base font-semibold text-white">{cur.title}</DialogTitle>
            <div className="text-xs text-white/70">第 {step + 1} / {steps.length} 步</div>
          </div>
        </div>
        <div className="max-h-[60svh] overflow-y-auto px-6 py-5">{cur.body}</div>
        <div className="flex items-center gap-2 border-t px-6 py-3">
          <div className="flex gap-1.5">
            {steps.map((_, i) => <span key={i} className={cn('h-1.5 rounded-full transition-all', i === step ? 'w-5 bg-primary' : 'w-1.5 bg-muted-foreground/30')} />)}
          </div>
          <Button variant="ghost" size="sm" className="ml-auto text-muted-foreground" onClick={finish}>跳过向导</Button>
          {step > 0 && <Button variant="outline" size="sm" onClick={() => setStep(step - 1)}>上一步</Button>}
          <Button size="sm" onClick={() => (last ? finish() : cur.next ? cur.next() : setStep(step + 1))}>{last ? '开始使用' : '下一步'}</Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
