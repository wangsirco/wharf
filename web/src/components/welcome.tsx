import { useEffect, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import {
  Anchor, BellRing, Check, ChevronRight, Cloud, Earth, Home, LayoutGrid, Puzzle, Server, ShieldHalf, Sparkles, Users, Waypoints,
} from 'lucide-react'
import { post, put } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { refreshBrand, useBrand } from '@/lib/brand'
import { useMode } from '@/lib/mode'
import { cn } from '@/lib/utils'
import { Field } from '@/components/common'
import { BrandMark } from '@/components/brand-mark'
import { DepsPanel } from '@/components/deps'
import { LoginModeStep } from '@/components/login-mode'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'

// Welcome: a short visual tour shown after a user's first successful login.
// Every step can be skipped; it can be reopened from the user menu.
export function Welcome() {
  const { user, onboarded, setOnboarded, isSuper, refresh } = useAuth()
  const brand = useBrand()
  const { mode, setMode } = useMode()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [step, setStep] = useState(0)
  const [me, setMe] = useState('')
  const [panel, setPanel] = useState({ name: '', subtitle: '' })
  const [reach, setReach] = useState<Reach>('home')

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

  // the next useful things; the first follows the answer to "where do you open the panel from"
  const reachNext: Record<Reach, [typeof Cloud, string, string, string] | null> = {
    home: null,
    tunnel: [Waypoints, '用 Cloudflare 隧道从外面打开', '不开端口、不需要公网 IP：连上 Cloudflare，点「接到隧道上」', '/cloudflare?tab=tunnel'],
    public: [Earth, '给面板一个公网域名', '有公网 IP：域名 + 证书，橙色云或直连都行', '/settings#sec-' + encodeURIComponent('面板域名（公网访问与 Passkey）').replace(/%/g, '').slice(0, 40)],
  }
  const next = ([
    reachNext[reach],
    [BellRing, '设置告警推送', 'Telegram / Server 酱：断网、新设备、异常流量第一时间知道', '/alerts'],
    [Puzzle, '把 OpenWrt 插件导入 Wharf', '一次转换所有设置页，之后用 Wharf 的样式管理', '/plugins'],
    [Waypoints, '动态域名 DDNS', '家里 IP 变了，域名自动跟着走', '/ddns'],
    [Anchor, '连接 Berth 服务器面板', '家里有服务器？配对后建站自动开端口、封禁互相同步', '/berth'],
    [Users, '给家人或朋友开个账号', '只给他们需要的功能，所有改动都有记录', '/users'],
    [ShieldHalf, '限制谁能从公网打开面板', '按地区、IP 放行，默认只允许你所在的地区', '/access'],
  ] as const).filter(Boolean) as [typeof Cloud, string, string, string][]

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
    { title: '以后怎么登录？', body: <LoginModeStep /> },
    ...(isSuper ? [{ title: '从哪里打开面板？', body: <ReachStep value={reach} onChange={setReach} /> }] : []),
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
          <p className="text-sm text-muted-foreground">点一项直接过去，也可以点「开始使用」先看看概览。</p>
          <div className="overflow-hidden rounded-xl border">
            {next.map(([Icon, t, d, to]) => (
              <button key={to + t} type="button" onClick={() => go(to)} className="flex w-full items-center gap-3 border-b px-3 py-2.5 text-left last:border-b-0 hover:bg-muted/50">
                <Icon className="size-4 shrink-0 text-primary" />
                <span className="min-w-0 flex-1"><span className="block text-sm font-medium">{t}</span><span className="block text-xs text-muted-foreground">{d}</span></span>
                <ChevronRight className="size-4 shrink-0 text-muted-foreground" />
              </button>
            ))}
          </div>
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

type Reach = 'home' | 'tunnel' | 'public'

// Where the panel is opened from: decides what the wizard suggests next.
function ReachStep({ value, onChange }: { value: Reach; onChange: (r: Reach) => void }) {
  const opts: [Reach, typeof Home, string, string][] = [
    ['home', Home, '只在家里用', '在家里用 wharf.lan 或路由器 IP 打开就够了。以后想从外面打开，随时可以设。'],
    ['tunnel', Waypoints, '外面也要用（没有公网 IP / 不想开端口）', '用 Cloudflare 隧道：不开任何端口，不暴露家里 IP，免费。需要一个托管在 Cloudflare 的域名。'],
    ['public', Earth, '外面也要用（家里有公网 IP）', '给面板一个公网域名，自动申请证书；可以开 Cloudflare 橙色云隐藏家里 IP，或者直连最快。'],
  ]
  return (
    <div className="grid gap-2">
      {opts.map(([k, Icon, t, d]) => (
        <button key={k} type="button" onClick={() => onChange(k)}
          className={cn('flex items-start gap-3 rounded-xl border p-3 text-left transition-colors hover:border-primary/50', value === k && 'border-primary bg-accent/50 ring-2 ring-primary/20')}>
          <Icon className="mt-0.5 size-4 shrink-0 text-primary" />
          <span className="min-w-0 flex-1"><span className="block text-sm font-medium">{t}</span><span className="block text-xs text-muted-foreground">{d}</span></span>
          {value === k && <Check className="size-4 shrink-0 text-primary" />}
        </button>
      ))}
      <p className="text-xs text-muted-foreground">不知道家里是不是公网 IP？「网络接口」页的「公网检测」会告诉你。不管选哪种，从外面打开时都受「面板访问控制」保护。</p>
    </div>
  )
}
