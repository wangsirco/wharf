import type { ReactNode } from 'react'
import { toast } from 'sonner'
import {
  ArchiveRestore, ArrowRight, Ban, BellRing, Boxes, Download, ExternalLink, Globe, KeyRound, LayoutDashboard, Server, ShieldCheck, Waypoints,
} from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { openBerth, useBerth } from '@/lib/berth'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/layout'
import { Pill } from '@/components/common'
import { BerthCard } from '@/components/berth-card'
import { BerthDiscovery, PairAddresses } from '@/components/berth-pair'
import { CopyText } from '@/pages/diag'
import { Button } from '@/components/ui/button'

const REPO = 'https://github.com/wangsirco/berth'
const INSTALL = 'curl -fsSL https://raw.githubusercontent.com/wangsirco/berth/main/scripts/install.sh | sudo sh'

function GitHubMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={className} fill="currentColor" aria-hidden>
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  )
}

// Berth (泊位), the server panel of the same series. Paired: open it and manage the link.
// Not yet: what it is, where to get it, and pairing step by step.
export default function BerthPage() {
  const berth = useBerth()
  const { isSuper } = useAuth()
  const open = () => openBerth().catch((e) => toast.error((e as Error).message))

  if (berth.paired) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Berth 泊位" desc="同一系列的服务器管理面板：Wharf 管路由器，Berth 管服务器。" />
        <div className="flex flex-wrap items-center gap-3 rounded-2xl border bg-card px-4 py-3">
          <img src="/berth/mark.svg" alt="" className="size-9" />
          <div className="min-w-0 flex-1">
            <div className="font-semibold">已和 Berth「{berth.name}」配对</div>
            <div className="truncate font-mono text-xs text-muted-foreground">{berth.url}</div>
          </div>
          {berth.state === 'active'
            ? <Button onClick={open}><ExternalLink /> 打开 Berth</Button>
            : <Pill tone="amber">对接已失效</Pill>}
          <Button variant="ghost" render={<a href={REPO} target="_blank" rel="noreferrer" />}><GitHubMark className="size-4" /> GitHub</Button>
        </div>
        {isSuper && <BerthCard />}
      </div>
    )
  }
  return <Intro />
}

const FEATURES = [
  [Globe, '网站与证书', '反向代理、PHP、静态站和原生项目，自动 HTTPS；建站时顺手检查域名解析。'],
  [Boxes, '容器与应用商店', 'Docker / Compose、几十个常用应用一键安装，装好直接建站。'],
  [Server, '虚拟机与数据库', '系统容器和完整虚拟机、MySQL / PostgreSQL / Redis，都在同一个面板。'],
  [ArchiveRestore, '备份与还原', '加密增量备份到本地、S3、网盘，每月自动演练恢复，还能整机迁移。'],
] as const

const TOGETHER = [
  [Waypoints, '建站自动开端口', 'Berth 建站时自动在路由器上加端口映射或登记 443 分流，删站自动撤销。'],
  [Ban, '封禁互相同步', '任一边封掉的攻击 IP，另一边也拦。'],
  [BellRing, '告警只收一份', '同一件事不会两边各发一次通知。'],
  [Download, 'DDNS 不打架', '同一个域名只由一方更新，冲突会提醒你选。'],
  [KeyRound, '互相跳转免登录', '从一边点一下就进另一边，不用再输密码。'],
  [LayoutDashboard, '路由器视角', '在 Berth 里看到服务器在路由器上的流量和端口。'],
] as const

function Intro() {
  const { isSuper } = useAuth()
  const { data: info } = useApi<{ self_fp: string }>(isSuper ? '/berth' : null)
  return (
    <div className="mx-auto grid max-w-5xl gap-6 pb-12">
      {/* what it is */}
      <section className="overflow-hidden rounded-2xl border bg-card">
        <div className="grid gap-6 p-6 md:grid-cols-[1.1fr_1fr] md:p-8">
          <div className="flex flex-col justify-center">
            <div className="flex items-center gap-3">
              <img src="/berth/mark.svg" alt="" className="size-12" />
              <div>
                <div className="text-2xl font-bold leading-tight">Berth <span className="font-semibold text-muted-foreground">泊位</span></div>
                <Pill tone="blue">Wharf 的姊妹产品</Pill>
              </div>
            </div>
            <p className="mt-4 text-base font-semibold leading-snug">一个让你几乎不用再开 SSH 的 Linux 服务器面板。</p>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
              网站、项目、容器、虚拟机、数据库、备份和多用户协作，一处管完；每次改动先预览、可审计、多数能撤销。和 Wharf 一样免费开源，不用注册账号、不收集数据。
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              <Button render={<a href={REPO} target="_blank" rel="noreferrer" />}><GitHubMark className="size-4" /> 在 GitHub 上看看</Button>
              <Button variant="outline" render={<a href={REPO + '/releases/latest'} target="_blank" rel="noreferrer" />}><Download /> 下载最新版本</Button>
              <Button variant="ghost" render={<a href="#pair" />}>已经装了？去配对 <ArrowRight /></Button>
            </div>
            <p className="mt-3 font-mono text-xs text-muted-foreground">github.com/wangsirco/berth</p>
          </div>
          <img src="/berth/store.jpg" alt="Berth 的应用商店页面" className="w-full rounded-xl border shadow-sm" loading="lazy" />
        </div>
      </section>

      {/* highlights */}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {FEATURES.map(([Icon, t, d]) => (
          <div key={t} className="rounded-xl border bg-card p-4">
            <Icon className="size-5 text-primary" />
            <div className="mt-2 text-sm font-semibold">{t}</div>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{d}</p>
          </div>
        ))}
      </section>

      {/* with Wharf */}
      <section className="rounded-xl border bg-card">
        <div className="border-b px-4 py-3 text-sm font-semibold">家里有服务器？和 Wharf 配对后</div>
        <div className="grid gap-x-6 gap-y-3 px-4 py-4 sm:grid-cols-2">
          {TOGETHER.map(([Icon, t, d]) => (
            <div key={t} className="flex gap-2.5">
              <Icon className="mt-0.5 size-4 shrink-0 text-primary" />
              <div><div className="text-sm font-medium">{t}</div><div className="text-xs text-muted-foreground">{d}</div></div>
            </div>
          ))}
        </div>
      </section>

      {/* pairing */}
      <section id="pair" className="grid scroll-mt-20 gap-3">
        <h2 className="text-base font-semibold">三步把 Berth 和 Wharf 连起来</h2>
        <Step n={1} title="在服务器上安装 Berth">
          <p className="text-xs text-muted-foreground">在服务器上用 root 运行（全自动：装依赖、校验安装包、启动服务，最后打印初始化链接）：</p>
          <div className="mt-2"><CopyText text={INSTALL} /></div>
          <p className="mt-2 text-xs text-muted-foreground">目前支持 ARM64（Apple M 系列 Mac、树莓派、ARM 云服务器），x86 版本在开发中。系统：Fedora、Debian、Ubuntu、Rocky / Alma，内存 1 GB 以上。</p>
        </Step>
        <Step n={2} title="在 Berth 里找到这台路由器">
          {isSuper ? <>
            <BerthDiscovery />
            <p className="mb-2 mt-3 text-xs text-muted-foreground">或者手动：打开 Berth 左侧的「Wharf」，点「配对」，填其中一个地址：</p>
            <PairAddresses selfFP={info?.self_fp} />
          </> : <p className="text-xs text-muted-foreground">需要超级管理员来操作。</p>}
        </Step>
        <Step n={3} title="在这里允许" last>
          <p className="text-xs text-muted-foreground">用内网发现时，申请会出现在上面，核对两边的校验码后点「允许」，Berth 自动完成配对。手动填地址时，Berth 会把你带回 Wharf 的授权页，勾选后同意即可。之后这一页会变成 Berth 的入口。</p>
        </Step>
      </section>
      <p className="flex items-center justify-center gap-1.5 text-xs text-muted-foreground"><ShieldCheck className="size-3.5" />配对后每一次调用都签名校验，所有改动记入审计，可以随时解除。</p>
    </div>
  )
}

function Step({ n, title, children, last }: { n: number; title: string; children: ReactNode; last?: boolean }) {
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <span className="grid size-7 shrink-0 place-items-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">{n}</span>
        {!last && <span className="mt-1 w-px flex-1 bg-border" />}
      </div>
      <div className={cn('min-w-0 flex-1 rounded-xl border bg-card px-4 py-3', !last && 'mb-1')}>
        <div className="mb-1 text-sm font-semibold">{title}</div>
        {children}
      </div>
    </div>
  )
}
