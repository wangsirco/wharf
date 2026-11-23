import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { Anchor, Check, Loader2, ShieldCheck } from 'lucide-react'
import { get, post } from '@/lib/api'
import { PageHeader } from '@/components/layout'
import { ErrorBox, Field, Pill, Section } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { cn } from '@/lib/utils'

interface Scope { key: string; label: string; desc: string }
interface Cand { ip: string; mac?: string; name?: string; online: boolean; matched: boolean }
interface Preview { berth_url: string; berth_urls: string[]; berth_fp: string; mode: 'lan' | 'public'; names: { lan: string; public: string }; scopes: Scope[]; devices: Cand[]; resolved: string[]; paired: boolean; paired_name: string }

// /pair/berth?berth_url=&berth_fp=&code=&cb= — Berth sends the super admin here to agree.
export default function PairBerth() {
  const [q] = useSearchParams()
  const navigate = useNavigate()
  const [p, setP] = useState<Preview | null>(null)
  const [err, setErr] = useState('')
  const [scopes, setScopes] = useState<string[]>([])
  const [days, setDays] = useState(0)
  const [hosts, setHosts] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [mode, setMode] = useState<'lan' | 'public'>('lan')
  const qs = new URLSearchParams({ berth_url: q.get('berth_url') ?? '', berth_urls: q.get('berth_urls') ?? '', berth_fp: q.get('berth_fp') ?? '', cb: q.get('cb') ?? '', mode: q.get('mode') ?? '' })

  useEffect(() => {
    get<Preview>('/berth/pair/preview?' + qs.toString())
      .then((r) => { setP(r); setMode(r.mode === 'public' && r.names.public ? 'public' : 'lan'); setScopes(r.scopes.map((s) => s.key)); setHosts(r.devices.filter((d) => d.matched).map((d) => d.ip)) })
      .catch((e) => setErr((e as Error).message))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const approve = async () => {
    if (!p) return
    setBusy(true)
    try {
      const targets = p.devices.filter((d) => hosts.includes(d.ip)).map(({ ip, mac, name }) => ({ ip, mac, name }))
      const r = await post<{ redirect: string }>('/berth/pair/approve', {
        berth_url: p.berth_url, berth_urls: p.berth_urls, berth_fp: p.berth_fp, mode, code: q.get('code') ?? '', cb: q.get('cb') ?? '', scopes, expires_days: days, targets,
      })
      window.location.href = r.redirect
    } catch (e) { toast.error((e as Error).message); setBusy(false) }
  }
  const toggle = (list: string[], set: (v: string[]) => void, k: string, on: boolean) => set(on ? [...list, k] : list.filter((x) => x !== k))

  return (
    <div className="mx-auto grid max-w-3xl gap-4">
      <PageHeader title="与 Berth 配对" desc="Berth 是同一系列的服务器管理面板。配对后，两边可以互相调用：映射端口、协调 DDNS、同步封禁、免登录跳转。所有经它做的改动都会记入审计。" />
      {err && <ErrorBox>{err}</ErrorBox>}
      {p && p.paired && <ErrorBox>Wharf 已经和 Berth「{p.paired_name}」配对。要换一个 Berth，请先在「Berth 服务器面板」页解除配对。</ErrorBox>}
      {p && !p.paired && (
        <>
          <Section title="Berth 和路由器在同一个局域网吗？" desc="决定两边用哪对名字互相访问。以后可以在「Berth 服务器面板」页切换，不用重新配对。">
            <div className="grid gap-2 p-4 sm:grid-cols-2">
              {([['lan', '是，内网互联', '两边都用内网名字，例如 ' + (p.names.lan || 'https://wharf.lan') + ' ⇄ https://mini.lan。最快，不经过外网。', !!p.names.lan],
                ['public', '不是，公网互联', p.names.public ? '两边都用公网名字（Wharf：' + p.names.public + '），按公网证书校验。' : 'Wharf 还没有公网名字：先在「外网访问」里设置一个。', !!p.names.public]] as const).map(([k, t, d, ok]) => (
                <button key={k} type="button" disabled={!ok} onClick={() => setMode(k)}
                  className={cn('grid gap-1 rounded-xl border p-3 text-left disabled:opacity-50', mode === k && 'border-primary bg-accent/40 ring-2 ring-primary/20')}>
                  <span className="text-sm font-medium">{t}</span><span className="text-xs text-muted-foreground">{d}</span>
                </button>
              ))}
            </div>
          </Section>

          <Section title="谁在请求配对">
            <div className="grid gap-3 p-4 text-sm">
              <div className="flex items-center gap-3 rounded-xl border bg-muted/30 p-3">
                <span className="grid size-9 place-items-center rounded-lg bg-accent text-accent-foreground"><Anchor className="size-4" /></span>
                <div className="min-w-0">
                  <div className="font-medium">{p.berth_url}</div>
                  <div className="truncate font-mono text-xs text-muted-foreground" title={p.berth_fp}>证书指纹 SHA-256 {p.berth_fp.match(/.{1,4}/g)?.join(' ')}</div>
                </div>
              </div>
              {p.berth_urls.length > 1 && <p className="text-xs text-muted-foreground">Wharf 回连 Berth 的地址（内网优先，连不上自动换下一个）：<span className="font-mono">{p.berth_urls.join(' · ')}</span></p>}
              <p className="text-xs text-muted-foreground">请和 Berth 配对页上显示的指纹核对。Wharf 直连 Berth 时校验这个指纹；经公网域名访问时，按域名校验公网证书。</p>
            </div>
          </Section>

          <Section title="授予哪些权限" desc="默认全部授予，可以取消。配对之后只能收窄，要增加需要重新配对。">
            <div className="grid gap-2 p-4 sm:grid-cols-2">
              {p.scopes.map((s) => (
                <label key={s.key} className={cn('flex cursor-pointer items-start gap-3 rounded-xl border p-3', scopes.includes(s.key) && 'border-primary/50 bg-accent/40')}>
                  <Checkbox className="mt-0.5" checked={scopes.includes(s.key)} onCheckedChange={(c) => toggle(scopes, setScopes, s.key, !!c)} />
                  <span><span className="block text-sm font-medium">{s.label}</span><span className="text-xs text-muted-foreground">{s.desc}</span></span>
                </label>
              ))}
            </div>
          </Section>

          <Section title="Berth 主机" desc="Berth 只能把端口映射、443 分流指向这里选中的设备；流量也只能读这些设备的。已按 Berth 地址自动匹配，可以改。">
            {p.devices.length === 0 && <p className="p-4 text-sm text-muted-foreground">读不到设备列表。</p>}
            <div className="grid max-h-80 gap-1.5 overflow-y-auto p-4">
              {p.devices.map((d) => (
                <label key={d.ip} className={cn('flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 text-sm', hosts.includes(d.ip) && 'border-primary/50 bg-accent/40')}>
                  <Checkbox checked={hosts.includes(d.ip)} onCheckedChange={(c) => toggle(hosts, setHosts, d.ip, !!c)} />
                  <span className="min-w-0 flex-1 truncate">{d.name || d.ip}</span>
                  <span className="font-mono text-xs text-muted-foreground">{d.ip}</span>
                  {d.matched && <Pill tone="blue">Berth 地址</Pill>}
                  {!d.online && <Pill>离线</Pill>}
                </label>
              ))}
            </div>
          </Section>

          <Section title="有效期">
            <Field className="p-4" label="对接令牌有效期" hint="到期后已建好的映射保留，两边都会提示「对接已失效」">
              <select className="h-9 w-48 rounded-md border bg-background px-2 text-sm" value={days} onChange={(e) => setDays(Number(e.target.value))}>
                <option value={0}>永久</option><option value={30}>30 天</option><option value={90}>90 天</option><option value={365}>365 天</option>
              </select>
            </Field>
          </Section>

          <div className="flex items-center justify-end gap-2">
            <Button variant="outline" onClick={() => navigate('/')}>不配对</Button>
            <Button disabled={busy || scopes.length === 0} onClick={approve}>{busy ? <Loader2 className="animate-spin" /> : <ShieldCheck />} 同意配对</Button>
          </div>
          <p className="flex items-center justify-end gap-1 text-xs text-muted-foreground"><Check className="size-3" />同意后会回到 Berth，由它完成剩下的步骤。</p>
        </>
      )}
    </div>
  )
}
