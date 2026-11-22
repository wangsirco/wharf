import { useState } from 'react'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { post } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { datetime } from '@/lib/format'
import { Dot, Field, Pill, Section } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

interface NameStatus { name: string; resolves: string[]; points: boolean; ddns: number }
interface Names {
  local: string; port: string; names: NameStatus[]; via_443: boolean; via_port: boolean; front_ready: boolean; wan_ips: string[] | null
  token_set: boolean; account: boolean; cert_busy: boolean; cert_error: string; cert_expires?: number
  proxied: string[] | null; origin_error: string; origin_cert?: { names: string[]; expires: number; source: string }
}

// PanelNames: the panel's names — passkeys need one, and the public ones open the panel
// from outside (through the 443 front and / or the panel's own port).
export function PanelNames() {
  const { data, reload } = useApi<Names>('/panel/names?dns=1', 15000)
  const [f, setF] = useState<{ names: string; token: string; via_443: boolean; via_port: boolean; proxied: string[] } | null>(null)
  const [pem, setPem] = useState({ cert: '', key: '' })
  const [busy, setBusy] = useState(false)
  if (!data) return null
  const v = f ?? { names: data.names.map((n) => n.name).join('\n'), token: data.token_set ? '••••••••' : '', via_443: data.via_443, via_port: data.via_port, proxied: data.proxied ?? [] }
  const list = v.names.split(/[\s,，]+/).filter(Boolean)
  const url = (h: string, p?: string) => `https://${h}${p && p !== '443' ? ':' + p : ''}`
  const save = async () => {
    setBusy(true)
    try { await post('/panel/names', { ...v, names: list }); setF(null); toast.success(list.length ? '已保存，正在申请证书' : '已清除公网域名'); reload() }
    catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const origin = async (body: Record<string, unknown>, ok: string) => {
    setBusy(true)
    try { await post('/panel/origin', body); setPem({ cert: '', key: '' }); toast.success(ok); reload() } catch (e) { toast.error((e as Error).message) } finally { setBusy(false) }
  }
  const ddns = async (name: string) => {
    try { await post('/panel/names/ddns', { name }); toast.success(`已用 DDNS 维护 ${name}`); reload() } catch (e) { toast.error((e as Error).message) }
  }
  return (
    <Section title="面板域名（公网访问与 Passkey）" desc="Passkey 只能在域名上使用；公网域名还能让你在外面打开面板。公网访问仍受「面板访问控制」限制（目前按地区）。" className="xl:col-span-2">
      <div className="grid gap-5 p-4 lg:grid-cols-2">
        <div className="grid content-start gap-2">
          <div className="text-sm font-medium">本地域名</div>
          <a className="font-mono text-sm text-primary underline" href={url(data.local, data.port)}>{url(data.local, data.port)}</a>
          <p className="text-xs text-muted-foreground">家里的设备直接可用（路由器自己解析）。证书由面板签发：每台要用 Passkey 的设备先安装一次面板证书（登录页「证书」里有下载和各系统步骤）。</p>
          {data.names.length > 0 && (
            <div className="mt-3 grid gap-1.5">
              <div className="text-sm font-medium">公网域名状态</div>
              {data.names.map((n) => ({ ...n, resolves: n.resolves ?? [] })).map((n) => (
                <div key={n.name} className="rounded-lg border px-3 py-2 text-xs">
                  <div className="flex items-center gap-2"><Dot tone={n.points || ((data.proxied ?? []).includes(n.name) && n.resolves.length) ? 'ok' : n.resolves.length ? 'warn' : 'bad'} /><span className="font-mono text-sm">{n.name}</span>{(data.proxied ?? []).includes(n.name) && <Pill tone="amber">橙色云</Pill>}</div>
                  <div className="mt-0.5 text-muted-foreground">
                    {(data.proxied ?? []).includes(n.name) && n.resolves.length ? '走 Cloudflare 代理（公网解析到 Cloudflare，正常）；家里直接进面板' : n.points ? `解析正确（${n.resolves.join('、')}）` : n.resolves.length ? `解析到 ${n.resolves.join('、')}，不是家里的公网 IP（${(data.wan_ips ?? []).join('、') || '未知'}）；开了橙色云也会这样` : '公网还解析不到'}
                    {n.ddns ? ' · DDNS 维护中' : ''}
                  </div>
                  {!n.ddns && !n.points && !(data.proxied ?? []).includes(n.name) && (
                    data.account
                      ? <Button size="sm" variant="outline" className="mt-1.5 h-7" onClick={() => ddns(n.name)}>用 DDNS 维护（Cloudflare 账户）</Button>
                      : <div className="mt-1">在「Cloudflare」页连接账户后，可以一键让它跟随家里的 IP。</div>
                  )}
                  {data.via_443 && <div className="mt-1">外网地址：<a className="text-primary underline" href={url(n.name)}>{url(n.name)}</a>{data.via_port && <>　或　<a className="text-primary underline" href={url(n.name, data.port)}>{url(n.name, data.port)}</a></>}</div>}
                  {!data.via_443 && data.via_port && <div className="mt-1">外网地址：<a className="text-primary underline" href={url(n.name, data.port)}>{url(n.name, data.port)}</a></div>}
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="grid content-start gap-3">
          <div className="text-sm font-medium">公网域名（可选，可以多个）</div>
          <Field label="域名" hint="一行一个，例如 wharf.example.com。会一起申请一张 Let's Encrypt 证书（Cloudflare DNS 验证，不用开放端口），家里由路由器直接解析到面板。">
            <textarea className="min-h-20 rounded-md border bg-background px-3 py-2 font-mono text-sm" value={v.names} placeholder="wharf.example.com" onChange={(e) => setF({ ...v, names: e.target.value })} />
          </Field>
          {!data.account && (
            <Field label="Cloudflare API 令牌" hint="更方便的做法：在「Cloudflare」页连接账户，这里就可以留空">
              <Input type="password" autoComplete="off" value={v.token} onChange={(e) => setF({ ...v, token: e.target.value })} />
            </Field>
          )}
          {list.length > 0 && (
            <div className="grid gap-2 rounded-lg border p-3">
              <div className="text-xs font-medium text-muted-foreground">走 Cloudflare 代理（橙色云加速）</div>
              {list.map((n) => (
                <label key={n} className="flex items-center justify-between gap-3 text-sm">
                  <span className="font-mono">{n}</span>
                  <Switch checked={v.proxied.includes(n)} onCheckedChange={(c) => setF({ ...v, proxied: c ? [...v.proxied, n] : v.proxied.filter((x) => x !== n) })} />
                </label>
              ))}
              <p className="text-xs text-muted-foreground">打开后：面板把这条记录切到橙色云，并在 Cloudflare 建一条 Origin Rule，把回源端口改到 {data.port}；WAN 的 {data.port} 只对 Cloudflare 的 IP 开放。地址仍然是 https://域名。Cloudflare 来的连接优先用源服务器证书（没有时用 Let's Encrypt 证书），家里直接访问用 Let's Encrypt 证书。令牌需要额外勾选「Origin Rules → 编辑」（创建令牌页面无法预选，需要手动加）。</p>
            </div>
          )}
          <div className="grid gap-2 rounded-lg border p-3">
            <div className="text-xs font-medium text-muted-foreground">直连时从外网怎么进来（可以都开）</div>
            <label className="flex items-start justify-between gap-3">
              <span><span className="text-sm">通过 443，地址不带端口</span><span className="block text-xs text-muted-foreground">{data.front_ready ? '复用代理扩展的 443 分流器，按域名交给面板；1Panel 网站和代理节点不受影响。域名请保持「仅 DNS」（灰色云）。' : '需要先在「代理」页安装代理扩展（它的 443 分流器负责按域名分发）。'}</span></span>
              <Switch checked={v.via_443} disabled={!data.front_ready} onCheckedChange={(c) => setF({ ...v, via_443: !!c })} />
            </label>
            <label className="flex items-start justify-between gap-3">
              <span><span className="text-sm">开放面板端口 {data.port}</span><span className="block text-xs text-muted-foreground">在 WAN 上放行 {data.port}（和 LuCI 里「允许外网访问」是同一个开关），地址要带 :{data.port}。</span></span>
              <Switch checked={v.via_port} onCheckedChange={(c) => setF({ ...v, via_port: !!c })} />
            </label>
          </div>
          {data.names.length > 0 && (
            <div className="text-xs">
              {data.cert_busy ? <span className="text-muted-foreground">正在申请证书（通常 1–2 分钟）…</span>
                : data.cert_expires ? <span className="text-success">证书有效期至 {datetime(data.cert_expires).slice(0, 10)}</span>
                : data.cert_error ? <span className="text-destructive">证书申请失败：{data.cert_error}</span>
                : <span className="text-muted-foreground">还没有证书</span>}
            </div>
          )}
          {data.origin_error && <div className="text-xs text-destructive">Cloudflare：{data.origin_error}</div>}
          <div className="flex gap-2">
            <Button size="sm" disabled={busy} onClick={save}>{busy && <Loader2 className="animate-spin" />}保存</Button>
          </div>
          {(data.proxied ?? []).length > 0 && (
            <div className="grid gap-2 rounded-lg border p-3">
              <div className="text-xs font-medium text-muted-foreground">Cloudflare 源服务器证书（给 Cloudflare 连回家用）</div>
              {data.origin_cert ? (
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-success">{data.origin_cert.names.join('、')} · 有效期至 {datetime(data.origin_cert.expires).slice(0, 10)}{data.origin_cert.source === 'api' ? ' · 面板申请' : ' · 已上传'}</span>
                  <Button size="sm" variant="ghost" className="h-7" disabled={busy} onClick={() => origin({ remove: true }, '已删除源服务器证书')}>删除</Button>
                </div>
              ) : <div className="text-xs text-muted-foreground">还没有：现在给 Cloudflare 的是 Let's Encrypt 证书，「完全」和「完全（严格）」都能用。放一张源服务器证书（15 年）就不再依赖 Let's Encrypt 续期。</div>}
              <Button size="sm" variant="outline" className="w-fit" disabled={busy} onClick={() => origin({ create: true }, '已申请 15 年的源服务器证书')}>让面板向 Cloudflare 申请（15 年）</Button>
              <div className="text-xs text-muted-foreground">或者粘贴你网站正在用的那张（例如 *.example.com）：</div>
              <textarea className="min-h-16 rounded-md border bg-background px-2 py-1 font-mono text-[11px]" placeholder="-----BEGIN CERTIFICATE-----" value={pem.cert} onChange={(e) => setPem({ ...pem, cert: e.target.value })} />
              <textarea className="min-h-16 rounded-md border bg-background px-2 py-1 font-mono text-[11px]" placeholder="-----BEGIN PRIVATE KEY-----" value={pem.key} onChange={(e) => setPem({ ...pem, key: e.target.value })} />
              <Button size="sm" className="w-fit" disabled={busy || !pem.cert || !pem.key} onClick={() => origin(pem, '已保存源服务器证书')}>保存证书</Button>
            </div>
          )}
        </div>
      </div>
    </Section>
  )
}
