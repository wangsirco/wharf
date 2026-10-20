import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Info, Plus, X } from 'lucide-react'
import { ApiError, get, put } from '@/lib/api'
import { useApi } from '@/lib/hooks'
import { browserTZ } from '@/lib/beacon'
import type { ForwardTarget } from '@/lib/types'
import { PageHeader } from '@/components/layout'
import { Field, Section, useConfirm } from '@/components/common'
import { DevicePicker, IPListInput, RegionPicker } from '@/components/pickers'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

type Settings = Record<string, string>
interface Me { ip: string; country: string; region: string; as_org: string; tz: string; mac: string; local: boolean }

const KEYS = ['access.lan.mode', 'access.lan.macs', 'access.wan.mode', 'access.wan.regions', 'access.wan.timezones', 'access.allow_ips', 'access.deny_ips', 'access.ipsb']
const arr = (s: string | undefined): string[] => { try { return JSON.parse(s || '[]') } catch { return [] } }

export default function Access() {
  const [s, setS] = useState<Settings | null>(null)
  const [d, setD] = useState<Settings>({})
  const { data: me } = useApi<Me>('/access/me')
  const { data: devices } = useApi<ForwardTarget[]>('/forwards/targets')
  const [tzInput, setTzInput] = useState('')
  const [rev, setRev] = useState(0) // remount list inputs after load
  const { confirm, dialog } = useConfirm()

  useEffect(() => { get<Settings>('/settings').then((r) => { setS(r); setD(r); setRev((x) => x + 1) }) }, [])
  if (!s) return <PageHeader title="面板访问控制" />

  const setArr = (k: string, v: string[]) => setD({ ...d, [k]: JSON.stringify(v) })
  const dirty = KEYS.filter((k) => d[k] !== s[k])
  const tzs = arr(d['access.wan.timezones'])

  const save = async (force = false) => {
    try {
      const body: Settings = Object.fromEntries(dirty.map((k) => [k, d[k]]))
      if (force) body._force = '1'
      const r = await put<Settings>('/settings', body)
      setS(r); setD(r)
      toast.success('访问控制已保存')
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.data.lockout) {
        if (await confirm('会把你自己挡在外面', <>{e.message}<br />如果仍要保存，之后只能在 OpenWrt 后台的插件页点击「重置面板访问控制」恢复。</>, { danger: true, ok: '仍然保存' })) return save(true)
        return
      }
      toast.error((e as Error).message)
    }
  }

  return (
    <>
      <PageHeader title="面板访问控制" desc="决定谁能打开这个面板。被拒绝的访问会看到「拒绝访问」页面，并记入访问记录。">
        <Button size="sm" disabled={!dirty.length} onClick={() => save()}>保存{dirty.length ? `（${dirty.length}）` : ''}</Button>
      </PageHeader>

      {me && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border bg-accent/50 px-4 py-3 text-sm">
          <Info className="mt-0.5 size-4 shrink-0 text-primary" />
          <div>
            你当前的访问：<span className="font-mono">{me.ip}</span>
            {me.mac && <> · 设备 <span className="font-mono">{me.mac}</span></>}
            {me.country && <> · {me.region || me.country}</>}
            {me.as_org && <> · {me.as_org}</>}
            <div className="text-xs text-muted-foreground">保存时会检查新规则是否会挡住你自己。万一被挡，可在 OpenWrt 后台「服务 → Wharf 码头」点击「重置面板访问控制」。</div>
          </div>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Section title="内网设备" desc={me?.local === false ? '面板未与路由器部署在同一内网，此项不生效' : '按设备 MAC 识别（IP 变化不影响）'}>
          <div className="grid gap-4 p-4">
            <Tabs value={d['access.lan.mode']} onValueChange={(v) => setD({ ...d, 'access.lan.mode': String(v) })}>
              <TabsList>
                <TabsTrigger value="all">全部允许</TabsTrigger>
                <TabsTrigger value="whitelist">仅白名单设备</TabsTrigger>
                <TabsTrigger value="blacklist">拒绝黑名单设备</TabsTrigger>
              </TabsList>
            </Tabs>
            {d['access.lan.mode'] !== 'all' && (
              <Field label={d['access.lan.mode'] === 'whitelist' ? '允许访问的设备' : '禁止访问的设备'}>
                <DevicePicker devices={devices ?? []} value={arr(d['access.lan.macs'])} onChange={(v) => setArr('access.lan.macs', v)} />
              </Field>
            )}
          </div>
        </Section>

        <Section title="公网访问" desc="按服务器实际看到的来源 IP，用离线库判断地区">
          <div className="grid gap-4 p-4">
            <Tabs value={d['access.wan.mode']} onValueChange={(v) => setD({ ...d, 'access.wan.mode': String(v) })}>
              <TabsList><TabsTrigger value="restrict">仅允许指定地区</TabsTrigger><TabsTrigger value="all">允许所有地区</TabsTrigger></TabsList>
            </Tabs>
            {d['access.wan.mode'] === 'restrict' && (
              <Field label="允许的国家 / 省州"><RegionPicker value={arr(d['access.wan.regions'])} onChange={(v) => setArr('access.wan.regions', v)} /></Field>
            )}
            <Field label="允许的浏览器时区（登录时检查）" hint="留空 = 不检查。时区由浏览器上报，只能作为额外门槛。">
              <div className="grid gap-2">
                <div className="flex flex-wrap gap-1.5">
                  {tzs.map((t) => (
                    <span key={t} className="inline-flex items-center gap-1 rounded-full bg-accent py-0.5 pl-2.5 pr-1 text-xs text-accent-foreground">
                      {t}<button type="button" className="rounded-full p-0.5 hover:bg-primary/15" onClick={() => setArr('access.wan.timezones', tzs.filter((x) => x !== t))}><X className="size-3" /></button>
                    </span>
                  ))}
                </div>
                <div className="flex gap-2">
                  <Input placeholder="例如 Pacific/Auckland" value={tzInput} onChange={(e) => setTzInput(e.target.value)} />
                  <Button variant="outline" disabled={!tzInput.trim()} onClick={() => { setArr('access.wan.timezones', [...new Set([...tzs, tzInput.trim()])]); setTzInput('') }}><Plus /> 添加</Button>
                  <Button variant="ghost" onClick={() => setArr('access.wan.timezones', [...new Set([...tzs, browserTZ()])])}>添加我的时区</Button>
                </div>
              </div>
            </Field>
          </div>
        </Section>

        <Section title="IP 白名单 / 黑名单" desc="对内网和公网都生效；黑名单优先，白名单可跳过地区与设备检查">
          <div className="grid gap-4 p-4 sm:grid-cols-2" key={rev}>
            <Field label="始终允许"><IPListInput value={arr(d['access.allow_ips'])} onChange={(v) => setArr('access.allow_ips', v)} /></Field>
            <Field label="始终拒绝"><IPListInput value={arr(d['access.deny_ips'])} onChange={(v) => setArr('access.deny_ips', v)} /></Field>
          </div>
        </Section>

        <Section title="前端 IP 检查" desc="访问者的浏览器向 ip.sb 查询自己的出口 IP 并上报，用于发现分流代理">
          <label className="flex items-center justify-between gap-4 p-4">
            <span className="text-sm text-muted-foreground">若 ip.sb 看到的 IP 与服务器看到的不同，访问记录会标记为「疑似代理」。上报数据由浏览器提供，仅作参考，不参与放行判断。</span>
            <Switch checked={d['access.ipsb'] === '1'} onCheckedChange={(c) => setD({ ...d, 'access.ipsb': c ? '1' : '0' })} />
          </label>
        </Section>
      </div>
      {dialog}
    </>
  )
}
