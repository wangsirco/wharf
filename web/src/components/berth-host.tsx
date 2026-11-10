import { toast } from 'sonner'
import { Anchor, Box, Globe, MonitorCog } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import { openBerth } from '@/lib/berth'
import { Empty, ErrorBox, Pill, Section } from '@/components/common'
import { Button } from '@/components/ui/button'

// What Berth reports for one of its hosts (GET /api/ext/wharf/v1/hosts/{ip} on Berth, see docs/BERTH.md).
interface HostInfo {
  name?: string
  containers?: { name: string; image?: string; state?: string; ports?: string[] }[]
  vms?: { name: string; state?: string; ip?: string }[]
  sites?: { domain: string; state?: string; target?: string; ref?: string }[]
}

const tone = (s?: string) => (s && /^(running|up|online|active|ok)/i.test(s) ? 'green' : s && /(exit|stop|down|fail|error)/i.test(s) ? 'red' : 'muted') as 'green' | 'red' | 'muted'

// BerthHostTab: containers, VMs and sites on a Berth host, read from Berth.
export function BerthHostTab({ ip }: { ip: string }) {
  const { data, error, loading } = useApi<HostInfo>(`/berth/host/${ip}`, 30000)
  const open = (ref?: string) => openBerth({ ref }).catch((e) => toast.error((e as Error).message))
  if (error) return <ErrorBox>读取 Berth 失败：{error}</ErrorBox>
  if (!data) return <Empty>{loading ? '正在向 Berth 读取…' : '没有数据'}</Empty>
  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <div className="flex items-center gap-2 xl:col-span-3">
        <Anchor className="size-4 text-primary" /><span className="text-sm">数据来自 Berth{data.name ? `「${data.name}」` : ''}，每 30 秒刷新。</span>
        <Button variant="outline" size="sm" className="ml-auto" onClick={() => open()}>在 Berth 里打开</Button>
      </div>
      <Section title={`站点 ${data.sites?.length ?? 0}`}>
        <div className="grid gap-1 p-2">
          {data.sites?.map((s) => (
            <button key={s.domain} type="button" onClick={() => open(s.ref ?? `site:${s.domain}`)} className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm hover:bg-muted/50">
              <Globe className="size-4 text-muted-foreground" /><span className="min-w-0 flex-1 truncate font-mono">{s.domain}</span>
              {s.state && <Pill tone={tone(s.state)}>{s.state}</Pill>}
            </button>
          ))}
          {!data.sites?.length && <Empty>没有站点</Empty>}
        </div>
      </Section>
      <Section title={`容器 ${data.containers?.length ?? 0}`}>
        <div className="grid gap-1 p-2">
          {data.containers?.map((c) => (
            <div key={c.name} className="flex items-center gap-2 px-2 py-1.5 text-sm">
              <Box className="size-4 text-muted-foreground" />
              <span className="min-w-0 flex-1"><span className="block truncate">{c.name}</span>{c.image && <span className="block truncate text-xs text-muted-foreground">{c.image}{c.ports?.length ? ` · ${c.ports.join(', ')}` : ''}</span>}</span>
              {c.state && <Pill tone={tone(c.state)}>{c.state}</Pill>}
            </div>
          ))}
          {!data.containers?.length && <Empty>没有容器</Empty>}
        </div>
      </Section>
      <Section title={`虚拟机 ${data.vms?.length ?? 0}`}>
        <div className="grid gap-1 p-2">
          {data.vms?.map((v) => (
            <div key={v.name} className="flex items-center gap-2 px-2 py-1.5 text-sm">
              <MonitorCog className="size-4 text-muted-foreground" /><span className="min-w-0 flex-1 truncate">{v.name}</span>
              {v.ip && <span className="font-mono text-xs text-muted-foreground">{v.ip}</span>}
              {v.state && <Pill tone={tone(v.state)}>{v.state}</Pill>}
            </div>
          ))}
          {!data.vms?.length && <Empty>没有虚拟机</Empty>}
        </div>
      </Section>
    </div>
  )
}
