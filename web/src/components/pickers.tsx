import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Search, X } from 'lucide-react'
import { useApi } from '@/lib/hooks'
import type { ForwardTarget, RegionInfo } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
import { Dot, VMTag } from '@/components/common'
import { DeviceIcon } from '@/components/device-icon'

// regionLabel turns "NZ" / "NZ/Auckland" into a readable label.
export function regionLabel(key: string, regions?: RegionInfo[] | null) {
  const [c, sub] = key.split('/')
  const name = regions?.find((r) => r.code === c)?.name ?? c
  return sub ? `${name} · ${sub}` : name
}

function Chip({ children, onRemove }: { children: React.ReactNode; onRemove: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-accent py-0.5 pl-2.5 pr-1 text-xs text-accent-foreground">
      {children}
      <button type="button" className="rounded-full p-0.5 hover:bg-primary/15" onClick={onRemove}><X className="size-3" /></button>
    </span>
  )
}

// RegionPicker selects countries ("NZ") or country/state ("NZ/Auckland") from the offline database.
export function RegionPicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const { data, error, loading } = useApi<RegionInfo[]>('/geo/regions')
  const [q, setQ] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  const list = useMemo(() => {
    const s = q.trim().toLowerCase()
    if (!data) return []
    if (!s) return data.filter((r) => ['NZ', 'AU', 'CN', 'HK', 'TW', 'US', 'JP', 'SG', 'GB'].includes(r.code) || value.some((v) => v.startsWith(r.code)))
    return data.filter((r) => r.code.toLowerCase() === s || r.name.toLowerCase().includes(s) || r.name_en.toLowerCase().includes(s)
      || (r.regions ?? []).some((x) => x.toLowerCase().includes(s)))
  }, [data, q, value])
  const toggle = (k: string, on: boolean) => onChange(on ? [...value, k] : value.filter((x) => x !== k))

  return (
    <div className="grid gap-2">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {value.map((k) => <Chip key={k} onRemove={() => toggle(k, false)}>{regionLabel(k, data)}</Chip>)}
        </div>
      )}
      <div className="rounded-lg border">
        <div className="relative border-b">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input className="h-8 border-0 pl-8 shadow-none focus-visible:ring-0" placeholder="搜索国家 / 省州（中文、英文或代码）" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="max-h-64 overflow-y-auto py-1 text-sm">
          {loading && <div className="px-3 py-2 text-muted-foreground">首次加载地区列表需要十几秒…</div>}
          {error && <div className="px-3 py-2 text-destructive">{error}</div>}
          {list.map((r) => (
            <div key={r.code}>
              <div className="flex items-center gap-2 px-3 py-1.5 hover:bg-muted">
                <Checkbox checked={value.includes(r.code)} onCheckedChange={(c) => toggle(r.code, !!c)} />
                <span className="flex-1">{r.name}<span className="ml-1.5 text-xs text-muted-foreground">{r.code}</span></span>
                {(r.regions?.length ?? 0) > 0 && (
                  <button type="button" className="flex items-center text-xs text-muted-foreground hover:text-foreground" onClick={() => setOpen(open === r.code ? null : r.code)}>
                    省/州 <ChevronRight className={cn('size-3.5 transition-transform', open === r.code && 'rotate-90')} />
                  </button>
                )}
              </div>
              {open === r.code && (
                <div className="grid grid-cols-2 gap-x-2 pb-1 pl-9 pr-3">
                  {r.regions!.map((sub) => {
                    const k = `${r.code}/${sub}`
                    return (
                      <label key={k} className="flex cursor-pointer items-center gap-2 py-1 text-xs">
                        <Checkbox checked={value.includes(k)} disabled={value.includes(r.code)} onCheckedChange={(c) => toggle(k, !!c)} />{sub}
                      </label>
                    )
                  })}
                </div>
              )}
            </div>
          ))}
          {data && !list.length && <div className="px-3 py-2 text-muted-foreground">没有匹配的地区</div>}
        </div>
      </div>
    </div>
  )
}

// IPListInput edits a list of IPs / CIDRs, one per line.
export function IPListInput({ value, onChange, placeholder }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [text, setText] = useState(value.join('\n'))
  return (
    <Textarea rows={3} className="font-mono text-xs" placeholder={placeholder ?? '每行一个，例如\n203.0.113.7\n198.51.100.0/24'} value={text}
      onChange={(e) => { setText(e.target.value); onChange(e.target.value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)) }} />
  )
}

// DevicePicker selects LAN devices by MAC (multi) from the live device list.
export function DevicePicker({ devices, value, onChange }: { devices: ForwardTarget[]; value: string[]; onChange: (v: string[]) => void }) {
  const [q, setQ] = useState('')
  const s = q.trim().toLowerCase()
  const list = devices.filter((d) => !s || [d.name, d.ip, d.mac].some((x) => x.toLowerCase().includes(s)))
  const has = (mac: string) => value.some((v) => v.toLowerCase() === mac.toLowerCase())
  const toggle = (mac: string, on: boolean) => onChange(on ? [...value, mac] : value.filter((v) => v.toLowerCase() !== mac.toLowerCase()))
  const unknown = value.filter((m) => !devices.some((d) => d.mac.toLowerCase() === m.toLowerCase()))
  return (
    <div className="rounded-lg border">
      <div className="relative border-b">
        <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input className="h-8 border-0 pl-8 shadow-none focus-visible:ring-0" placeholder="名称 / IP / MAC" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="max-h-64 overflow-y-auto py-1 text-sm">
        {unknown.map((m) => (
          <label key={m} className="flex items-center gap-2.5 px-3 py-1.5 hover:bg-muted">
            <Checkbox checked onCheckedChange={() => toggle(m, false)} />
            <span className="flex-1 text-muted-foreground">当前不在线的设备</span><span className="font-mono text-xs">{m}</span>
          </label>
        ))}
        {list.map((d) => (
          <label key={d.mac} className="flex cursor-pointer items-center gap-2.5 px-3 py-1.5 hover:bg-muted">
            <Checkbox checked={has(d.mac)} onCheckedChange={(c) => toggle(d.mac, !!c)} />
            <Dot tone={d.online ? 'ok' : 'off'} />
            <span className="flex-1 truncate">{d.name || '未知设备'}</span>
            <span className="font-mono text-xs text-muted-foreground">{d.ip}</span>
          </label>
        ))}
      </div>
    </div>
  )
}

// DeviceSelect: pick one LAN device by name / IP / MAC / vendor / note, or type an IP.
export function DeviceSelect({ devices, value, fallbackName, onChange }: {
  devices: ForwardTarget[] | null | undefined; value: string; fallbackName?: string
  onChange: (ip: string, device?: ForwardTarget) => void
}) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const sel = devices?.find((d) => d.ip === value)
  const s = q.trim().toLowerCase()
  const list = (devices ?? [])
    .filter((d) => !s || [d.name, d.ip, d.mac, d.vendor, d.hostname, d.type, d.note, d.vm_tag].some((x) => x?.toLowerCase().includes(s)))
    .sort((a, b) => Number(b.online) - Number(a.online) || ipNum(a.ip) - ipNum(b.ip))
  const typedIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(q.trim()) && !list.some((d) => d.ip === q.trim()) ? q.trim() : ''
  const pick = (ip: string, d?: ForwardTarget) => { onChange(ip, d); setOpen(false); setQ('') }

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)}
        className="flex h-auto min-h-9 w-full items-center gap-2.5 rounded-lg border bg-transparent px-2.5 py-1.5 text-left text-sm hover:bg-muted/40 disabled:opacity-60">
        {value ? (
          <>
            <DeviceIcon type={sel?.type} online={sel?.online} className="size-7" />
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-1.5"><span className="truncate font-medium">{sel?.name || fallbackName || '未知设备'}</span><VMTag tag={sel?.vm_tag} /></span>
              <span className="block truncate font-mono text-[11px] text-muted-foreground">{value}{sel ? ` · ${sel.mac}` : ''}</span>
            </span>
          </>
        ) : <span className="flex-1 text-muted-foreground">选择设备…</span>}
        <ChevronDown className="size-4 shrink-0 text-muted-foreground" />
      </button>
    )
  }
  return (
    <div className="grid gap-1.5 rounded-lg border p-1.5">
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input autoFocus value={q} onChange={(e) => setQ(e.target.value)} placeholder="搜索名称、IP、MAC、厂商、备注，或直接输入 IP"
          className="h-8 pl-8" onKeyDown={(e) => {
            if (e.key === 'Escape') { setOpen(false); setQ('') }
            if (e.key === 'Enter') { e.preventDefault(); if (list[0]) pick(list[0].ip, list[0]); else if (typedIP) pick(typedIP) }
          }} />
      </div>
      <div className="max-h-72 overflow-y-auto">
        {typedIP && (
          <button type="button" onClick={() => pick(typedIP)} className="flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted">
            <span className="grid size-7 place-items-center rounded-lg bg-muted text-xs text-muted-foreground">IP</span>
            使用 <span className="font-mono">{typedIP}</span><span className="text-xs text-muted-foreground">（不在设备列表中）</span>
          </button>
        )}
        {list.map((d) => (
          <button key={d.mac + d.ip} type="button" onClick={() => pick(d.ip, d)}
            className={cn('flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left hover:bg-muted', d.ip === value && 'bg-accent')}>
            <DeviceIcon type={d.type} online={d.online} className="size-7" />
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-1.5 text-sm"><span className="truncate font-medium">{d.name || '未知设备'}</span><VMTag tag={d.vm_tag} /></span>
              <span className="block truncate text-[11px] text-muted-foreground">
                <span className="font-mono">{d.ip}</span>{d.vendor ? ` · ${d.vendor}` : ''}{d.type && d.type !== '未知' ? ` · ${d.type}` : ''}{d.note ? ` · ${d.note}` : ''}
              </span>
            </span>
            {!d.online && <span className="shrink-0 text-[11px] text-muted-foreground">离线</span>}
          </button>
        ))}
        {!list.length && !typedIP && <div className="px-2 py-6 text-center text-sm text-muted-foreground">{devices ? '没有匹配的设备' : '加载中…'}</div>}
      </div>
      <button type="button" className="text-xs text-muted-foreground hover:text-foreground" onClick={() => { setOpen(false); setQ('') }}>收起</button>
    </div>
  )
}

const ipNum = (ip: string) => ip.split('.').reduce((n, p) => n * 256 + Number(p), 0)
