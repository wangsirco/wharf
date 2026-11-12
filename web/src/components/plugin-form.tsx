import { useMemo, useState } from 'react'
import { ExternalLink, Plus, RotateCcw, Save, X } from 'lucide-react'
import {
  checkDatatype, editableKind, flagOn, initialValues, plainText, sanitizeHTML, sectionChanges, visible, vkey,
  type FMap, type FOpt, type FormBlock, type FSection, type UciChange, type Values,
} from '@/lib/plugin-form'
import { Pill } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

// PluginForm draws a plugin page (from LuCI CBI or a JS view) in Wharf's design.
// Only plain uci options are editable here; anything the plugin handles with its
// own code (buttons, custom templates, custom save logic) links to LuCI instead.

const Html = ({ html, className }: { html?: string | null; className?: string }) =>
  html ? <span className={className} dangerouslySetInnerHTML={{ __html: sanitizeHTML(html) }} /> : null

export function PluginForm({ blocks, editable, luciURL, saving, onSave }: {
  blocks: FormBlock[]; editable: boolean; luciURL: string; saving?: boolean; onSave: (changes: UciChange[]) => void
}) {
  const initial = useMemo(() => {
    const m: Record<string, Values> = {}
    blocks.forEach((b, bi) => { if (b.type === 'map') b.map.sections.forEach((s, si) => { m[`${bi}.${si}`] = initialValues(s) }) })
    return m
  }, [blocks])
  const [vals, setVals] = useState<Record<string, Values>>(initial)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const changes = useMemo(() => {
    const out: UciChange[] = []
    blocks.forEach((b, bi) => {
      if (b.type !== 'map' || !b.map.config || b.map.readonly || b.map.json) return
      b.map.sections.forEach((s, si) => out.push(...sectionChanges(b.map.config!, s, initial[`${bi}.${si}`] ?? {}, vals[`${bi}.${si}`] ?? {})))
    })
    return out
  }, [blocks, initial, vals])

  const set = (key: string, sid: string, o: FOpt, v: string | string[]) => {
    setVals((cur) => ({ ...cur, [key]: { ...cur[key], [vkey(sid, o.option)]: v } }))
    const err = typeof v === 'string' ? checkDatatype(o.datatype, v) : v.map((x) => checkDatatype(o.datatype, x)).find(Boolean) ?? null
    setErrors((e) => { const n = { ...e }; const k = `${key}|${sid}|${o.option}`; if (err) n[k] = err; else delete n[k]; return n })
  }
  const hasErrors = Object.keys(errors).length > 0

  return (
    <div className="grid gap-4">
      {blocks.map((b, bi) => {
        if (b.type === 'note') return <div key={bi} className="rounded-lg border bg-muted/30 px-3 py-2 text-sm whitespace-pre-line">{b.text}</div>
        if (b.type === 'html') return <div key={bi} className="plugin-html rounded-xl border bg-card p-4 text-sm"><Html html={b.html} /></div>
        return <MapView key={bi} map={b.map} bi={bi} vals={vals} errors={errors} editable={editable && !b.map.readonly && !b.map.json && !!b.map.config} luciURL={luciURL} set={set} />
      })}
      {editable && changes.length > 0 && (
        <div className="sticky bottom-3 z-10 flex flex-wrap items-center gap-2 rounded-xl border bg-card/95 px-4 py-2.5 shadow-lg backdrop-blur">
          <span className="text-sm">改了 {changes.reduce((n, c) => n + Object.keys(c.values ?? {}).length + (c.options?.length ?? 0), 0)} 项</span>
          {hasErrors && <span className="text-xs text-destructive">有格式不正确的内容</span>}
          <span className="flex-1" />
          <Button variant="outline" size="sm" onClick={() => { setVals(initial); setErrors({}) }}><RotateCcw /> 还原</Button>
          <Button size="sm" disabled={saving || hasErrors} onClick={() => onSave(changes)}><Save /> 保存并应用</Button>
        </div>
      )}
    </div>
  )
}

// untitled custom blocks are summarised in one line; tables of nothing but
// buttons are the plugin's own save / apply bar (Wharf has its own)
const hiddenSection = (s: FSection) => (s.kind === 'custom' && !s.title) || (s.kind === 'table' && s.options.length > 0 && s.options.every((o) => o.kind === 'button' || o.kind === 'custom'))
const hiddenOption = (o: FOpt) => o.kind === 'hidden' || ((o.kind === 'custom' || o.kind === 'button') && !plainText(o.title) && !o.description)

function MapView({ map, bi, vals, errors, editable, luciURL, set }: {
  map: FMap; bi: number; vals: Record<string, Values>; errors: Record<string, string>; editable: boolean; luciURL: string
  set: (key: string, sid: string, o: FOpt, v: string | string[]) => void
}) {
  return (
    <div className="grid gap-3">
      {(map.title || map.description) && (
        <div>
          {map.title && <h2 className="text-base font-semibold">{plainText(map.title)}</h2>}
          {map.description && <p className="text-sm text-muted-foreground"><Html html={map.description} /></p>}
        </div>
      )}
      {map.sections.map((s, si) => hiddenSection(s) ? null : <SectionView key={si} sec={s} k={`${bi}.${si}`} vals={vals[`${bi}.${si}`] ?? {}} errors={errors} editable={editable} luciURL={luciURL} set={set} />)}
      {map.sections.some((s) => s.kind === 'custom' && !s.title) && (
        <p className="text-xs text-muted-foreground">这个页面另有 {map.sections.filter((s) => s.kind === 'custom' && !s.title).length} 块插件自己画的界面（状态面板、按钮等）没有转换，<a className="text-primary hover:underline" href={luciURL} target="_blank" rel="noreferrer">在 LuCI 中查看</a>。</p>
      )}
      {!map.sections.length && <p className="text-sm text-muted-foreground">这个页面没有可以显示的设置。</p>}
    </div>
  )
}

function SectionView({ sec, k, vals, errors, editable, luciURL, set }: {
  sec: FSection; k: string; vals: Values; errors: Record<string, string>; editable: boolean; luciURL: string
  set: (key: string, sid: string, o: FOpt, v: string | string[]) => void
}) {
  const [tab, setTab] = useState(sec.tabs[0]?.name ?? '')
  const shown = sec.options.filter((o) => !hiddenOption(o))
  if (sec.kind === 'custom') {
    return (
      <div className="rounded-xl border border-dashed p-4 text-sm text-muted-foreground">
        {sec.title && <div className="mb-1 font-medium text-foreground">{plainText(sec.title)}</div>}
        这一块是插件自己画的界面（状态面板、按钮等），Wharf 没法转换。<a className="ml-1 inline-flex items-center gap-1 text-primary hover:underline" href={luciURL} target="_blank" rel="noreferrer">在 LuCI 中查看 <ExternalLink className="size-3" /></a>
      </div>
    )
  }
  if (sec.kind === 'table') {
    if (!sec.sections.length) return null
    const cols = shown.filter((o) => o.kind !== 'button')
    return (
      <div className="overflow-hidden rounded-xl border bg-card">
        {sec.title && <div className="border-b px-4 py-2.5 text-sm font-semibold">{plainText(sec.title)}</div>}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-xs text-muted-foreground"><tr>{cols.map((o, i) => <th key={i} className="px-3 py-2 text-left font-medium">{plainText(o.title) || o.option}</th>)}</tr></thead>
            <tbody>
              {sec.sections.map((sid) => (
                <tr key={sid} className="border-t">
                  {cols.map((o, i) => { const v = vals[vkey(sid, o.option)]; return <td key={i} className="px-3 py-2"><Html html={Array.isArray(v) ? v.join(', ') : v ?? ''} /></td> })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {shown.some((o) => o.kind === 'button') && <div className="border-t px-4 py-2 text-xs text-muted-foreground">表格里的操作按钮（启动、删除等）请<a className="mx-1 text-primary hover:underline" href={luciURL} target="_blank" rel="noreferrer">在 LuCI 中</a>进行。</div>}
      </div>
    )
  }
  const opts = sec.tabs.length && tab ? shown.filter((o) => (o.tab ?? sec.tabs[0].name) === tab) : shown
  const many = sec.sections.length > 1
  return (
    <section className="rounded-xl border bg-card">
      {(sec.title || sec.description || sec.tabs.length > 0) && (
        <div className="grid gap-2 border-b px-4 py-3">
          {sec.title && <h3 className="text-sm font-semibold">{plainText(sec.title)}</h3>}
          {sec.description && <p className="text-xs text-muted-foreground"><Html html={sec.description} /></p>}
          {sec.tabs.length > 1 && (
            <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
              <TabsList className="h-auto flex-wrap">{sec.tabs.map((t) => <TabsTrigger key={t.name} value={t.name}>{plainText(t.title)}</TabsTrigger>)}</TabsList>
            </Tabs>
          )}
        </div>
      )}
      {!sec.sections.length && (
        <p className="px-4 py-6 text-sm text-muted-foreground">还没有这类配置。{sec.addremove && <>新增请<a className="mx-1 text-primary hover:underline" href={luciURL} target="_blank" rel="noreferrer">在 LuCI 中</a>操作。</>}</p>
      )}
      {sec.sections.map((sid, idx) => {
        const rows = (
          <div className="divide-y">
            {opts.filter((o) => visible(sec, o, sid, vals)).map((o, i) => (
              <OptionRow key={o.option + i} o={o} v={vals[vkey(sid, o.option)]} err={errors[`${k}|${sid}|${o.option}`]} editable={editable} luciURL={luciURL} onChange={(v) => set(k, sid, o, v)} />
            ))}
          </div>
        )
        if (!many) return <div key={sid}>{rows}</div>
        const label = ['remarks', 'name', 'alias', 'label', 'description'].map((x) => vals[vkey(sid, x)]).find((x) => x && !Array.isArray(x))
        const anon = /^cfg[0-9a-f]{6}$/.test(sid)
        return (
          <details key={sid} className="group border-b last:border-b-0" open={sec.sections.length <= 3 || undefined}>
            <summary className="flex cursor-pointer list-none items-center gap-2 bg-muted/30 px-4 py-2 text-sm hover:bg-muted/50">
              <span className="text-muted-foreground transition-transform group-open:rotate-90">›</span>
              <span className="font-medium">{label ? String(label) : anon ? `第 ${idx + 1} 项` : sid}</span>
              {!anon && label && <span className="font-mono text-xs text-muted-foreground">{sid}</span>}
            </summary>
            {rows}
          </details>
        )
      })}
    </section>
  )
}

function OptionRow({ o, v, err, editable, luciURL, onChange }: {
  o: FOpt; v: string | string[] | undefined; err?: string; editable: boolean; luciURL: string; onChange: (v: string | string[]) => void
}) {
  const title = plainText(o.title) || o.option
  const canEdit = editable && editableKind(o.kind) && !o.readonly && !o.custom_write
  const str = v === undefined ? '' : Array.isArray(v) ? v.join(' ') : v
  const choiceLabel = (x: string) => o.choices?.find((c) => c[0] === x)?.[1] ?? x
  let control: React.ReactNode
  switch (o.kind) {
    case 'flag':
      control = <Switch checked={flagOn(o, v)} disabled={!canEdit} onCheckedChange={(c) => onChange(c ? (o.enabled ?? '1') : (o.disabled ?? '0'))} />
      break
    case 'list': {
      const cur = str || (o.default ?? '')
      const choices = o.choices ?? []
      control = canEdit ? (
        <select className="h-9 w-full max-w-md rounded-md border bg-background px-2 text-sm" value={cur} onChange={(e) => onChange(e.target.value)}>
          {!choices.some((c) => c[0] === cur) && <option value={cur}>{cur || '（未设置）'}</option>}
          {choices.map(([k, l]) => <option key={k} value={k}>{plainText(l) || k || '（空）'}</option>)}
        </select>
      ) : <span className="text-sm">{plainText(choiceLabel(cur)) || '—'}</span>
      break
    }
    case 'multi': {
      const cur = Array.isArray(v) ? v : str ? str.split(/\s+/) : []
      control = (
        <div className="flex flex-wrap gap-x-4 gap-y-1.5">
          {(o.choices ?? []).map(([k, l]) => (
            <label key={k} className="flex items-center gap-1.5 text-sm">
              <Checkbox checked={cur.includes(k)} disabled={!canEdit} onCheckedChange={(c) => onChange(c ? [...cur, k] : cur.filter((x) => x !== k))} />{plainText(l) || k}
            </label>
          ))}
          {!o.choices?.length && <span className="text-sm">{cur.join(', ') || '—'}</span>}
        </div>
      )
      break
    }
    case 'dynlist': {
      const cur = Array.isArray(v) ? v : str ? [str] : []
      control = <ListEditor value={cur} disabled={!canEdit} choices={o.choices} placeholder={o.placeholder ?? undefined} onChange={onChange} />
      break
    }
    case 'text':
      control = <Textarea className="max-w-2xl font-mono text-xs" rows={Math.min(o.rows ?? 6, 16)} value={str} disabled={!canEdit} onChange={(e) => onChange(e.target.value)} />
      break
    case 'dummy':
      control = <span className="text-sm"><Html html={str || o.default || '—'} /></span>
      break
    case 'button':
    case 'custom':
      control = <a className="inline-flex items-center gap-1 text-sm text-primary hover:underline" href={luciURL} target="_blank" rel="noreferrer">{o.kind === 'button' ? (title || '执行') + '：' : ''}在 LuCI 中操作 <ExternalLink className="size-3" /></a>
      break
    default:
      control = canEdit ? (
        <>
          <Input className="max-w-md" type={o.password ? 'password' : 'text'} autoComplete="off" value={str} placeholder={o.placeholder ?? o.default ?? ''} list={o.choices?.length ? `dl-${o.option}` : undefined} onChange={(e) => onChange(e.target.value)} />
          {!!o.choices?.length && <datalist id={`dl-${o.option}`}>{o.choices.map(([k, l]) => <option key={k} value={k}>{plainText(l)}</option>)}</datalist>}
        </>
      ) : <span className="break-all font-mono text-sm">{o.password && str ? '••••••' : str || (o.default ? <span className="text-muted-foreground">{o.default}（默认）</span> : '—')}</span>
  }
  return (
    <div className="grid gap-1.5 px-4 py-3 sm:grid-cols-[minmax(10rem,16rem)_1fr] sm:gap-4">
      <div className="text-sm">
        <span className="font-medium">{title}</span>
        {o.custom_write && editable && <Pill>由插件自己保存</Pill>}
      </div>
      <div className="grid min-w-0 gap-1">
        {control}
        {err && <span className="text-xs text-destructive">{err}</span>}
        {o.description && <span className="text-xs text-muted-foreground"><Html html={o.description} /></span>}
        {o.custom_write && editable && <span className="text-xs text-muted-foreground">这个选项由插件自己的代码保存，请<a className="mx-1 text-primary hover:underline" href={luciURL} target="_blank" rel="noreferrer">在 LuCI 中</a>修改。</span>}
      </div>
    </div>
  )
}

function ListEditor({ value, disabled, choices, placeholder, onChange }: { value: string[]; disabled: boolean; choices?: [string, string][]; placeholder?: string; onChange: (v: string[]) => void }) {
  const [add, setAdd] = useState('')
  const id = useMemo(() => 'dl-' + Math.random().toString(36).slice(2), [])
  return (
    <div className="grid max-w-md gap-1.5">
      {value.map((x, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <span className="min-w-0 flex-1 truncate rounded-md border bg-muted/30 px-2 py-1 font-mono text-xs" title={x}>{x}</span>
          {!disabled && <Button variant="ghost" size="icon-sm" onClick={() => onChange(value.filter((_, j) => j !== i))}><X /></Button>}
        </div>
      ))}
      {!value.length && disabled && <span className="text-sm text-muted-foreground">—</span>}
      {!disabled && (
        <div className="flex gap-1.5">
          <Input className="h-8 font-mono text-xs" value={add} placeholder={placeholder ?? '添加一项'} list={choices?.length ? id : undefined} onChange={(e) => setAdd(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && add.trim()) { e.preventDefault(); onChange([...value, add.trim()]); setAdd('') } }} />
          {!!choices?.length && <datalist id={id}>{choices.map(([k, l]) => <option key={k} value={k}>{plainText(l)}</option>)}</datalist>}
          <Button variant="outline" size="sm" disabled={!add.trim()} onClick={() => { onChange([...value, add.trim()]); setAdd('') }}><Plus /></Button>
        </div>
      )}
    </div>
  )
}
