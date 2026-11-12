// One form model for both kinds of LuCI pages: Lua CBI models (dumped on the
// router by LuCI's own parser) and JavaScript views (run in the sandbox).

export type OptKind = 'value' | 'list' | 'flag' | 'dynlist' | 'multi' | 'text' | 'dummy' | 'button' | 'hidden' | 'custom'

export interface FOpt {
  kind: OptKind
  option: string
  title: string | null
  description?: string | null
  default?: string | null
  placeholder?: string | null
  rmempty?: boolean
  optional?: boolean
  password?: boolean
  readonly?: boolean
  datatype?: string | null
  enabled?: string | null
  disabled?: string | null
  widget?: string | null
  tab?: string | null
  choices?: [string, string][]
  deps?: Record<string, string>[]
  custom_write?: boolean
  values?: Record<string, string | string[]>
  rows?: number | null
}

export interface FSection {
  kind: 'typed' | 'named' | 'table' | 'custom'
  type?: string | null
  name?: string | null
  title?: string | null
  description?: string | null
  anonymous?: boolean
  addremove?: boolean
  sortable?: boolean
  sections: string[]
  tabs: { name: string; title: string }[]
  options: FOpt[]
  template?: string | null
}

export interface FMap {
  config: string | null
  json?: boolean
  title?: string | null
  description?: string | null
  readonly?: boolean
  sections: FSection[]
}

export type FormBlock = { type: 'map'; map: FMap } | { type: 'html'; html: string } | { type: 'note'; text: string }

// ---- Lua CBI dump -> form model ----

interface CbiNode {
  class: string
  config?: string; title?: string; description?: string; template?: string; children?: CbiNode[]; readonly?: boolean
  sectiontype?: string; section?: string; addremove?: boolean; anonymous?: boolean; sortable?: boolean; sections?: string[]
  tabs?: { name: string; title: string }[]
  option?: string; datatype?: string; default?: string; placeholder?: string; rmempty?: boolean; optional?: boolean; password?: boolean
  enabled?: string; disabled?: string; widget?: string; delimiter?: string; rows?: number; inputtitle?: string
  custom_write?: boolean; custom_value?: boolean; deps?: Record<string, string>[]; choices?: [string, string][]; values?: Record<string, string | string[]>; tab?: string
}

const stdTemplate = (t?: string) => !t || t.startsWith('cbi/')

function cbiOpt(n: CbiNode): FOpt {
  const kind: OptKind = !stdTemplate(n.template) ? 'custom'
    : ({ Flag: 'flag', ListValue: 'list', MultiValue: 'multi', StaticList: 'multi', DynamicList: 'dynlist', TextValue: 'text', DummyValue: 'dummy', Button: 'button', Value: 'value' } as Record<string, OptKind>)[n.class] ?? 'custom'
  return {
    kind, option: n.option ?? '', title: n.class === 'Button' ? (n.title || n.inputtitle || '') : (n.title ?? ''), description: n.description, default: n.default, placeholder: n.placeholder,
    rmempty: n.rmempty, optional: n.optional, password: n.password, readonly: n.readonly, datatype: n.datatype, enabled: n.enabled, disabled: n.disabled,
    widget: n.widget, tab: n.tab, choices: n.choices, deps: n.deps, custom_write: n.custom_write, values: n.values, rows: n.rows,
  }
}

export function fromCbi(tree: { maps?: CbiNode[]; error?: string }): FormBlock[] {
  if (tree.error) throw new Error(tree.error)
  const out: FormBlock[] = []
  for (const m of tree.maps ?? []) {
    const isForm = m.class === 'SimpleForm' || m.class === 'Delegator'
    const map: FMap = { config: isForm ? null : m.config ?? null, title: m.title, description: m.description, readonly: m.readonly || isForm, sections: [] }
    for (const c of m.children ?? []) {
      if (c.class === 'TypedSection' || c.class === 'NamedSection') {
        map.sections.push({
          kind: c.class === 'NamedSection' ? 'named' : 'typed', type: c.sectiontype, name: c.section, title: c.title, description: c.description,
          anonymous: c.anonymous, addremove: c.addremove, sortable: c.sortable, sections: c.sections ?? [], tabs: c.tabs ?? [],
          options: (c.children ?? []).map(cbiOpt), template: c.template,
        })
      } else if (c.class === 'Table' || c.class === 'SimpleSection') {
        map.sections.push({ kind: 'table', title: c.title, description: c.description, sections: c.sections ?? [], tabs: [], options: (c.children ?? []).map(cbiOpt), template: c.template })
      } else {
        map.sections.push({ kind: 'custom', title: c.title, description: c.description, sections: [], tabs: [], options: [], template: c.template })
      }
    }
    out.push({ type: 'map', map })
  }
  return out
}

// ---- values, dependencies, changes ----

export type Values = Record<string, string | string[] | undefined> // key: section/option

export const vkey = (sid: string, opt: string) => `${sid}\u0001${opt}`

export function initialValues(sec: FSection): Values {
  const v: Values = {}
  for (const o of sec.options) for (const sid of sec.sections) {
    const x = o.values?.[sid]
    if (x !== undefined) v[vkey(sid, o.option)] = x
  }
  return v
}

export function effective(o: FOpt, v: string | string[] | undefined): string | string[] {
  if (v !== undefined && v !== null) return v
  if (o.kind === 'flag') return o.default ?? o.disabled ?? '0'
  return o.default ?? ''
}

export function flagOn(o: FOpt, v: string | string[] | undefined) {
  return String(effective(o, v)) === (o.enabled ?? '1')
}

// visible: no dependencies, or one group whose every condition holds
export function visible(sec: FSection, o: FOpt, sid: string, vals: Values): boolean {
  const groups = (o.deps ?? []).map((g) => Object.entries(g).filter(([k]) => !k.startsWith('!')))
  if (!groups.length || groups.every((g) => !g.length)) return true
  return groups.some((g) => g.every(([field, want]) => {
    const dep = sec.options.find((x) => x.option === field)
    const cur = dep ? effective(dep, vals[vkey(sid, field)]) : vals[vkey(sid, field)]
    const s = Array.isArray(cur) ? cur.join(' ') : String(cur ?? '')
    if (dep?.kind === 'flag' && (want === '1' || want === '0' || want === 'true' || want === 'false')) {
      const on = s === (dep.enabled ?? '1')
      return on === (want === '1' || want === 'true')
    }
    return s === want || (Array.isArray(cur) && cur.includes(want))
  }))
}

export const editableKind = (k: OptKind) => k === 'value' || k === 'list' || k === 'flag' || k === 'dynlist' || k === 'multi' || k === 'text'

export interface UciChange { op: 'set' | 'delete' | 'add'; config: string; section?: string; type?: string; values?: Record<string, unknown>; options?: string[] }

// changes: diff the edited values against the loaded ones for one section.
export function sectionChanges(config: string, sec: FSection, before: Values, after: Values): UciChange[] {
  const out: UciChange[] = []
  for (const sid of sec.sections) {
    const set: Record<string, unknown> = {}
    const del: string[] = []
    for (const o of sec.options) {
      if (!editableKind(o.kind) || o.readonly || o.custom_write || !o.option) continue
      const k = vkey(sid, o.option)
      if (!(k in after)) continue
      const a = after[k], b = before[k]
      if (JSON.stringify(a ?? null) === JSON.stringify(b ?? null)) continue
      const empty = a === undefined || a === '' || (Array.isArray(a) && a.length === 0)
      const isDisabledFlag = o.kind === 'flag' && String(a) === (o.disabled ?? '0') && o.rmempty !== false
      if (empty || isDisabledFlag) {
        if (b !== undefined) del.push(o.option)
      } else set[o.option] = a
    }
    if (Object.keys(set).length) out.push({ op: 'set', config, section: sid, values: set })
    if (del.length) out.push({ op: 'delete', config, section: sid, options: del })
  }
  return out
}

// ---- datatype checks for the common LuCI datatypes ----

const ip4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const ip6 = /^[0-9a-fA-F:.]+$/
export function checkDatatype(dt: string | null | undefined, v: string): string | null {
  if (!dt || v === '') return null
  const one = (t: string, x: string): boolean => {
    const m = /^(\w+)(?:\((.*)\))?$/.exec(t.trim())
    if (!m) return true
    const [, name, arg] = m
    const n = Number(x)
    switch (name) {
      case 'port': return Number.isInteger(n) && n >= 0 && n <= 65535
      case 'portrange': return /^\d{1,5}([-:]\d{1,5})?$/.test(x)
      case 'uinteger': return /^\d+$/.test(x)
      case 'integer': return /^-?\d+$/.test(x)
      case 'ufloat': return /^\d+(\.\d+)?$/.test(x)
      case 'float': return /^-?\d+(\.\d+)?$/.test(x)
      case 'range': { const [lo, hi] = (arg ?? '').split(',').map(Number); return !isNaN(n) && n >= lo && n <= hi }
      case 'min': return !isNaN(n) && n >= Number(arg)
      case 'max': return !isNaN(n) && n <= Number(arg)
      case 'ipaddr': case 'ipmask': case 'cidr': return ip4.test(x.split('/')[0]) || ip6.test(x.split('/')[0])
      case 'ip4addr': case 'ipmask4': case 'cidr4': return ip4.test(x.split('/')[0])
      case 'ip6addr': case 'ipmask6': case 'cidr6': return ip6.test(x.split('/')[0])
      case 'macaddr': return /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(x)
      case 'host': case 'hostname': return /^[a-zA-Z0-9_.:-]+$/.test(x)
      case 'hostport': case 'ipaddrport': return /^[a-zA-Z0-9_.:[\]-]+:\d{1,5}$/.test(x)
      case 'or': return (arg ?? '').split(/,(?![^(]*\))/).some((a) => one(a, x))
      case 'and': return (arg ?? '').split(/,(?![^(]*\))/).every((a) => one(a, x))
      case 'list': return x.split(/\s+/).every((p) => one(arg ?? '', p))
      case 'minlength': return x.length >= Number(arg)
      case 'maxlength': return x.length <= Number(arg)
      case 'rangelength': { const [lo, hi] = (arg ?? '').split(',').map(Number); return x.length >= lo && x.length <= hi }
      default: return true
    }
  }
  return one(dt, v) ? null : '格式不正确'
}

// ---- safe HTML for plugin titles / descriptions / status blocks ----

const allowed = new Set(['B', 'STRONG', 'I', 'EM', 'BR', 'CODE', 'PRE', 'P', 'DIV', 'SPAN', 'A', 'UL', 'OL', 'LI', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TD', 'TH', 'SMALL', 'H3', 'H4', 'H5', 'LABEL', 'SUP', 'SUB', 'HR'])

export function sanitizeHTML(html: string | null | undefined): string {
  if (!html) return ''
  const doc = new DOMParser().parseFromString(`<div>${html}</div>`, 'text/html')
  const out = document.createElement('div')
  const copy = (src: Node, dst: Node) => {
    for (const n of Array.from(src.childNodes)) {
      if (n.nodeType === Node.TEXT_NODE) { dst.appendChild(document.createTextNode(n.textContent ?? '')); continue }
      if (n.nodeType !== Node.ELEMENT_NODE) continue
      const el = n as Element
      if (el.tagName === 'SCRIPT' || el.tagName === 'STYLE' || el.tagName === 'TEMPLATE') continue
      if (!allowed.has(el.tagName)) { copy(el, dst); continue }
      const c = document.createElement(el.tagName)
      if (el.tagName === 'A') {
        const href = el.getAttribute('href') ?? ''
        if (/^https?:\/\//i.test(href)) { c.setAttribute('href', href); c.setAttribute('target', '_blank'); c.setAttribute('rel', 'noreferrer') }
      }
      for (const at of ['colspan', 'rowspan']) if (el.hasAttribute(at)) c.setAttribute(at, el.getAttribute(at)!)
      copy(el, c)
      dst.appendChild(c)
    }
  }
  copy(doc.body.firstChild ?? doc.body, out)
  return out.innerHTML
}

export function plainText(html: string | null | undefined): string {
  if (!html) return ''
  return new DOMParser().parseFromString(html, 'text/html').body.textContent?.trim() ?? ''
}
