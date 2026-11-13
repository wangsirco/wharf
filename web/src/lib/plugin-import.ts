import { del, get, post, put } from './api'
import { runLuciView } from './luci-view'
import { fromCbi, type FormBlock } from './plugin-form'
import type { PluginItem } from './plugins'

// Importing a plugin converts every LuCI page of it to Wharf's form model once,
// stores the structure on the panel (no values), and from then on a page opens
// from that copy with the current uci values laid over it.

export type PluginPage = NonNullable<PluginItem['pages']>[number]

export interface ImportedPage {
  path: string; title: string; kind: string; target: string
  status: 'ok' | 'custom' | 'failed'; error?: string; blocks?: FormBlock[] | null
}
export interface PluginImport { pkg: string; version: string; imported_at: number; imported_by: string; refreshed_at: number; pages: ImportedPage[] }

export const formPages = (p: PluginItem): PluginPage[] =>
  (p.pages ?? []).filter((g) => g.title && ['cbi', 'form', 'view', 'template'].includes(g.kind))

/** Converts one page now (the slow path: CBI dump on the router, or JS view in the sandbox). */
export async function convertPage(pkg: string, page: PluginPage): Promise<ImportedPage> {
  const base = { path: page.path, title: page.title, kind: page.kind, target: page.target }
  if (page.kind !== 'view' && page.kind !== 'cbi' && page.kind !== 'form') return { ...base, status: 'custom' }
  try {
    const blocks = page.kind === 'view'
      ? await runLuciView(page.target)
      : fromCbi((await get<{ tree: Parameters<typeof fromCbi>[0] }>(`/plugins/form?pkg=${encodeURIComponent(pkg)}&model=${encodeURIComponent(page.target)}`)).tree)
    return { ...base, status: 'ok', blocks }
  } catch (e) {
    return { ...base, status: 'failed', error: (e as Error).message }
  }
}

/** Converts every page of the plugin and stores the result; onStep reports progress. */
export async function importPlugin(p: PluginItem, onStep?: (done: number, total: number, page: ImportedPage | null) => void) {
  const pages = formPages(p)
  const out: ImportedPage[] = []
  onStep?.(0, pages.length, null)
  for (const g of pages) {
    const r = await convertPage(p.pkg, g)
    out.push(r)
    onStep?.(out.length, pages.length, r)
  }
  await post('/plugins/import', { pkg: p.pkg, version: p.version, pages: out })
  return out
}

export const unimportPlugin = (pkg: string) => del(`/plugins/import?pkg=${encodeURIComponent(pkg)}`)
export const loadImport = (pkg: string) => get<PluginImport>(`/plugins/import?pkg=${encodeURIComponent(pkg)}`)
export const storePage = (pkg: string, page: ImportedPage) => put('/plugins/import/page', { pkg, page }).catch(() => {})

type UciSec = Record<string, unknown> & { '.type'?: string; '.index'?: number; '.name'?: string }

/** Fills the stored structure with the current uci values (fast: one read per config). */
export async function withCurrentValues(blocks: FormBlock[]): Promise<FormBlock[]> {
  const configs = [...new Set(blocks.flatMap((b) => (b.type === 'map' && b.map.config && !b.map.json ? [b.map.config] : [])))]
  const data: Record<string, Record<string, UciSec>> = {}
  await Promise.all(configs.map(async (c) => { data[c] = await get<Record<string, UciSec>>(`/plugins/uci?config=${encodeURIComponent(c)}`).catch(() => ({})) }))
  return blocks.map((b) => {
    if (b.type !== 'map' || !b.map.config || b.map.json) return b
    const all = data[b.map.config] ?? {}
    const byType = (t: string) => Object.entries(all).filter(([, s]) => s['.type'] === t).sort((x, y) => (x[1]['.index'] ?? 0) - (y[1]['.index'] ?? 0)).map(([n]) => n)
    return {
      ...b,
      map: {
        ...b.map,
        sections: b.map.sections.map((s) => {
          const sids = s.name ? [s.name] : s.type ? byType(s.type) : s.sections
          return {
            ...s,
            sections: sids,
            options: s.options.map((o) => {
              if (!o.option || ['dummy', 'button', 'custom'].includes(o.kind)) return o
              const values: Record<string, string | string[]> = {}
              for (const sid of sids) {
                const v = all[sid]?.[o.option]
                if (typeof v === 'string' || Array.isArray(v)) values[sid] = v as string | string[]
              }
              return { ...o, values }
            }),
          }
        }),
      },
    }
  })
}
