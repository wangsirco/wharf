import { get, post } from './api'
import type { FormBlock } from './plugin-form'

// Runs a LuCI JavaScript view (e.g. "nextdns/overview") inside the sandboxed
// iframe /luci-sandbox.html and returns the form tree it built. The iframe has an
// opaque origin; every request it makes comes here as a postMessage and is
// answered through the panel's API (read-only uci, file and rpc calls).

let catalog: Promise<Record<string, string>> | null = null
const i18n = () => (catalog ??= get<Record<string, string>>('/plugins/i18n').catch(() => ({})))

export function runLuciView(view: string, timeoutMs = 30000): Promise<FormBlock[]> {
  return new Promise((resolve, reject) => {
    const frame = document.createElement('iframe')
    frame.setAttribute('sandbox', 'allow-scripts')
    frame.style.display = 'none'
    frame.src = '/luci-sandbox.html'
    let done = false
    const finish = (err: Error | null, blocks?: FormBlock[]) => {
      if (done) return
      done = true
      window.removeEventListener('message', onMsg)
      clearTimeout(timer)
      frame.remove()
      if (err) reject(err)
      else resolve(blocks ?? [])
    }
    const reply = (id: number, result: unknown, error?: string) => frame.contentWindow?.postMessage({ reply: id, result, error }, '*')
    const onMsg = async (ev: MessageEvent) => {
      if (ev.source !== frame.contentWindow) return
      const m = ev.data as { wharf?: number; id?: number; kind?: string; payload?: Record<string, unknown>; result?: FormBlock[]; error?: string }
      if (!m || m.wharf !== 1) return
      try {
        switch (m.kind) {
          case 'ready':
            frame.contentWindow?.postMessage({ kind: 'run', payload: { view, i18n: await i18n() } }, '*')
            return
          case 'done':
            finish(m.error ? new Error(m.error) : null, m.result)
            return
          case 'uci':
            reply(m.id!, await get(`/plugins/uci?config=${encodeURIComponent(String(m.payload?.config ?? ''))}`))
            return
          case 'rpc':
            reply(m.id!, await post('/plugins/rpc', m.payload))
            return
          case 'file':
            reply(m.id!, await get(`/plugins/file?path=${encodeURIComponent(String(m.payload?.path ?? ''))}`))
            return
        }
      } catch (e) {
        if (m.id) reply(m.id, null, (e as Error).message)
      }
    }
    const timer = window.setTimeout(() => finish(new Error('插件页面加载超时')), timeoutMs)
    window.addEventListener('message', onMsg)
    document.body.appendChild(frame)
  })
}
