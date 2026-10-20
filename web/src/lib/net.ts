import type { NetTarget } from './types'

export const TARGET_NAME: Record<string, string> = { '1.1.1.1': 'Cloudflare', '223.5.5.5': '阿里 DNS', '8.8.8.8': 'Google' }
export const targetLabel = (t: string, gw?: string) => (t === gw ? `网关 ${t}` : `${TARGET_NAME[t] ?? t} ${t}`)

// quality grades a latency/loss pair the way a person would describe it.
export function quality(ms: number, loss: number): { label: string; tone: 'green' | 'amber' | 'red' } {
  if (loss >= 5 || ms === 0) return { label: loss >= 50 || ms === 0 ? '断网' : '不稳定', tone: 'red' }
  if (loss >= 1 || ms > 150) return { label: '一般', tone: 'amber' }
  if (ms > 60) return { label: '良好', tone: 'green' }
  return { label: '优秀', tone: 'green' }
}

// publicNow: the best current latency to a public target (gateway excluded).
export function publicNow(targets: NetTarget[] | null | undefined, gw?: string) {
  const pub = (targets ?? []).filter((t) => t.target !== gw && t.now > 0)
  if (!pub.length) return { ms: 0, loss: 100 }
  const best = pub.reduce((a, b) => (a.now < b.now ? a : b))
  return { ms: best.now, loss: Math.min(...pub.map((t) => t.loss)) }
}
