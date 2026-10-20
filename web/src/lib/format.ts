export function bytes(n: number, digits = 1): string {
  if (!isFinite(n)) return '–'
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let i = 0
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return `${n.toFixed(i === 0 ? 0 : digits)} ${u[i]}`
}

export function bitrate(bytesPerSec: number): string {
  let n = bytesPerSec * 8
  const u = ['bps', 'Kbps', 'Mbps', 'Gbps']
  let i = 0
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++ }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${u[i]}`
}

export function duration(sec: number): string {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60)
  if (d > 0) return `${d} 天 ${h} 小时`
  if (h > 0) return `${h} 小时 ${m} 分`
  return `${m} 分钟`
}

export function datetime(ts: number): string {
  if (!ts) return '–'
  const d = new Date(ts * 1000)
  const p = (x: number) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export function ago(ts: number): string {
  if (!ts) return '从未'
  const s = Math.floor(Date.now() / 1000 - ts)
  if (s < 60) return '刚刚'
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`
  return `${Math.floor(s / 86400)} 天前`
}

export function utcOffset(min: number | null): string {
  if (min === null || min === undefined) return '–'
  const sign = min >= 0 ? '+' : '-'
  const a = Math.abs(min)
  return `UTC${sign}${String(Math.floor(a / 60)).padStart(2, '0')}:${String(a % 60).padStart(2, '0')}`
}
