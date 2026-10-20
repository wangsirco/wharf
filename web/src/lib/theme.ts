export type Theme = 'light' | 'dark' | 'system'

export function getTheme(): Theme {
  try { return (localStorage.getItem('owp-theme') as Theme) || 'system' } catch { return 'system' }
}

export function applyTheme(t: Theme) {
  try { localStorage.setItem('owp-theme', t) } catch { /* private mode */ }
  const dark = t === 'dark' || (t === 'system' && matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.classList.toggle('dark', dark)
}
