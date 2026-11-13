// Installed plugin as returned by GET /api/plugins.
export interface PluginItem {
  pkg: string; version: string; desc: string; installed_at: number; size: number; title: string; luci_title: string; about: string; group: string; group_label: string
  covered: string; category: string; pages: { path: string; title: string; order: number; kind: string; target: string }[] | null
  services: { name: string; enabled: boolean; running: boolean }[] | null; configs: string[] | null; procs: { pid: number; name: string; exe: string }[] | null
  ports: { port: number; proto: string; bind: string; proc: string; local: boolean; wan_open?: boolean; wan_rule?: string }[] | null
  i18n: boolean; by_wharf: boolean; warnings: string[] | null; depends: string[] | null
  imported?: { version: string; at: number; ok: number; custom: number; failed: number } | null
}

export const pluginState = (p: PluginItem): [string, 'ok' | 'warn' | 'bad' | 'off'] => {
  const svcs = p.services ?? []
  if (!svcs.length) return ['无后台服务', 'off']
  if (svcs.some((s) => s.running)) return ['运行中', 'ok']
  if (svcs.some((s) => s.enabled)) return ['已启用但没在运行', 'warn']
  return ['已停止', 'off']
}
