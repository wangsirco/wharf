import { useEffect, useRef } from 'react'
import { toast } from 'sonner'
import { get, post } from '@/lib/api'

const LABELS: Record<string, string> = {
  'ui.name': '面板名称', 'ui.subtitle': '面板副标题', 'ui.timezone': '时区',
  'access.allow_ips': '允许的 IP', 'access.deny_ips': '拒绝的 IP', 'access.ipsb': '出口 IP 检查', 'access.lan.macs': '局域网设备名单',
  'access.lan.mode': '局域网访问方式', 'access.wan.mode': '公网访问方式', 'access.wan.regions': '允许的地区', 'access.wan.timezones': '允许的时区',
  'approval.expire_hours': '审批有效期', 'approval.forward_open_all': '端口全开需审批', 'approval.required': '需要审批的操作',
  'dns.source': 'DNS 数据来源', 'identity.dhcp_log': 'DHCP 指纹识别', 'identity.probe': '主动识别设备', 'nextdns.profile': 'NextDNS 配置',
  'presence.away_minutes': '离开网络判定', 'pve.url': 'PVE 地址', 'pve.fingerprint': 'PVE 证书指纹',
  'retention.audit_days': '审计保留天数', 'retention.traffic_days': '流量日志保留天数', 'retention.traffic_mb': '流量日志占用上限', 'retention.visitor_days': '访问记录保留天数',
  'rules.update_hours': '规则库更新间隔', 'update.check': '检查更新', 'update.repo': '更新来源', 'alerts.rules': '告警规则',
}
const human = (s = '') => s.replace(/^修改设置 (\S+)$/, (_, k: string) => `修改「${LABELS[k] ?? k}」`)

// After a change is saved, offer to take it back for a little while: the panel's audit
// log already knows how to restore it (only the author, within two minutes).
export function UndoWatcher() {
  const seen = useRef(new Set<number>())
  useEffect(() => {
    let timer = 0
    const check = async () => {
      try {
        const e = await get<{ id?: number; summary?: string }>('/audit/undo?since=0')
        if (!e.id || seen.current.has(e.id)) return
        seen.current.add(e.id)
        const id = e.id
        toast(`可以撤销：${human(e.summary)}`, {
          duration: 10000,
          action: {
            label: '撤销',
            onClick: async () => {
              try {
                await post(`/audit/${id}/undo`)
                toast.success('已撤销，正在刷新页面')
                setTimeout(() => window.location.reload(), 700)
              } catch (err) { toast.error((err as Error).message) }
            },
          },
        })
      } catch { /* not signed in, or the panel is restarting */ }
    }
    const onMut = () => { clearTimeout(timer); timer = window.setTimeout(check, 400) }
    window.addEventListener('owp:mutated', onMut)
    return () => { window.removeEventListener('owp:mutated', onMut); clearTimeout(timer) }
  }, [])
  return null
}
