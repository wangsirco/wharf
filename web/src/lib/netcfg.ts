// Shared types and labels for the network settings pages.

export interface Pending { token: string; configs: string[]; deadline: number; started: number; summary?: string }

export interface NetHealthResp {
  internet?: boolean; checked?: boolean; down_since?: number; gateway?: string; gateway_ok?: boolean; ts?: number
  wans: { up: boolean; proto: string; device: string; uptime: number; ipv4: string; gateway: string; interface: string }[] | null
  pending?: Pending | null
  rollback?: { at: number; why: string; configs: string[] } | null
}

export interface IfaceStat {
  name: string; proto: string; device: string; l3_device: string; up: boolean; pending: boolean; available: boolean; autostart: boolean
  uptime: number; metric: number; ipv4: string[] | null; ipv6: string[] | null; prefix6: string[] | null; gateway?: string; gateway6?: string
  dns: string[] | null; errors?: string[] | null; config: Record<string, unknown> | null
  zones?: string[] | null; role: 'lan' | 'wan' | 'wan6' | 'other'; public?: { ip: string; kind: 'direct' | 'nat' | 'cgnat' }
}

export interface NetLink {
  name: string; type: string; mac?: string; present: boolean; up: boolean; carrier: boolean; speed?: number; duplex?: string; mtu?: number
  members?: string[] | null; bridge?: string; physical: boolean; rx: number; tx: number; rx_errors: number; tx_errors: number; driver?: string
}

export interface DiagStep { id: string; label: string; status: 'ok' | 'warn' | 'fail' | 'skip'; detail: string; ms: number }
export interface WanDiag { iface: string; at: number; steps: DiagStep[]; who: string; verdict: string; advice: string }

export const protoLabels: Record<string, string> = {
  static: '静态地址', dhcp: 'DHCP 自动获取', pppoe: 'PPPoE 拨号', dhcpv6: 'DHCPv6', none: '不配置地址（仅桥接）',
  wireguard: 'WireGuard', '6in4': '6in4 隧道', '6to4': '6to4 隧道', '6rd': '6rd 隧道', dslite: 'DS-Lite', l2tp: 'L2TP', pptp: 'PPTP',
  qmi: '4G / 5G（QMI）', ncm: '4G / 5G（NCM）', mbim: '4G / 5G（MBIM）', '3g': '3G 拨号', modemmanager: '4G / 5G（ModemManager）', relay: '中继桥',
  gre: 'GRE 隧道', gretap: 'GRETAP', vxlan: 'VXLAN', openvpn: 'OpenVPN', zerotier: 'ZeroTier', batadv: 'B.A.T.M.A.N.',
}
export const protoLabel = (p: string) => protoLabels[p] ?? p

export const roleLabel = { lan: '局域网 LAN', wan: '外网 WAN', wan6: '外网 IPv6', other: '其他' } as const

// pages tell the banner to refresh right after a guarded change
export const netChanged = () => window.dispatchEvent(new Event('owp:net-changed'))
