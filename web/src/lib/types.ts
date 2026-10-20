export type Role = 'super' | 'admin'

export interface User {
  id: number
  username: string
  display_name: string
  role: Role
  perms: string[]
  quotas: Record<string, number>
  grants?: ForwardGrants
  disabled: boolean
  created_at: number
  updated_at: number
  last_login_at: number
}

export interface PermDef { key: string; group: string; label: string; desc: string }
export interface QuotaDef { key: string; label: string; default: number }
export interface ActionDef { key: string; label: string; perm: string }
export interface Meta { permissions: PermDef[]; quotas: QuotaDef[]; actions: ActionDef[] }

export interface IfStat { name: string; rx_bytes: number; tx_bytes: number; rx_packets: number; tx_packets: number }
export interface SystemInfo {
  hostname: string; release: string; kernel: string; model: string; firewall: string
  uptime: number; load: number[]; mem_total: number; mem_available: number
  conntrack: number; conntrack_max: number; wan_ifname: string; lan_ifname: string
  ifaces: IfStat[]; time: number
}

export interface Device {
  mac: string; ip: string; hostname: string; static_name: string; lease_expiry: number
  neigh_state: string; online: boolean; last_seen?: number; static: boolean; static_id?: string
  owner_id?: number; owner_name?: string; editable: boolean
  name: string; alias: string; note: string; type: string; os: string; vendor: string; type_by: string; random_mac: boolean; vm_tag?: string; guest_name?: string
  first_seen: number; is_new: boolean; controlled: boolean; blocked: boolean; blocked_by: string
}

export interface AuditEntry {
  id: number; ts: number; user_id: number; username: string; ip: string; action: string
  target_type: string; target_id: string; summary: string
  before: unknown; after: unknown; approval_id: number | null
  restorable: boolean; restored_by: number | null; restored_at: number | null; restore_of: number | null
}

export interface Approval {
  id: number; ts: number; user_id: number; username: string; ip: string; action: string
  summary: string; status: 'pending' | 'approved' | 'rejected' | 'expired' | 'failed'
  decided_by: number | null; decided_at: number | null; note: string; result: string
}

export interface Visitor {
  id: number; ts: number; user_id: number | null; username: string; ip: string
  asn: number; as_org: string; country: string; region: string; city: string
  ip_tz: string; ip_offset: number | null; client_tz: string; client_offset: number | null
  client_time: string; tz_match: 'match' | 'mismatch' | 'unknown'; user_agent: string; path: string
  blocked: boolean; reason: string; mac: string; ipsb: string; ipsb_match: '' | 'same' | 'diff'
}

export interface IPSB { ip: string; asn: number; asn_organization: string; isp: string; country_code: string; country: string; region: string; city: string; timezone: string; offset: number }

export interface Forward {
  id: string; rev: string; name: string; proto: string; wan_port: string; wan: string; lan_ip: string; lan_port: string
  enabled: boolean; managed: boolean; device_name: string; device_now?: string; vm_tag?: string; online?: boolean; device_mac: string; note: string
  mode: 'all' | 'restrict'; regions: string[]; allow: string[]; deny: string[]
  owner_id: number; owner_name: string; editable: boolean; created: number
}

export interface PortGrant { wan: string; from: number; to: number }
export interface ForwardGrants { ports: PortGrant[]; lan: string[] }
export interface WanInfo { interface: string; device: string; ipv4: string; up: boolean; proto: string }
export interface PortIssue { level: 'error' | 'warn'; msg: string }
export interface PortsInfo {
  wans: WanInfo[]
  used: { port: number; to?: number; proto: string; wan: string; mine: boolean; enabled: boolean; label?: string }[] | null
  router: { port: number; proto: string; proc: string }[] | null
  restricted: boolean; lan_restricted: boolean; lan: string[]
  grants: (PortGrant & { free: number; next: number })[]
  allocations?: (PortGrant & { user_id: number; user: string })[]
  suggest?: PortGrant
  check?: { port: number; ok: boolean; issues: PortIssue[] }
}

export interface ForwardTarget { ip: string; mac: string; name: string; hostname?: string; type?: string; vendor?: string; vm_tag?: string; note?: string; online: boolean; static?: boolean }
export interface RegionInfo { code: string; name: string; name_en: string; regions: string[] | null }

export interface ActionResult { ok?: boolean; pending?: boolean; approval_id?: number; message?: string; result?: unknown }

export interface LiveHost { mac: string; ip: string; up: number; down: number; up_total: number; down_total: number; last_seen: number }
export interface Agg { name: string; category?: string; sub?: string; company?: string; guess?: boolean; uncertain?: boolean; bytes: number; up: number; down: number; requests: number; conns: number }
export interface TrafficResp {
  from: number; to: number; step: number; series: { t: number; up: number; down: number }[]
  up: number; down: number; heatmap: number[][]; by_hour: number[]; peak_hour: number; services: Agg[] | null; categories: Agg[] | null
}
export interface DomainRow { nextdns?: { status: string; reasons: string; tracker: string }; domain: string; service: string; category: string; sub: string; guess: boolean; uncertain: boolean; company: string; requests: number; blocked: number; bytes: number; last_seen: number }
export interface Probe { target: string; domain: string; status: 'ok' | 'failed'; summary: string; detail: string; ts: number }
export interface RemoteRow {
  ip: string; port: number; proto: string; inbound: boolean; service: string; category: string; company: string
  sub: string; guess: boolean; uncertain: boolean
  by: string; country: string; as_org: string; bytes: number; conns: number; probe?: Probe
}
export interface ProfileResp {
  from: number; to: number; requests: number; blocked: number; bytes: number
  categories: Agg[]; categories_by_req: Agg[]; subcategories: Agg[]; subcategories_by_req: Agg[]; services: Agg[]; services_by_req: Agg[]; companies: Agg[]; countries: Agg[]
  domains: DomainRow[]; remotes: RemoteRow[]; requests_by_hour: number[]; summary: string[] | null; rules_version: string
}
export interface ServiceInfo { n: string; c: string; s?: string; o: string }
export interface Catalog { categories: string[]; companies: string[]; version: string; services: ServiceInfo[] | null; updated_at: string }

export interface PolicySchedule { days: number[]; start: string; end: string }
export interface DevicePolicy {
  mac: string; name: string; block: boolean; mode: 'none' | 'blacklist' | 'whitelist'; targets: string[]
  schedules: PolicySchedule[]; captive: boolean; force_dns: boolean; router_ports: string[]
  exists: boolean; owner_id: number; owner_name: string; editable: boolean
  status: { blocked: boolean; reason: string } | null
}

export interface Overview {
  today: { up: number; down: number; dns_requests: number; dns_blocked: number }
  devices?: { online: number; total: number; new_24h: number; controlled: number; blocked: number }
  approvals_pending?: number; visitors_denied_24h?: number; services_today?: Agg[] | null; categories_today?: Agg[] | null
}
export interface OwpEvent { ts: number; kind: string; level: 'info' | 'warn' | 'alert'; title: string; detail?: string; mac?: string; link?: string }

export interface SimpleDevice { mac: string; up: number; down: number; categories: Agg[] | null; services: Agg[] | null; now: Agg[] | null }

export interface NetPoint { t: number; avg: number; max: number; loss: number; jitter: number }
export interface NetTarget { target: string; points: NetPoint[] | null; avg: number; loss: number; now: number }
export interface WanInfo { up: boolean; proto: string; device: string; uptime: number; ipv4: string; gateway: string; dns: string[] | null; ipv6: string[] | null; interface: string }
export interface SpeedRow { ts: number; down_mbps: number; up_mbps: number; latency_ms: number; server: string; error?: string; username?: string }
export interface NetworkResp {
  from: number; to: number; step: number; wan?: { wan: WanInfo; wan6?: WanInfo; mwan3?: unknown }
  targets: NetTarget[] | null; silent?: string[] | null; outages: { from: number; to: number; minutes: number }[] | null
  events: { ts: number; kind: string; detail: string }[] | null; speedtests: SpeedRow[] | null
}
