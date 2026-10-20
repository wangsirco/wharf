package panel

// Permission catalog. Super admins implicitly hold every permission plus the
// super-only areas (users, audit, visitors, approvals, settings), which are
// never assignable to normal admins.
type PermDef struct {
	Key   string `json:"key"`
	Group string `json:"group"`
	Label string `json:"label"`
	Desc  string `json:"desc"`
}

var Permissions = []PermDef{
	{"dashboard.view", "概览", "查看概览", "系统状态、实时流量"},
	{"devices.view", "设备", "查看设备", "在线设备、IP、MAC、名称"},
	{"devices.manage", "设备", "管理设备", "设备命名、静态 IP 绑定（仅限自己创建的）"},
	{"forwards.view", "端口转发", "查看端口转发", "查看自己创建的端口转发"},
	{"forwards.manage", "端口转发", "管理端口转发", "新增/修改/删除自己创建的端口转发"},
	{"traffic.view", "流量分析", "查看流量与访问记录", "设备访问目标、统计、画像"},
	{"access.manage", "访问控制", "管理访问控制", "断网、黑白名单、定时断网"},
	{"system.view", "系统", "查看系统状态", "CPU / 磁盘、插件服务状态、系统日志、UPnP、自定义解析"},
	{"system.manage", "系统", "系统维护", "重启、定时重启、开关插件、UPnP、自定义解析（重启和开关插件需超级管理员批准）"},
	{"tools.wol", "工具", "网络唤醒", "向局域网设备发送唤醒包"},
	{"tools.diag", "工具", "网络诊断", "路由追踪、TCP Ping、DNS / HTTP 测试、内网测速（iperf3）、局域网扫描、定时监控"},
	{"tools.capture", "工具", "抓包", "在路由器上抓包、查看分析、下载 pcap（能看到通信内容，谨慎授予；每次操作都记入审计）"},
}

// Quotas assignable per admin. 0 = not allowed, -1 = unlimited.
type QuotaDef struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Default int    `json:"default"`
}

var Quotas = []QuotaDef{
	{"max_forwards", "最多端口转发条数", 5},
	{"max_static_hosts", "最多静态绑定条数", 10},
}

func validPerm(k string) bool {
	for _, p := range Permissions {
		if p.Key == k {
			return true
		}
	}
	return false
}

func (u *User) Can(perm string) bool {
	if u.Role == RoleSuper {
		return true
	}
	for _, p := range u.Perms {
		if p == perm {
			return true
		}
	}
	return false
}

// Quota returns the user's limit; super admins are unlimited.
func (u *User) Quota(key string) int {
	if u.Role == RoleSuper {
		return -1
	}
	if v, ok := u.Quotas[key]; ok {
		return v
	}
	for _, q := range Quotas {
		if q.Key == key {
			return q.Default
		}
	}
	return 0
}
