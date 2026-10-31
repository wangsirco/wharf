# Changelog · 更新日志

## Unreleased · 未发布

- Alerts: separate "device left" and "device came back" switches for selected or all devices, driven by the same presence tracking as the dashboard and grouped per minute; "WAN down" renamed to make clear it is the whole home's internet · 告警：设备离开 / 回来分开设置，可选设备或全部设备，同一分钟合并；「断网 / 恢复」明确为整个家的外网

## 0.18.0 — proxy extension and DDNS · 代理扩展与动态域名

- Optional proxy extension: official Xray-core installed online and run as nobody; VLESS / REALITY / Vision / XHTTP / Trojan / VMess / SS2022 / Hysteria 2 · 代理扩展
- Nodes linked to the firewall and port checks; shared 443 routed by SNI, optional takeover of an existing 443 forward; ACME certificates · 防火墙联动、443 分流、自动证书
- Proxy users with traffic limits, expiry, IP limits, subscriptions, QR codes; live dashboard, access records; `proxy.manage` permission · 代理用户、大屏、访问记录
- Dynamic DNS with 9 providers, multi-WAN, IPv6, CNAME to an existing dynamic name · 动态域名 DDNS（含 CNAME）
- Shared 443 next to an existing website forward: the forward stays untouched and the site keeps seeing real visitors (transparent hand-off); optional read-only 1Panel API link · 共用 443 不动原转发、网站仍见真实 IP；可连接 1Panel
- Shared port is configurable (443 by default; 8443 / 2053 … when the provider blocks 443) · 分流端口可自定义（运营商封 443 时可换端口）
- Shared port on fw4 / nftables systems too (own table `ip wharf_pxy`, not yet tested on hardware) · fw4 / nftables 系统也支持共用端口（尚未实机测试）
- A page that fails to render now shows the error (and logs it on the router) instead of a blank screen; fixed the proxy settings tab going blank before 1Panel was connected · 页面出错不再白屏；修复未连接 1Panel 时代理「扩展设置」白屏
- Fix: the panel could show "无法连接面板" on devices that do not trust its certificate (the service worker is retired) · 修复部分设备提示无法连接面板

## 0.17.0 — first public release · 首个公开版本

- Signed online updates from GitHub Releases, per component (web UI hot-swap, program via opkg) · 按组件的签名在线更新
- New logo and app icons · 全新 logo 与应用图标
- Optional dependency manager: install from the panel, removed again on uninstall · 依赖组件管理
- Port-forward usage analytics: service fingerprinting, who connected, scan / brute-force detection, live connections · 端口转发用量与连接分析
- Scheduled monitors with alerts and CSV export · 定时监控、告警、CSV 导出
- Packet capture with expert-style analysis, LAN scan · 抓包自动分析、局域网扫描
- Route trace on a map, TCP ping, DNS comparison, HTTP timing, browser / iperf3 speed tests · 路由追踪地图等诊断工具
- Local CA for HTTPS (fixes iOS home-screen app), HTTP → HTTPS redirect · 本地 CA 证书

## Earlier (0.1 – 0.16, private)

Multi-admin RBAC, audit with restore, approvals, port forwards with geo restriction and port-range grants, multi-WAN, traffic analytics and device profiles, world flow map, DNS / NextDNS, device controls, presence (left / back), alerts (Telegram / ServerChan), system maintenance, PVE integration, welcome wizard, PWA and phone layout.
多管理员权限、审计与还原、审批、地区限制的端口转发、端口段授权、多 WAN、流量分析与设备画像、全球流量地图、DNS / NextDNS、设备管控、上下线记录、告警、系统维护、PVE 集成、首次向导、PWA 与手机适配。
