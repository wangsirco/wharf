# Changelog · 更新日志

## 0.25.0 — One name at home, Berth v3 · 内网名字不带端口、Berth 互联 v3

- https://wharf.lan without a port: the router's LAN 443 is shared — Wharf's names go to the panel, everything else (LuCI by IP) stays with LuCI (agent splitter, firewall redirect owp_lan443); the LAN name can be renamed; opened by IP or an old name, the panel moves to the LAN name when the device can open it · 内网名字不带端口、可改名、自动转到主名字
- Settings → Access addresses (LAN / public / fallback, certificate steps per system) and a wizard step, on by default · 「访问地址」卡片和向导一步
- Berth v3 (docs/BERTH.md §9): names endpoint, LAN or public link chosen at pairing and switchable without pairing again (no silent switching, errors by step), single sign-on to the right name with a chooser when unsure, read-only statistics for Berth's overview (scope stats), visitor log filters by country and period · Berth v3：名字、内网 / 公网互联、打开时判断在家在外、统计给 Berth
- Pages take filters from the address (/visitors?cc=, /world?range=, /dns?range=, /traffic?range=, /devices?q=) · 页面支持地址里的筛选参数
- Remote access: four ways (direct, Cloudflare Tunnel, Tailscale, LAN only) with the line's verdict; the tunnel from token to open in one card, one button, undone on failure, stopped in one step · 外网访问四种方式，隧道在卡片里一键开放 / 停止
- Cloudflare Access on Wharf's names lets Berth's signed calls through (Bypass on /api/ext/berth/); Access in front of Berth is reported as such · Access 放行面板接口，被 Access 拦时说清楚
- Passkeys follow names: clear message instead of a dead end when an account's passkey is on another name, a banner to add one here, a one-time link to carry the sign-in to another name · Passkey 跟着名字走
- Fixes: a resource leak behind the LAN 443 splitter took the panel's names down (keep-alive connections never closed); listeners no longer stop on accept errors; timeouts on every server; bounded login limiter; time limits on opkg · 修复 443 分流背后的连接泄漏等

## 0.24.0 — Berth pairing v2, verdict line, settings tabs, phones · Berth 互联 v2、一句话结论、设置分类、手机

- Berth pairing v2 (docs/BERTH.md §8): LAN discovery — Berth asks, the admin allows here after comparing a six-digit code (LAN sources only, a 10-minute window, identity confirmed again); the pairing page explains the LAN address with Wharf's fingerprint and public names with their public certificate; several Berth addresses, LAN first, switched automatically when one fails; signed requests carry a token id instead of the token once Berth supports it; link status with LAN / Tailscale / public (direct, Cloudflare, CloudFront, Fastly, proxy), latency, jitter, peer address and country; new scope to register `.lan` names for Berth in the router's DNS · Berth 互联 v2：内网发现绑定、两种证书说明、多地址自动切换、签名不带令牌、互联状态、登记 .lan 名字
- Overview starts with a verdict: all fine, or the most pressing problem (internet down, NextDNS not running, DDNS failing, certificate expiring, approvals, Berth link, plugins to re-import) with a link · 概览一句话结论
- Settings in four tabs; search finds settings and opens the section · 系统设置分 4 个标签，搜索能直接搜到设置项
- Errors in plain words with the next step; a router that is busy restarting is retried automatically · 出错说人话并自动重试
- Phones: tables become cards; a bottom bar with overview, devices, cut off, refresh DNS, Berth · 手机上表格变卡片，底部常用操作栏
- Fixes: the overview no longer fails as a whole when the router leaves fields out; the plugin card's import button no longer wraps · 修复概览在数据不全时整页报错、插件卡片「导入」按钮换行

## 0.23.0 — Remote access in one place, menu groups, undo · 外网访问、菜单分组、撤销

- Remote access page: how the panel is reachable from outside right now, the three ways (Cloudflare Tunnel / orange cloud / direct) with the one that suits the line (from the public address check), the panel's names, and who may come in (access control, Cloudflare Access). Panel names moved here from Settings · 外网访问页
- Menu in groups: home network, control, tools, router, management, links; "DNS 拦截" is now "NextDNS 统计", linked both ways with DHCP / DNS; search finds the new pages and DNS cache · 菜单分组与改名
- Undo: after saving a change that can be restored, a toast offers to take it back (the author, within two minutes) · 保存后可一键撤销

## 0.22.0 — Cloudflare, Berth, page contents, proxy usage · Cloudflare、Berth、页内目录、代理用量

- Cloudflare page: a token in two steps with every permission explained and checked; Cloudflare Tunnel (cloudflared from Cloudflare's releases, run as nobody; the panel and home services published without opening a port, visitor addresses trusted through a socket only cloudflared can open); domains with attack mode, cache purge and a week of edge statistics; Access email codes in front of the panel. Other tools' objects in the same account (Berth's) are read-only · Cloudflare 独立菜单：隧道、防攻击、Access
- Berth entry page: what it is, where to get it, pairing in three steps; once paired, open it without signing in · Berth 入口页
- Page contents on long pages (right-hand list on wide screens, chips under the top bar elsewhere) · 长页面的本页目录
- Proxy usage for any period per node and per user (last hours, days, months, since creation, chosen dates), busiest hour or day, who used it; lifetime totals in the lists · 代理按任意时段查看用量
- Setup wizard asks where the panel is opened from and ends with the next useful things · 设置向导

## 0.21.1 — DNS cache and troubleshooting · DNS 缓存与排查

- DHCP / DNS page: the resolver chain with cache sizes and hit rate; look a name up through every layer (dnsmasq, NextDNS on the router, NextDNS cloud, 1.1.1.1, the authoritative servers) to see which one is stale — a cached "does not exist", an old address, the NextDNS cloud, rebind protection (allow in one click), a NextDNS block, or no such record · 逐层查询，指出卡在哪一层
- Refresh DNS cache: dnsmasq (without interruption) and NextDNS (restart, about a second); audited · 一键刷新 DNS 缓存
- NextDNS maximum cache age (1 min – 1 h, 15 min as a middle ground; default unchanged), so new records need not wait for the zone's 30-minute negative TTL · NextDNS 缓存最长保留
- Fix: the users page crashed ("Cannot read properties of null (reading 'login_mode')") · 修复「用户与权限」页报错

## 0.21.0 — Public address check, plugin import · 公网检测、插件导入

- Public address check on the interfaces page: lookup services asked through the WAN are compared with the WAN address, and the hop beyond a modem is classified, to tell a real public IP from a modem in front, a proxy exit or carrier-grade NAT; with what to do next — set up DDNS (opens prefilled; existing records pointing here are listed), bridge / DMZ, ask the ISP, IPv6 + DDNS or a tunnel · 公网检测：外部确认是否真公网，给出 DDNS 等下一步建议
- Plugin import: plugins are split into "managed by Wharf" and "OpenWrt plugins"; importing converts every settings page once and keeps the structure (no values) on the panel, so pages open at once with current settings and refresh quietly in the background; plugins installed from the store are imported right away; re-import after an upgrade, un-import any time · 插件导入：一次转换全部设置页，之后打开即用
- Fix: an open plugin page no longer re-converts every 20 seconds · 修复插件页面每 20 秒重新转换一次

## 0.20.0 — Interfaces, DHCP / DNS, firewall and plugins · 网络接口、DHCP / DNS、防火墙与插件

- Network interfaces page: online state and public IP (direct / behind a modem / CGNAT), a card per LAN / WAN / WAN6 / extra interface with addresses, link, traffic, zone and mwan3 state; restart, stop, edit (DHCP, static, PPPoE, DHCPv6 …), add WAN2 or delete; physical ports and outage history · 网络接口页：公网 IP、各接口状态、重启与设置
- Apply-then-confirm for interface and firewall changes: kept only when confirmed within 90 s (4 min for a new LAN address), otherwise — or after a restart in between — the router restores the previous configuration · 接口 / 防火墙改动不确认就自动恢复
- Outage diagnosis (cable → address → ISP gateway → internet → DNS → web, with a verdict: home, account, ISP or DNS / proxy) and a red "外网断了" bar on every page · 断网诊断与全局断网提示
- DHCP and DNS page: pools, upstream DNS (recognises NextDNS, SmartDNS, OpenClash …), rebind protection, static leases with clash checks, current leases · DHCP 与 DNS 页
- Firewall page: defaults, zones and zone forwarding, traffic rules; clean-up of zones listing missing interfaces; Wharf's own rules read-only · 防火墙页
- Plugins: every installed LuCI app with state, processes and ports (open a port to the WAN in one click), warnings for clashing proxy / DNS plugins; each plugin's settings pages redrawn in Wharf's design and editable — Lua pages via LuCI's own parser, JavaScript pages in a sandbox · 插件兼容层：插件设置页换成 Wharf 样式
- Plugin store on the router's opkg feeds with a dry-run compatibility check (dependencies, architecture, space, clashes) before installing · 插件商店，安装前检查兼容性
- New permissions `network.view`, `network.manage`, `firewall.manage`, `plugins.view`, `plugins.manage`, `plugins.install` · 新权限可单独授予

## 0.19.0 — Berth integration · 与 Berth 泊位联动

- Pairing with Berth (the server panel of the same series): the super admin agrees on Wharf to the scopes, lifetime and Berth host(s); both sides then hold a token for the other, every call is signed (time window, nonce) and pinned to the certificate fingerprint taken at pairing. Narrow scopes, rotate tokens or unpair (keep or delete Berth's mappings) under Settings → 集成. Protocol in docs/BERTH.md · 与 Berth 配对，签名对接通道
- Berth creates, changes and removes its own port mappings on its hosts (with a dry-run preview); they carry a Berth badge that opens the site in Berth; admins see them read-only, a super admin's change is reported back · Berth 管理自己的端口映射，带徽标
- 443 by name: Berth registers its domains with the SNI front, passed through untouched (optionally with PROXY protocol); proxy nodes and the panel's names keep priority; `*.zone` names supported · 443 分流可登记 Berth 的域名
- DDNS: one side keeps each name; Berth can ask Wharf to keep a new name with the account of the same zone; names both sides update are flagged for a choice · DDNS 由一方维护
- External bans dropped at the WAN (router and forwards, LAN unaffected), from Berth or made here, optionally synced to Berth per ban; a ban button in a forward's connection list · 外部封禁与封禁同步
- One main notifier for alerts (Wharf or Berth), deduplicated; sign-in without a password in both directions via one-time tickets and a Berth → Wharf user mapping; Berth hosts tagged on the device pages with their sites, containers and VMs; audit filter for Berth · 主通知方、互相免登录跳转、设备页 Berth 标签页

## 0.18.3 — Cloudflare account, public panel access, clearer alerts · Cloudflare 账户、面板公网访问、告警排版

- Cloudflare account for DDNS: one-click token page with the permissions chosen, then pick a domain, add or take over records; plans plus custom check / forced-refresh intervals (up to 7 days) · DDNS 连接 Cloudflare 账户，快速方案与自定义
- Public panel access on several names: through the 443 SNI front (real visitor IP via PROXY protocol, access control applies) and / or the panel port; one Let's Encrypt certificate for all names; one-click DDNS for a name · 面板公网访问（443 或独立端口，多个域名）
- Panel names behind Cloudflare's orange cloud: an Origin Rule sends them to the panel port (open to Cloudflare only), Cloudflare gets the origin certificate (pasted or a 15-year one from the API), home devices the Let's Encrypt one · 面板域名可走 Cloudflare 橙色云，用源服务器证书
- Alerts: icon per kind, device names in bold, one block per device; devices arriving together within a few minutes come as one message · 告警排版与合并
- Sign-in per user, chosen in account security or the first-login wizard: password or passkey, password + passkey (two-step), or passkey only; the login page always offers both, and a passkey-only account answers a correct password like a wrong one. Weakening a strict mode needs a fresh proof; a super admin reset or `reset-super` restores the password · 每个账号可选登录方式：密码或 Passkey、密码 + Passkey、只用 Passkey
- Fix: the sidebar scrolls on its own · 修复侧边栏不能单独滚动

## 0.18.2 — passkeys and device recognition · Passkey 登录与设备识别

- Passkey sign-in (Face ID / fingerprint / security key) next to the password, on the local name wharf.lan or an optional public name with a Let's Encrypt certificate (Cloudflare DNS challenge) · Passkey 登录；本地域名 wharf.lan 与可选公网域名 + Let's Encrypt
- Device recognition by DHCP fingerprint, mDNS (names, models, services; sleep-proxy answers for sleeping iPhones) and UPnP; private-MAC phones show their system and maker, TVs / printers / consoles their model · 按 DHCP 指纹、mDNS、UPnP 识别设备
- Alerts state times with the time zone (new setting, the router's by default); device left / came back give leave and return times, model, system, IP and MAC; Telegram titles in bold · 告警写明时间与时区，离开 / 回来消息更完整
- Fix: adding a Telegram channel always failed with "格式不正确" (the Chat ID never reached the server). The Chat ID can now be left empty and is found from the bot's messages; the token may be pasted with a "bot" prefix or as a whole API address, and is checked with Telegram · 修复 Telegram 渠道总提示格式不正确；Chat ID 可自动获取

## 0.18.1 — sharper alerts and device status · 告警与设备状态细化

- Every alert has its own switch (DDNS, monitors, proxy users, proxy certificates were always on) · 每类告警都能单独开关
- Traffic-spike alerts per hour or per day, per-device thresholds and exclusions · 流量异常：按小时 / 天、单设备阈值、排除设备
- New-device alerts recognise phones that switched to a new private MAC; optional ignore of randomised MACs · 新设备告警识别换了私有 MAC 的已知设备
- Single WAN line down / back alerts and events with several lines · 多线路时单条线路掉线 / 恢复提醒与事件
- Device list separates "not responding" from "left"; dashboard events filter by type and show more · 设备列表区分「暂时无响应」和「已离开」；最近事件可筛选
- Proxy early warnings: 80 % traffic, expiring within 3 days, certificates not renewing · 代理提前提醒
- Blocking a device states that only the internet is cut; optional "also block the router" · 断网写清只断外网，可选同时禁止访问路由器
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
