<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/wharf-logo/svg/readme-banner-dark.svg">
    <img alt="Wharf 码头" src="docs/brand/wharf-logo/svg/readme-banner-light.svg" width="640">
  </picture>
</p>

<p align="center">
  <b>给全家人和多位管理员一起用的 OpenWrt 控制面板：看得懂、管得住、查得清。</b><br>
  <a href="README.md">English</a> · 简体中文
</p>

<p align="center">
  <a href="https://github.com/wangsirco/wharf/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/wangsirco/wharf?color=2563eb"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2563eb"></a>
  <img alt="OpenWrt 22.03+" src="https://img.shields.io/badge/OpenWrt-22.03%2B-1d5fe0">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.27%2B-00ADD8">
</p>

---

OpenWrt 很强，但 LuCI 只适合「一个懂网络的人」。**Wharf（码头）** 把你的 OpenWrt / iStoreOS 路由器，变成一家人、几位管理员都能放心使用的控制面板：

- **看得懂**：每台设备都有名字和类型；每台设备在访问什么（视频、AI、游戏……）、流量飞向哪些国家，一目了然。
- **管得住**：把一个端口段或某台设备交给朋友管理，不用给他 root 密码；他做的每一步都有审计、可以一键还原。
- **查得清**：路由追踪地图、抓包自动诊断、定时监控与告警、局域网扫描。网络出问题时，证据可以直接交给运营商。

Wharf 以 LuCI 插件形式安装在路由器上，只用 OpenWrt 原生机制（防火墙转发、ipset、dnsmasq、conntrack），**从不重启网络**。

> **项目状态：** 持续开发中，作者每天在 iStoreOS 22.03 x86_64 路由器上使用。界面目前为简体中文，欢迎贡献英文界面翻译。

## 功能

| | |
|---|---|
| **概览与大屏** | WAN 实时网速、谁在线、今日流量去向、最近事件（新设备、离开 / 回家、断网、拒绝访问、审批） |
| **简要模式** | 给家人看的设备墙，没有任何开关，不会误操作 |
| **设备** | 自动识别品牌 / 类型 / 系统，PVE 虚拟机名称，别名与备注，在线 / 离开 / 回家判断，静态 IP 绑定 |
| **设备画像** | 实时网速、时段热力图、按大类 → 服务 → 公司的流量去向（约 290 个服务）、国家、DNS 记录、未知目标识别 |
| **流量与全球地图** | 设备排行、全家流量去向、全球流量飞线地图（24 小时 / 7 天 / 30 天） |
| **DNS** | 查询趋势、拦截原因、热门域名、每台设备视角（dnsmasq 日志，或可选的 NextDNS API） |
| **端口转发** | 按国家 / IP 段限制来源、黑名单、按管理员分配端口段、冲突检查、多 WAN 绑定；**用量分析**：服务识别（SSH、HTTPS、RDP……）、谁连了它、扫描与暴力破解识别、正在连接 |
| **设备管控** | 一键断网、按服务或域名的黑白名单、定时断网、禁止访问路由器端口、强制使用路由器 DNS |
| **网络工具** | 路由追踪（地图 + 每跳运营商）、TCP Ping、DNS 对比、网站访问分段计时、浏览器 / iperf3 内网测速、**定时监控（告警 + CSV 导出）**、局域网扫描、**专业抓包与自动诊断**（可下载 pcap）、网络唤醒、UPnP、自定义解析 |
| **系统维护** | CPU / 内存 / 磁盘 / 温度、插件服务、日志、定时重启、配置备份与还原、**依赖组件管理** |
| **多管理员** | 超级管理员与普通管理员、12 项细分权限、配额、端口段授权、审批流程、完整审计与一键还原 |
| **安全** | 面板访问控制（内网设备 / 国家 / IP）、浏览器时区校验、访问记录（ASN、代理识别）、本地 CA 证书、登录限速、签名的 agent API |
| **告警** | Telegram、Server 酱：新设备、WAN 掉线、设备离线、流量突增、拒绝访问、待审批、监控异常 / 恢复 |
| **在线更新** | 从 GitHub Release 获取并校验签名，**按组件更新**：网页界面热更新无需重启，程序核心通过 opkg 更新 |
| **细节** | 首次登录向导、自定义面板名称、可安装为手机 App（PWA）、手机窄屏适配、深色模式、⌘K 全局搜索 |

## 安装

**系统要求**
- OpenWrt 22.03 及以上。fw3 / iptables 已充分验证；fw4 / nftables 系统尚未测试。
- 内存建议 512 MB 以上。
- 支持的架构：`x86_64`、`aarch64`、`arm`（cortex-a7）。暂不支持 MIPS（内置 SQLite 不支持 32 位 MIPS，这类路由器内存通常也不够）。

**步骤**
1. 在[最新 Release](https://github.com/wangsirco/wharf/releases/latest) 下载 `luci-app-wharf_<版本>-1_<架构>.ipk`。
2. 上传到路由器后安装：
   ```sh
   opkg install /tmp/luci-app-wharf_*.ipk
   ```
3. 打开 LuCI「服务 → Wharf 码头」，可以看到面板地址（默认 `https://路由器IP:7080`）。点「重置超级管理员密码」，获取 `admin` 账户的密码。
4. 登录后会出现首次向导，可以给面板起名、选择简要或专业模式，并一键安装缺少的组件。

**证书提示：** 面板使用自己的本地证书，每台设备第一次访问时浏览器会提示「不安全」。在登录页点「安装面板证书」，每台设备装一次即可。这张证书只能用于内网地址和 `.lan` 这类本地域名，不能用来冒充任何公网网站。

**升级：** 在「系统设置 → 版本与更新」在线更新，或手动 `opkg install` 新版本的 ipk（不要加 `--force-reinstall`）。

**卸载：** 执行 `opkg remove luci-app-wharf`。
- 会清除：Wharf 的防火墙链、ipset、DNS 日志设置，以及由 Wharf 自己安装的软件包。
- 会保留：你的端口转发规则和面板数据目录。

## 依赖组件

Wharf 没有强制的软件包依赖。缺少某个组件时，对应功能的页面会提示，超级管理员可以在「系统维护 → 依赖组件」里一键安装。由面板安装的包会被记录下来，卸载 Wharf 时一并移除；你原本就有的包不会被动到。

| 组件 | 软件包 | 用途 |
|---|---|---|
| conntrack、连接字节统计、ipset | `conntrack`、内核开关、`ipset` | 流量分析、端口转发规则、设备管控（核心） |
| tcpdump · mtr · iperf3 · dig · curl | `tcpdump`、`mtr-json`、`iperf3`、`bind-dig`、`curl` | 抓包、路由追踪、测速、DNS / 网站测试 |
| ip-full · etherwake · miniupnpd | `ip-full`、`etherwake`、`miniupnpd-*` | 在线判断、网络唤醒、UPnP |

DNS 统计使用 dnsmasq 自带的查询日志，不需要 SmartDNS、AdGuard Home 或 dnsmasq-full。

## 工作原理

```
 浏览器 / 手机 ──HTTPS──▶ owp-panel（Go + SQLite，内嵌 React 界面）
                               │  HMAC 签名 API（127.0.0.1:7071）
                               ▼
                        owp-agent（uci、防火墙、conntrack、dnsmasq 日志、诊断工具）
                               │
                               ▼
                        OpenWrt（firewall、ipset、dnsmasq、conntrack、opkg）
```

面板也可以部署在 VPS 上，路由器只运行 agent（HTTPS + 证书指纹固定 + 来源白名单）。内部名称（`owp-agent`、`owp-panel`、uci `owp*`）为了兼容而保留。

## 文档

- 📖 [完整使用手册](docs/MANUAL.md)：每个页面的说明、权限、安全设计、Wharf 会改动路由器的哪些地方、数据保留期限、命令行、常见问题
- 🎨 [品牌资源](docs/brand/wharf-logo/)
- 🧩 [界面组件说明](docs/UI-KIT.md)

## 从源码构建

```sh
git clone https://github.com/wangsirco/wharf && cd wharf
cd web && npm ci && npm run build && cd ..
go test ./internal/...
scripts/build-ipk.sh x86_64        # → dist/luci-app-wharf_<版本>-1_x86_64.ipk
```

需要 Go 1.27+ 和 Node 22+。发布用 `scripts/release.sh`：一次构建全部架构，并为更新清单签名。

## 隐私

- 所有数据都只保存在你的路由器上。
- 流量分析只使用连接元数据（地址、端口、字节数）和 DNS 查询，不解密任何内容。
- 抓包是单独的权限，全程审计。
- Wharf 只在这些情况联网，而且都可以关闭：
  - IP 库和规则库的每月更新
  - 检查新版本
  - 你自己开启的 NextDNS、Proxmox、测速

## 参与贡献与安全

欢迎提 Issue 和 PR，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## 致谢

- IP 地理数据：[DB-IP](https://db-ip.com)（CC BY 4.0）
- 内容识别规则：[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)
- 地图数据：Natural Earth（world-atlas）
- 界面：React、Tailwind CSS、shadcn/ui、Base UI、ECharts、Lucide

Wharf 由 [iWSheng](https://github.com/wangsirco) 与 Claude（Anthropic）共同设计开发。

## 许可

[MIT](LICENSE)
