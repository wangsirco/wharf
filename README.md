<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/wharf-logo/svg/readme-banner-dark.svg">
    <img alt="Wharf 码头" src="docs/brand/wharf-logo/svg/readme-banner-light.svg" width="640">
  </picture>
</p>

<p align="center">
  <b>A multi-admin control panel for OpenWrt — see, share and secure your home network.</b><br>
  English · <a href="README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <a href="https://github.com/wangsirco/wharf/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/wangsirco/wharf?color=2563eb"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2563eb"></a>
  <img alt="OpenWrt 22.03+" src="https://img.shields.io/badge/OpenWrt-22.03%2B-1d5fe0">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.27%2B-00ADD8">
</p>

---

OpenWrt is powerful, but LuCI is built for one person who knows networking. **Wharf** turns your OpenWrt / iStoreOS router into something a whole household and several admins can use safely:

- **Understand it.** Every device has a real name and type. You can see what each one talks to (video, AI, games …) and which countries your traffic flies to.
- **Share it.** Hand a friend a port range or a single device to manage without giving away the root password. Everything they do is audited and can be undone.
- **Fix it.** Route tracing on a map, packet capture with an automatic diagnosis, scheduled probes with alerts, and a LAN scan. The evidence is ready to send to your ISP.

Wharf runs on the router itself as a LuCI package, uses only native OpenWrt mechanisms (firewall redirects, ipset, dnsmasq, conntrack), and never restarts your network.

> **Status:** actively developed, in daily use on an iStoreOS 22.03 x86_64 router. The UI is currently in Simplified Chinese. English UI translation is welcome — see [Contributing](CONTRIBUTING.md).

## Features

| | |
|---|---|
| **Dashboard & big screen** | Live WAN speed, who is online, today's traffic by category, recent events (new device, left / came home, WAN down, denied logins, approvals) |
| **Simple mode** | A device wall for family members. No switches, nothing to break |
| **Devices** | Brand / type / OS detection, Proxmox VM names, aliases and notes, reliable online / away / back tracking, static leases |
| **Device profile** | Real-time speed, hourly heatmap, traffic by category → service → company (≈290 services), countries, DNS requests, unknown-target probing |
| **Traffic & world map** | Per-device ranking, household breakdown, animated world flow map (24 h / 7 d / 30 d) |
| **DNS** | Query trends, block reasons, top domains, per-device view (dnsmasq log, or optional NextDNS API) |
| **Port forwarding** | Restrict sources by country / IP range, deny lists, per-admin port ranges, conflict checks, multi-WAN binding. **Usage analytics:** service fingerprinting (SSH, HTTPS, RDP …), who connected, scan and brute-force detection, live connections |
| **Device controls** | One-click block, allow / deny lists by service or domain, schedules, block router ports, force router DNS |
| **Network tools** | Route trace with map and per-hop ASN, TCP ping, DNS comparison, HTTP timing waterfall, browser and iperf3 LAN speed tests, **scheduled monitors with alerts and CSV export**, LAN scan with port discovery, **packet capture with expert-style analysis** and pcap download, Wake-on-LAN, UPnP, local DNS records |
| **System** | CPU / memory / disk / temperature, plugin services, logs, scheduled reboot, config backup and restore, **optional dependency manager** |
| **Multi-admin** | Super admin and scoped admins, 12 fine-grained permissions, quotas, port-range grants, approval workflow, full audit log with one-click restore |
| **Security** | Panel access control by LAN device / country / IP, browser time-zone check, visitor log with ASN and proxy hints, local CA for HTTPS, login rate limiting, signed agent API |
| **Alerts** | Telegram and ServerChan: new device, WAN down, device offline, traffic spike, denied access, pending approval, monitor down / recovered |
| **Updates** | Signed online updates from GitHub Releases, **per component**: the web UI hot-swaps without a restart, and the program updates through opkg |
| **Polish** | First-login wizard, custom panel name, installable PWA, phone layout, dark mode, ⌘K search |

## Install

Requirements: OpenWrt 22.03 or newer (fw3 / iptables is fully tested; fw4 / nftables systems are not yet tested), ≥ 512 MB RAM recommended. Architectures: `x86_64`, `aarch64`, `arm` (cortex-a7). MIPS routers are not supported (the embedded SQLite has no 32-bit MIPS port, and they rarely have the memory).

1. Download `luci-app-wharf_<version>-1_<arch>.ipk` from the [latest release](https://github.com/wangsirco/wharf/releases/latest).
2. Copy it to the router and install:
   ```sh
   opkg install /tmp/luci-app-wharf_*.ipk
   ```
3. Open **LuCI → Services → Wharf 码头**, which shows the panel address (default `https://<router-ip>:7080`). Use **Reset super admin password** to get the password for user `admin`.
4. Log in. The welcome wizard lets you name the panel, pick simple or pro mode, and install any missing optional components.

The panel uses its own local certificate authority, so browsers will warn about it until you install the certificate once per device (login page → *Install panel certificate*). That CA is name-constrained to private addresses and `.lan`-style names, so it cannot impersonate public websites.

**Upgrading:** Settings → *Version & updates*, or install a newer ipk with `opkg install` (avoid `--force-reinstall`). **Uninstalling:** `opkg remove luci-app-wharf` removes Wharf's firewall chains, ipsets, its DNS-log setting and any packages that Wharf itself installed. Your port forwards and the panel data directory are kept.

## Optional components

Wharf has no hard opkg dependencies. Features that need a system tool say so on their page, and the super admin can install the tool in one click (System → Dependencies). Packages installed that way are recorded and removed again when Wharf is uninstalled. Packages you already had are never touched.

| Component | Package | Used for |
|---|---|---|
| conntrack, byte accounting, ipset | `conntrack`, sysctl, `ipset` | traffic analytics, port-forward rules, device controls *(core)* |
| tcpdump · mtr · iperf3 · dig · curl | `tcpdump`, `mtr-json`, `iperf3`, `bind-dig`, `curl` | capture, route trace, speed test, DNS / HTTP tests |
| ip-full · etherwake · miniupnpd | `ip-full`, `etherwake`, `miniupnpd-*` | presence accuracy, Wake-on-LAN, UPnP |

DNS analytics use dnsmasq's built-in query log, so no SmartDNS, AdGuard Home or dnsmasq-full is needed.

## How it works

```
 Browser / phone ──HTTPS──▶ owp-panel  (Go + SQLite, embedded React UI)
                                │  HMAC-signed API on 127.0.0.1:7071
                                ▼
                         owp-agent  (uci, firewall, conntrack, dnsmasq log, diagnostics)
                                │
                                ▼
                         OpenWrt  (firewall, ipset, dnsmasq, conntrack, opkg)
```

The panel can also run on a VPS while only the agent runs on the router (HTTPS with certificate pinning and a source allow-list). Internal names (`owp-agent`, `owp-panel`, uci `owp*`) are kept for compatibility.

## Documentation

- 📖 [User manual](docs/MANUAL.md) (Chinese): every page, permissions, security design, exactly what Wharf changes on your router, data retention, CLI, FAQ
- 🎨 [Brand assets](docs/brand/wharf-logo/)
- 🧩 [UI kit](docs/UI-KIT.md)

## Build from source

```sh
git clone https://github.com/wangsirco/wharf && cd wharf
cd web && npm ci && npm run build && cd ..
go test ./internal/...
scripts/build-ipk.sh x86_64        # → dist/luci-app-wharf_<version>-1_x86_64.ipk
```

Go 1.27+ and Node 22+ are required. Releases are published with `scripts/release.sh`, which builds all architectures and signs the update manifest.

## Privacy

All data stays on your router. Traffic analytics use connection metadata (addresses, ports, byte counts) and DNS queries; nothing is decrypted. Packet capture is a separate, audited permission. Wharf only goes online for things you can turn off: monthly IP-database and rule updates, the update check, and services you enable yourself (NextDNS, Proxmox, speed tests).

## Contributing & security

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Credits

IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0) · content rules from [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) · map data from Natural Earth via world-atlas · UI built with React, Tailwind CSS, shadcn/ui, Base UI, ECharts and Lucide.

Wharf is designed and built by [iWSheng](https://github.com/wangsirco) together with Claude (Anthropic).

## License

[MIT](LICENSE)
