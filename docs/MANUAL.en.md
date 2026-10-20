# Wharf · User Manual

> An OpenWrt control panel built for a whole household and several admins. You can see what is happening on your network and look after every port without knowing iptables.

Applies to: 0.17 and later · Systems: OpenWrt 22.03+ / iStoreOS (x86_64, aarch64, arm) · [中文版](MANUAL.md)

> The panel's interface is currently in Simplified Chinese. This manual gives the Chinese labels in parentheses where it helps you find things, for example *Settings (系统设置)*.

---

## Contents

1. [What Wharf is](#1-what-wharf-is)
2. [Feature overview](#2-feature-overview)
3. [How it works](#3-how-it-works)
4. [Installation and first use](#4-installation-and-first-use)
5. [Optional components](#5-optional-components)
6. [Features in detail](#6-features-in-detail)
7. [Multiple admins and permissions](#7-multiple-admins-and-permissions)
8. [Security design](#8-security-design)
9. [What Wharf changes on your router](#9-what-wharf-changes-on-your-router)
10. [Data and privacy](#10-data-and-privacy)
11. [Command line and the LuCI page](#11-command-line-and-the-luci-page)
12. [FAQ](#12-faq)
13. [Development and building](#13-development-and-building)
14. [Third-party data and licences](#14-third-party-data-and-licences)

---

## 1. What Wharf is

OpenWrt is powerful, but LuCI is built for one person who knows networking:

- **Hard to read.** Devices appear as a MAC and an IP, traffic is only a total, and finding out what one device is talking to is close to impossible.
- **Hard to share.** To let a friend manage one port range you have to give them the root password, which lets them change everything.
- **Hard to trace.** Nothing records who changed a firewall rule, when, or what it was before.
- **Troubleshooting means the command line.** When the network is slow you SSH in, run mtr, tcpdump and dig, and interpret the output yourself.

Wharf turns this into a panel that family members can read, that admins can safely delegate, and that produces evidence when something breaks.

**Design principles**

| Principle | In practice |
|---|---|
| Native OpenWrt only | Port forwards are standard `firewall` redirects, source restrictions use `ipset`, and DNS statistics come from dnsmasq's own query log. After uninstalling Wharf your rules are still ordinary OpenWrt configuration and still visible in LuCI. |
| No kernel changes, no outages | Changes are applied with `reload`. Wharf never restarts the network or the WAN. |
| Admins are isolated | Scoped admins only see and change what they created. Sensitive actions can require super-admin approval. |
| Everything is traceable | Every change is audited: who, when, from which IP, old value and new value. Restorable changes can be undone with one click. |
| Data stays at home | The IP database and content rules are local, and no cloud service is required. NextDNS, Proxmox and the update check are optional. |
| Plain language | A device is "Dad's iPhone", not `5e:3a:…`. Traffic is "YouTube / TikTok", not a list of IPs. Diagnostic tools give you a conclusion, not just raw output. |

---

## 2. Feature overview

| Area | Main features |
|---|---|
| **Dashboard / big screen** | Live WAN speed, busiest devices, today's traffic by category, recent events (new device, left / came back, WAN down, denied access, approvals); `/screen` big-screen mode |
| **Simple mode** | A device wall for family members (who is online, what they watch, where the data goes) with no switches |
| **Network** | WAN status, latency and loss (every 10 s), availability strip, outage log, speed tests (Cloudflare / Speedtest.net) |
| **Devices** | Brand, type, OS and Proxmox VM name detection; aliases and notes; online / away / back history; static leases |
| **Device profile** | Per-device live speed, traffic trend, weekly heatmap, services / companies / countries, DNS requests, connection targets (unknown targets can be probed) |
| **Traffic** | Device ranking, household breakdown by category, service and company, traffic over time |
| **World map** | Animated flow lines from home to countries and cities (Pacific-centred), 24 h / 7 d / 30 d |
| **DNS & NextDNS** | Query trend, block reasons, top blocked / queried domains, per-device view, resolved countries, recent queries |
| **Port forwarding** | Source restriction by country or IP range, deny list, per-admin port ranges, conflict checks with free-port suggestions, multi-WAN binding, **usage and connection analytics** (service fingerprint, who connected, scan / brute-force verdicts, live connections) |
| **Device controls** | One-click block, allow / deny lists by service or domain, schedules, block access to router ports, force router DNS, keep connectivity checks working while blocked |
| **Network tools** | Route trace (map + per-hop ASN), TCP ping, DNS comparison, HTTP timing, browser / iperf3 LAN speed tests, **scheduled monitors with alerts**, LAN scan, **packet capture with automatic analysis**, Wake-on-LAN, UPnP, local DNS records |
| **System** | CPU / memory / disk / temperature, plugin services, system log, reboot and scheduled reboot, backup and restore, **dependency manager** |
| **Multiple admins** | Users and permissions (12 fine-grained permissions), quotas, port-range grants, approvals, my requests, audit log with one-click restore |
| **Security** | Panel access control (LAN by device, internet by country, IP allow / deny, browser time-zone check), visitor log (ASN, ISP, proxy hints), local CA certificate, login rate limiting |
| **Alerts** | ServerChan and Telegram: new device, WAN down, watched device offline, traffic spike, denied access, pending approval, monitor down / recovered; quiet hours |
| **Other** | First-login wizard, custom panel name, installable PWA, phone layout, dark mode, ⌘K search, online updates |

---

## 3. How it works

```
 Browser / phone ──HTTPS──▶ owp-panel  (panel: Go + SQLite + embedded web UI)
                                │  HMAC-signed HTTP API (127.0.0.1:7071)
                                ▼
                         owp-agent  (router agent: uci, firewall, conntrack, dnsmasq log)
                                │
                                ▼
                         OpenWrt  (firewall, ipset, dnsmasq, conntrack, opkg …)
```

- **owp-agent** runs on the router and is the only component that touches the system.
  - Every request must carry an HMAC signature. By default it listens only on `127.0.0.1:7071`.
  - It reads the connection table every 10 seconds and follows the dnsmasq query log, then aggregates traffic per device × destination × port into one-minute records.
- **owp-panel** is the backend and web UI.
  - It handles login, permissions, audit, approvals, storage (SQLite), IP geolocation and content recognition.
  - It turns changes to the router into agent calls. It listens on port `7080` (HTTPS) by default.
- **LuCI page** (*Services → Wharf 码头*): switch the agent and the panel on or off, see the panel address, reset the super-admin password, reset access control.
- **Deployment**
  - **Local mode** (default): agent and panel both run on the router.
  - **VPS mode**: the router runs only the agent, with HTTPS and a source allow-list. The panel runs on your VPS and pins the agent's certificate fingerprint.

**Storage:** the panel database and certificates live in uci `owp.main.data_dir` (default `/etc/owp`; a data partition such as `/mnt/data/owp` is recommended). Captures are kept in RAM under `/tmp/owp-pcap`.

---

## 4. Installation and first use

### 4.1 Requirements

- OpenWrt 22.03 or later. fw3 / iptables is fully tested; fw4 / nftables systems are not yet tested.
- At least 512 MB of RAM is recommended. The panel database is capped at 1 GB by default, so put it on a partition with enough space.
- Architectures: x86_64, aarch64, arm (cortex-a7). MIPS is not supported: the embedded SQLite has no 32-bit MIPS port, and these routers rarely have the memory.

### 4.2 Installing

```sh
# after copying the package to the router
opkg install luci-app-wharf_<version>_<arch>.ipk
```

The services start automatically. *LuCI → Services → Wharf 码头* shows the panel address (default `https://<router-ip>:7080`).

**Initial password:** on first start a random password is generated for the super admin `admin`. Use *Reset super admin password* on the LuCI page to get a new one, then change it right away from the user menu (*修改密码*).

**Upgrading:** use the online update in *Settings → Version & updates* (see 6.14), or install a newer ipk by hand. Configuration, data and rules are kept. Do not use `opkg install --force-reinstall`, because reinstalling triggers the uninstall clean-up.

### 4.3 "Your connection is not private"

The panel uses its own **local certificate authority**. It can only sign for LAN addresses and local names such as `.lan`, so it cannot impersonate a public website. Install it once per device and the warning goes away:

1. On the login page, click *浏览器提示不安全？安装面板证书* → *下载证书* (download certificate).
2. Then, depending on the device:
   - **iPhone / iPad:** Settings → *Profile Downloaded* → Install. Then go to Settings → General → About → Certificate Trust Settings and switch it on.
   - **Android:** Settings → Security → Encryption & credentials → Install a certificate → CA certificate.
   - **Mac:** double-click to add it to Keychain and set it to *Always Trust*.
   - **Windows:** double-click → Install Certificate → place it in *Trusted Root Certification Authorities*.

After that, Wharf added to the iPhone home screen opens like an app. Typing an `http://` address redirects to `https://` automatically.

### 4.4 First-login wizard

Every user sees a 5–6 step wizard on first login. Any step can be skipped:

1. **Welcome:** what Wharf does.
2. **Your name:** your display name. The super admin can also name the panel; the name appears on the login page, the sidebar, the browser tab and the home-screen icon.
3. **Tour:** only the features you have permission for.
4. **Pick a look:** simple mode for family or pro mode for tinkerers. You can switch any time at the top right.
5. **Check components** (super admin only): lists missing optional packages and installs them in one click. See section 5.
6. **Ready:** suggested next steps for the super admin (change password, set up alerts, restrict internet access to the panel, create accounts for family).

You can reopen it later from the user menu → *使用向导*.

---

## 5. Optional components

Some features build on official OpenWrt packages. **None of them is a hard dependency.** Wharf installs and runs without them, and a feature that needs a missing package says so at the top of its page.

| Component | Package | Level | Used for | If missing |
|---|---|---|---|---|
| conntrack tools | `conntrack` | core | traffic stats, device profiles, world map, port-forward usage | no traffic breakdown at all |
| Connection byte accounting | kernel switch `net.netfilter.nf_conntrack_acct` | core | byte counts per connection | connection counts but no sizes |
| ipset | `ipset` | core | forward source restrictions, device controls, live speeds | these features are unavailable |
| ip (full) | `ip-full` | recommended | online / away detection | busybox `ip` works with less detail |
| tcpdump | `tcpdump` | recommended | packet capture and analysis | capture page unavailable |
| mtr (JSON) | `mtr-json` | recommended | route trace | route trace unavailable |
| iperf3 | `iperf3` | recommended | iperf3 speed tests | the browser speed test still works |
| dig | `bind-dig` | recommended | DNS comparison | DNS comparison unavailable |
| curl | `curl` | recommended | HTTP timing test | HTTP test unavailable |
| etherwake | `etherwake` | optional | Wake-on-LAN | WOL unavailable |
| UPnP daemon | `miniupnpd-iptables` / `miniupnpd-nftables` | optional | UPnP management | UPnP page unavailable (it is a security risk, so only install it if you need it) |

DNS statistics use dnsmasq's **built-in** query log (`logqueries`), so you don't need dnsmasq-full, SmartDNS or AdGuard Home. If you use NextDNS, you can optionally add an API key in Settings to see full block reasons.

### How install and uninstall work

- **One click:** in the wizard or *System → Dependencies (依赖组件)*, tick the missing components and click Install.
  - The panel runs `opkg update` if needed, then `opkg install`, and shows the log live.
  - Only the super admin can do this, and every run is audited.
- **No bundling:** these are ordinary official packages installed system-wide, so other software can use them too. Wharf neither ships them inside its own package nor changes their configuration.
- **Removed together with Wharf:** packages installed through the panel are recorded in `/etc/wharf-deps.list`. When Wharf is uninstalled, the removal script waits for opkg to finish and then removes them, together with any libraries that were pulled in only for them (`--autoremove`).
- **Your existing packages are left alone:** packages you already had are never recorded or removed. If something else has come to depend on a package the panel installed, it is kept and the reason is written to the system log.
- You can also remove a single component marked *installed by the panel* from *System → Dependencies*.

---

## 6. Features in detail

### 6.1 Simple mode and pro mode

Switch at the top right; the browser remembers your choice.

- **Simple mode:** for family members. A device wall plus device details: who is online, how fast they're using the network, what the household mostly accessed in the last 24 hours, and where the data went. There are no switches, so nothing can be changed by accident.
- **Pro mode:** everything.

### 6.2 Dashboard and big screen

- **Live WAN traffic:** refreshed every 2 seconds, covering the last 5 minutes.
- **Busiest devices:** sorted by current speed.
- **Today's traffic:** a donut by category or service.
- **Recent events:**
  - new devices
  - devices that left or came back (with how long they were away)
  - WAN outages
  - schedules taking effect
  - denied panel access
  - approvals
- **Big screen:** `/screen`, designed to stay on a wall display. It includes the world map.

### 6.3 Network

- **Latency and loss:** the router measures latency and loss to the ISP gateway and a few public targets every 10 seconds. The results are drawn as latency curves and an availability strip (green = fine, yellow = loss, red = down).
- **Outage log:** every WAN disconnect and reconnect.
- **Speed test:**
  - Run from the router (Cloudflare or Speedtest.net).
  - Takes about 20–30 seconds and briefly saturates the line.
  - Limited to once per minute per user. All results are kept.

### 6.4 Devices

- **Automatic recognition:** brand, type (phone, computer, TV, camera, NAS, VM …) and OS, based on the MAC vendor (offline OUI database), DHCP hostname and mDNS / web probing. Randomised MACs are marked.
- **Proxmox VMs:** with a read-only Proxmox API token, VMs show their name from Proxmox and a *PVE 虚拟机 #id* tag.
- **Aliases and notes:** the alias you set is used everywhere in the panel (forwards, controls, search). Any characters are allowed, including apostrophes and mixed case.
- **Presence:**
  - Every 30 seconds the router re-checks idle devices (re-ARP); only a real answer counts as online.
  - A device not confirmed for 90 seconds shows as *disconnected*.
  - After the away threshold (default 10 minutes) Wharf records *left the network*. When the device returns it records *came back*, with how long it was away.
- **Static leases:** pin a device to an IP (written as a dhcp host). Scoped admins can only manage leases they created, within their quota.

### 6.5 Device profile

On a device's page:

- **Live speed:** sampled every 2 seconds.
- **Traffic trend** and **weekly pattern** (7 × 24 heatmap).
- **Where traffic goes:** drill down by category → service → company, for example *Video → TikTok → ByteDance*.
  - Rules come from the blackmatrix7 rule set, plus additions for newer platforms such as AI services. That is about 290 services, updated automatically every 72 hours.
- **Destination countries** and **active hours**.
- **Requested domains:** DNS requests merged with traffic.
- **Connection targets:** sorted by traffic. For targets the rules don't recognise, click *模拟访问* (probe). The router reads the certificate, page title and reverse DNS to work out what the target is, and labels the result as probed.

### 6.6 Traffic and world map

- **Device ranking** (download / upload), **household breakdown** and **traffic over time**.
- **World map:**
  - Animated flow lines from home, with traffic counted by country and city.
  - Anycast CDNs such as Cloudflare and Akamai count as local.
  - The map is Pacific-centred, which suits New Zealand and Asia-Pacific users.
  - The 24 h / 7 d / 30 d views are precomputed in the background, so they open instantly.

### 6.7 DNS and NextDNS

- **Data source:** the router's own dnsmasq log (default, no extra dependencies) or the NextDNS API (needs an API key).
- Query trend, block reasons, most blocked / queried domains, per-device queries (NextDNS view), resolved countries, protocols, recent queries.

### 6.8 Port forwarding

**Adding a forward**

- **LAN device** is searchable by name, IP, MAC, vendor, type, note or PVE tag; you can also type an IP.
- **Port check:** checks live for conflicts with other forwards, services the router itself listens on, and the panel's port. It also checks that the port is inside the range you were granted, and suggests free ports.
- **Multi-WAN:** a forward can be bound to one WAN interface (`extra -i <device>`).
- **Source restriction:**
  - **Restricted** (recommended): only listed countries or regions (for example New Zealand and China), or listed IPs / ranges. Countries come from the offline IP database and are compiled into an ipset.
  - **Everyone:** open to the world.
  - **Deny list:** extra IPs / ranges to block, in either mode.
- The result is a standard OpenWrt `firewall` redirect with structured information in its comment (creator, device, purpose), and it is visible in LuCI too.

**Usage and connection analytics** (the *24h 用量* column, or forward details → *查看流量与连接记录*)

- **What runs behind the forward:** the router connects to the target port and identifies the service, for example:
  - `SSH · OpenSSH_10.0`
  - `HTTPS · openresty`
  - `FTP · SmbFTPD`
  - `HTTP · nginx "fnOS"`
  - RDP, VNC, MySQL, Redis, Telnet …

  If the target is offline or the port is closed, it tells you.
- **Usage:** inbound and outbound bytes separately; 24 h / 7 d / 30 d with one point per hour (or day).
- **Who connected:** for each source IP you get country, city, network (ASN), connections, bytes, session time, last seen, and a verdict:

  | Verdict | Rule |
  |---|---|
  | Real use | long sessions, still connected, or real data exchanged |
  | Bulk | more than 10 MB in one connection |
  | Possible brute force | repeated short SSH connections under 1 minute and 15 KB (like password attempts) |
  | Scan / probe | connected but exchanged nothing (under 600 bytes) |
  | Scanning organisation | ASN of Censys, Shodan, Shadowserver and similar internet-wide scanners |

- **Live connections:** every open connection (who, since when, how much).
- **Recent connections:** the latest 150, each classified (probe / short / session / long session / bulk).
- **Source countries:** connections per country.
- **Findings:**
  - how much of the traffic is scanning
  - which IPs look like brute force
  - advice when a risky service is exposed (Telnet, FTP, databases, Redis, RDP, VNC, plain-HTTP logins; disable password login for SSH)
  - a note when the forward sits behind Cloudflare, since real visitor IPs are then only in your web server's logs

> Scope: only inbound connections through configured port forwards are counted. UPnP mappings and forwards to the router itself are not included.

### 6.9 Device controls

From any device → *访问控制* (access control):

- **Block** with one click.
- **Deny / allow lists** by service (for example "TikTok" or "Games") or by domain. The ipsets are built dynamically from DNS answers.
- **Schedules** by weekday and time, for example weekdays 22:00–07:00.
- **Block access to router ports**, for example keep a device away from the router's SSH or LuCI.
- **Force router DNS** so the device cannot bypass blocking with its own resolver.
- **Allow connectivity checks while blocked** so phones don't keep switching networks because they think there is no internet.

All active controls are listed together on the *设备管控* page.

### 6.10 Network tools

| Tool | What it does |
|---|---|
| **Route trace** | Like OpenTrace / NextTrace. ICMP, TCP or UDP; each hop shows IP, reverse DNS, country / city, ASN and network, average / best / worst latency and loss; the path is drawn on a map. |
| **TCP ping** | Is a port reachable? Refused or silently dropped? How fast? |
| **DNS comparison** | Ask the router, AliDNS, Tencent, Cloudflare, Google and Quad9 (or your own) the same question at once, and compare answers and times to spot pollution or blocking. |
| **HTTP test** | Open a URL from the router and split the time into DNS, TCP connect, TLS handshake, waiting for the first byte, and download. |
| **This device ↔ router speed** | A browser speed test between the current device and the router (Wi-Fi / cable), with nothing to install. |
| **iperf3 server** | The router acts as an iperf3 server for 10 minutes (LAN only, then it stops by itself). The page gives copyable client commands and lists every result. |
| **iperf3 client** | The router tests against a NAS, PC or VM; direction, TCP / UDP and parallel streams are selectable. |
| **Scheduled monitors** | See below. |
| **LAN scan** | Sweeps the subnet (about 10 s) to find devices with static IPs, devices that ignore ping, and 32 common ports (SSH, web, SMB, NFS, printers, cameras, Proxmox, Home Assistant …). Web ports are clickable. |
| **Packet capture** | See below. |
| **Wake-on-LAN** | Send a magic packet to a LAN device. |
| **UPnP** | Turn UPnP on or off, and view or delete the mappings devices created. |
| **Local DNS records** | Make LAN devices resolve a name to an IP (for example `nas.home`). |

**Scheduled monitors**

- **Probe types:** **ping** or **TCP connect**, every 1–60 minutes, 3–30 probes per round.
- **Fresh source ports:** TCP probes use a new source port each time. If one path of a load-balanced link is broken, this shows up as a steady share of failed connections, which ping usually misses.
- **Alerts:** two bad rounds in a row (unreachable, loss or latency over threshold) trigger an alert through your channels. Recovery is reported too, with how long the problem lasted.
- **History:** kept for 30 days, with latency and failure-rate charts for 6 h / 24 h / 7 d / 30 d and a **CSV export** that you can attach to an ISP ticket.
- **Templates:** Telegram Singapore / Miami, Cloudflare, AliDNS, AWS Singapore / Sydney.

**Packet capture**

- **Choose an interface.** The page explains what each one sees:
  - **LAN:** each device's own IP before NAT. Use it to investigate one device.
  - **WAN:** what actually goes over the ISP line. Use it for international routing or ISP issues.
  - **All interfaces.**
- **Filters:** device / IP, port, protocol (TCP / UDP / DNS / ICMP), or a raw tcpdump BPF expression. The expression is compiled first, so mistakes are reported immediately.
- **Limits:**
  - Duration: 30 s to 30 min.
  - File size: 10 to 200 MB.
  - *Headers only* for privacy and smaller files.
  - Option to exclude the panel's own traffic.
- **Automatic analysis**, in the spirit of Wireshark's Expert Info:
  - **TCP health:** handshake success rate, failed handshakes (SYN without answer), median and P95 handshake time, retransmission rate, resets, zero windows, duplicate ACKs, MSS.
  - **DNS:** queries, average and P95 time, failures (SERVFAIL / REFUSED), unanswered queries, slow queries, top names, resolvers used.
  - **TLS server names** (SNI) and HTTP hosts: which sites were visited.
  - **ICMP:** unreachables (including "fragmentation needed", the MTU problem) and TTL exceeded.
  - **Overview:** timeline of traffic and retransmissions, protocol and service mix, top hosts, packet sizes.
  - **Conversations:** problems first, with an "only show problems" filter.
- **Download** the pcap for Wireshark.
- Captures can contain content, so they need a **separate permission**, and starting, downloading and deleting are all audited.
- Captures are kept in router RAM (up to 12 files, 600 MB in total) and are lost on reboot or panel upgrade. Download the ones you want to keep.

### 6.11 System

- **Hardware:** CPU (load, cores), memory, disk, temperature (VMs usually have no sensor), connection count.
- **Dependencies:** see section 5.
- **Plugin services:** switch common iStore / OpenWrt plugins; critical ones warn first.
- **System log:** `logread` / `dmesg`, searchable.
- **Reboot** and **scheduled reboot** (weekdays + time, written to crontab).
- **Backup and restore:**
  - Uses `sysupgrade -b`, so it contains all of `/etc`, including passwords and keys.
  - Before restoring, the contents are listed for you to confirm.
  - Super admin only.

### 6.12 Alerts

- **Channels:** ServerChan and Telegram bots. You can add several; their addresses are masked in the UI and the audit log.
- **Rules:**
  - new device joined
  - WAN down for more than N minutes
  - watched device offline for more than N minutes (for example a NAS or camera)
  - a device used more than N MB in an hour
  - panel access denied (someone tried to log in from somewhere not allowed)
  - action waiting for approval
  - monitor down / recovered
- **Quiet hours:** urgent alerts such as WAN down are still sent.
- **Log:** where every alert went and whether it succeeded.
- Alert titles start with your panel name, for example "[Home] Monitor down: …".

### 6.13 Settings

- **Panel name and subtitle.**
- **Approval for sensitive actions:** choose which actions by scoped admins need super-admin approval (plugin switches, reboot, port forwards, device controls …).
- **Retention and thresholds:**
  - Audit 365 days, visitor log 90 days.
  - Traffic detail 7 days, with 1 GB total; the oldest detail is dropped first.
  - Away threshold 10 minutes.
- **Router agent:** connection status and version.
- **IP database:** DB-IP Lite (City + ASN), updated monthly.
- **Content rules:** version and update interval.
- **NextDNS:** API key and profile.
- **Proxmox VE:** address, read-only token, certificate fingerprint.
- **Version & updates:** online updates, see 6.14.

Every settings change is audited and can be restored.

### 6.14 Online updates

Wharf updates from GitHub Releases (default repository `wangsirco/wharf`), **one component at a time**:

| Component | Contents | How it updates |
|---|---|---|
| Web UI | every page you see in the browser (about 700 KB) | swapped in immediately, **no restart**; just reload the page |
| Program core | router agent + panel backend + LuCI page (about 15 MB, for your router's architecture) | installed by the agent through opkg; services restart for about 10 seconds, **your network is not affected** |
| Content rules | recognition rules for about 290 services | always updates itself periodically |
| IP & network database | DB-IP Lite | always updates itself monthly |

- The panel checks every 12 hours (this can be turned off) and shows the super admin a badge when there is something new.
- *Settings → Version & updates* lists each component's current version, whether it needs updating and how much it will download. One click applies the update.
- A release that only changed the UI downloads only the UI bundle. The program package is downloaded only when the program changed.
- **Security:**
  - Every release carries a manifest signed with the maintainer's ed25519 key, and the panel checks it against the public key built into it.
  - Nothing is installed unless the signature and every file's SHA-256 match.
  - Only the super admin can update, and every update is audited.
- If a new UI misbehaves, one click restores the UI built into the program.

---

## 7. Multiple admins and permissions

### 7.1 Roles

- **Super admin:** every permission, plus users, approvals, audit, visitor log, alerts, access control and settings.
- **Scoped admins:** created by the super admin with the permissions below. Scoped admins cannot see or change each other's forwards, leases or controls.

### 7.2 Permissions

| Permission | Group | Allows |
|---|---|---|
| `dashboard.view` | Dashboard | system status, live traffic, network page |
| `devices.view` | Devices | online devices, IP, MAC, names |
| `devices.manage` | Devices | naming devices, static leases (own only) |
| `forwards.view` | Forwards | own forwards, with usage and connection records |
| `forwards.manage` | Forwards | add / change / delete own forwards |
| `traffic.view` | Traffic | destinations, statistics, profiles, world map, DNS |
| `access.manage` | Controls | block, allow / deny lists, schedules |
| `system.view` | System | hardware, plugin status, logs, UPnP, local DNS, dependency status |
| `system.manage` | System | reboot, scheduled reboot, plugin switches, UPnP, local DNS |
| `tools.wol` | Tools | Wake-on-LAN |
| `tools.diag` | Tools | route trace, TCP ping, DNS / HTTP tests, speed tests, LAN scan, monitors |
| `tools.capture` | Tools | packet capture, analysis, pcap download (can see content; grant carefully) |

### 7.3 Quotas and port-range grants

- **Quotas:** how many port forwards (default 5) and static leases (default 10) an admin may create. -1 means unlimited.
- **Port-range grants:** give an admin public port ranges (optionally per WAN) and the LAN IP ranges they may forward to, for example "8000–8010 → 192.168.1.100–192.168.1.120".
  - Ranges are exclusive between admins.
  - Someone else's range stays reserved for them, even against admins without restrictions.
  - With no grant, the admin is not restricted.

### 7.4 Approvals

Actions ticked in *Settings → Approval for sensitive actions* go into the **approval queue** when a scoped admin submits them. They only run once the super admin approves. Admins can follow their requests on *我的申请* (my requests), and a pending approval can trigger an alert.

### 7.5 Audit and restore

Every change is recorded with the time, admin, source IP, action, target and summary, together with the **old and new values** side by side, and whether it went through approval. Forwards, static leases, device controls and settings can be **restored with one click**, and the restore itself is audited too.

---

## 8. Security design

- **HTTPS**
  - By default the certificate is issued by a local CA. The CA is name-constrained to LAN addresses and local names (`.lan`, `.local`, `.home.arpa` …).
  - The server certificate is valid for 397 days and is reissued automatically when the router's IPs change.
  - You can use your own certificate instead, or turn TLS off behind a reverse proxy.
- **Panel access control** (who may even see the login page)
  - **LAN:** allow-list or deny-list by device MAC.
  - **Internet:** by country or region, based on the source IP the server sees and the offline database.
  - **IP allow / deny lists:** the deny list wins; the allow list skips the country and device checks.
  - **Browser-side IP check** (optional): the browser asks ip.sb for its own public IP and reports it, which exposes split-tunnel proxies.
  - **Browser time-zone check:** at login, the browser's time zone is compared with the IP's.
  - **Recovery:** denied visitors see an access-denied page and are logged. If you lock yourself out, use *Reset access control* in LuCI.
- **Visitor log:** each visit records the time, the visitor's local time and time zone, IP, ASN, network and browser. Mismatched time zones or public IPs are flagged.
- **Login protection:** rate limiting, session timeout, CSRF tokens, `HttpOnly + Secure` cookies, a strict CSP.
- **Agent:** every request is HMAC-signed with replay protection, and the agent listens on localhost by default. In VPS mode it can use HTTPS with a source allow-list, and the panel pins its certificate.
- **Input safety:** router commands always run as argument arrays, never through a shell. Targets, ports and filter expressions are strictly validated.
- **Secrets:** the NextDNS key, Proxmox token and alert URLs are masked in the UI and audit log, and are stored only in the panel database.

---

## 9. What Wharf changes on your router

Wharf only changes things when you use the matching feature, and uses standard configuration wherever possible.

| Change | Where | When | On uninstall |
|---|---|---|---|
| Port forwards | `/etc/config/firewall` redirects (`owpr_*`) + ipsets (`owps_*`); metadata in `/etc/config/owpfwd` | adding a forward | kept (they are your rules) |
| Device controls | `/etc/config/owpdev`; iptables chains `owp_pol` / `owp_polin` / `owp_dns`; ipsets `owp_p[bw]_*` | setting a control | chains and ipsets removed |
| Traffic counters | iptables chain `owp_acct`; ipsets `owp_up` / `owp_dn` | agent start | removed |
| DNS query log | dnsmasq `logqueries` + `logfacility=/var/log/owp-dns.log` | first agent start | restored |
| WAN access to panel / agent | firewall rules `owp_panel` / `owp_agent` | only if you tick *allow from WAN* in LuCI | removed |
| Static leases, local DNS | `/etc/config/dhcp` (host / domain sections) | when used | kept |
| Scheduled reboot | root crontab (tagged `# owp-reboot`) | when set | kept (turn it off in the panel) |
| Optional components | opkg packages, recorded in `/etc/wharf-deps.list` | when you install them from the panel | the ones Wharf installed are removed (see section 5) |
| Byte accounting | `/etc/sysctl.d/90-wharf.conf` | when you enable it in the panel | removed |
| Panel data | `owp.main.data_dir` (database, certificates, IP database, rules; a downloaded UI goes in its `web/` folder) | while running | kept; delete by hand if you want |

**What Wharf never does:**
- restart the network or the WAN
- change the LAN subnet, WAN dial-up or Wi-Fi
- upgrade firmware or kernel
- touch other plugins' configuration

---

## 10. Data and privacy

| Data | Kept for | Notes |
|---|---|---|
| Traffic detail (device × destination × hour) | 7 days by default, 1 GB cap | adjustable |
| Per-minute traffic | 48 hours | for live charts |
| Port-forward connections | 30 days, up to 1.5 million | one row per inbound connection |
| Monitor results | 30 days | |
| Device presence events | 90 days | |
| Audit log | 365 days by default | |
| Visitor log | 90 days by default | |
| Alert log | 90 days | |
| Packet captures | RAM only, gone on reboot | up to 12 files / 600 MB |

- **Where data lives:** everything stays on your router (or your VPS).
- **When Wharf goes online**, and every one of these can be turned off:
  - the monthly IP-database update (DB-IP)
  - rule updates (GitHub)
  - the update check (GitHub)
  - services you enable yourself: NextDNS, Proxmox, speed tests, the browser-side IP check
- **What is recorded:** traffic analytics use connection metadata (addresses, ports, byte counts) and DNS queries. **Nothing is decrypted and no content is recorded.**
- **Packet capture is the exception:** it does record content, which is why it is a separate, fully audited permission.

---

## 11. Command line and the LuCI page

**LuCI: Services → Wharf 码头**
- Switch the agent and panel on or off; set ports and WAN access.
- See the panel addresses (LAN / WAN) and copy the agent key (for VPS mode).
- Reset the super-admin password, and reset panel access control if you locked yourself out.

**Command line (on the router, as root)**

```sh
P="/usr/bin/owp-panel -config /var/etc/owp/panel.json"

$P reset-super                         # print a new super-admin password
$P reset-access                        # clear panel access control
$P setting nextdns.api_key <KEY>       # write a setting (secrets stay in the database)
$P monitor-add "Telegram SG" 91.108.56.130 tcp 443 20 5 10
                                       # name target icmp|tcp port count interval(min) loss-alert%
$P monitor-export > monitors.csv       # export every monitor round

/etc/init.d/owp restart                # restart agent and panel
logread | grep -E "owp|wharf"          # logs
```

---

## 12. FAQ

**"Cannot connect" or "not secure" when opening the panel**
Install the certificate as described in 4.3. Web apps on the iPhone home screen cannot bypass certificate warnings, so there the certificate is required.

**No traffic breakdown**
Check *System → Dependencies*: conntrack, byte accounting and ipset should all be ready. Data is aggregated per minute, so give a fresh install a few minutes.

**A device shows as "unknown device"**
This happens when there is no DHCP hostname and the vendor isn't recognised. Give it an alias on its page. For Proxmox VMs, connect Proxmox to get their names automatically.

**My phone left but still shows online**
Phones put Wi-Fi to sleep when the screen is off. Wharf shows *disconnected* after 90 s without confirmation and only records *left* after the away threshold (default 10 minutes), so phones don't flap in and out. The threshold is adjustable.

**"Who connected" is empty for a forward**
Per-connection records are collected from version 0.15 on, and only for inbound connections through port forwards. If nobody has connected, the list is empty. Hourly usage includes history and is available straight away.

**The network is slow. How do I find out why?**
1. Check WAN latency and outages on the *Network* page.
2. Use *Route trace* to see which hop is slow.
3. Watch the target with a TCP *monitor* over time. A steady share of failed connections means a path problem.
4. Capture on the WAN interface and look at failed handshakes and retransmissions.
5. Export the monitor CSV and the pcap and attach them to your ISP ticket.

This is exactly how the author proved a fault on an international route to their ISP.

**Uninstalling**
Run `opkg remove luci-app-wharf`. It removes Wharf's firewall chains, ipsets, the dnsmasq log setting and the components the panel installed. Your port forwards and the panel data directory are kept; you can delete the data directory by hand.

---

## 13. Development and building

```
cmd/owp-agent       router agent (Go)
cmd/owp-panel       panel (Go, embeds web/dist)
cmd/owp-rulegen     rule-set compiler
cmd/wharf-release   release tool: signs and uploads GitHub Releases
internal/agent      agent: uci, firewall, conntrack, DNS log, diagnostics, capture analysis, dependencies
internal/panel      panel: auth, permissions, audit, approvals, traffic, forwards, monitors, alerts …
internal/release    online updates: release manifest, signature check, web bundle
internal/tlsutil    local CA, certificate pinning, HTTP and HTTPS on one port
internal/rules      content recognition rules
internal/oui        MAC vendor database
web/                React + TypeScript + Tailwind + shadcn/ui (Base UI), ECharts maps
package/luci-app-wharf   ipk: procd service, LuCI page, install / remove scripts
docs/               manuals, screenshots, brand assets, UI kit
```

```sh
cd web && npm ci && npm run build && cd ..
go test ./internal/...
scripts/build-ipk.sh x86_64      # also aarch64 / arm
```

- **Version:** lives in `internal/version/version.go`; the build script reads it.
- **Releasing:** `GITHUB_TOKEN=… scripts/release.sh` builds every architecture, signs the manifest and uploads the GitHub Release. The signing key is held by the maintainer and is not in the repository.
- **Test mode:** `OWP_COLLECT=0 owp-agent …` serves the API without touching the firewall.
- **Internal names:** `owp-agent`, `owp-panel`, uci `owp*` and the `owp_*` chains are kept for compatibility; the public name is Wharf.

---

## 14. Third-party data and licences

- **IP geolocation and ASN:** DB-IP Lite (CC BY 4.0)
- **Content rules:** [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)
- **MAC vendors:** IEEE OUI public data
- **World map:** world-atlas (Natural Earth, public domain)
- **Front end:** React, Tailwind CSS, shadcn/ui, Base UI, ECharts, Lucide icons, Geist font
- **Speed tests:** Cloudflare Speed, Speedtest.net (speedtest-go)

Wharf itself is released under the MIT licence.

---

*Wharf is designed and built by iWSheng together with Claude (Anthropic).*
