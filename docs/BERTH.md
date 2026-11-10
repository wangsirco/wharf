# Wharf ⇄ Berth 对接协议

Berth 是同一系列的 Linux 服务器管理面板（Wharf 管路由器，Berth 管服务器）。本文是 **Wharf 一侧已经实现** 的接口与约定，Berth 按这里实现即可联调。Wharf 的实现在 `internal/panel/berth.go`、`berth_api.go`、`berth_bans.go`，签名在 `internal/sign`。

- 同一时间只和一个 Berth 配对。
- 一切经对接令牌的写操作都记入 Wharf 审计，执行者是「Berth（名称）」。Berth 在请求头 `X-Berth-Actor` 里写上它那边是谁（例如 `王 · 新建站点 vault.example.net`），会一并记进摘要。
- 出错时一律返回 `{"error": "给人看的中文"}`，个别情况另带 `code`、`issues`、`conflicts` 字段（见下文）。

---

## 1. 签名

两个方向用同一套算法，只是头的前缀不同：

| 方向 | 令牌 | 头前缀 |
|---|---|---|
| Berth → Wharf `/api/ext/berth/v1/*` | `wharf_bth_…`（Wharf 签发） | `X-Berth` |
| Wharf → Berth `/api/ext/wharf/v1/*` | `berth_wrf_…`（Berth 签发） | `X-Wharf` |

```
Authorization: Bearer <token>
<P>-Ts:    Unix 秒
<P>-Nonce: 随机串（≤ 64 字符，Wharf 用 24 位十六进制）
<P>-Sig:   hex( HMAC-SHA256( key, canonical ) )

key       = HMAC-SHA256( key = token 的 UTF-8 字节, msg = "wharf-berth-sign-v1" )
canonical = METHOD + "\n" + REQUEST_URI + "\n" + TS + "\n" + NONCE + "\n" + hex(sha256(body))
```

- `REQUEST_URI` 是路径加查询串，原样，例如 `/api/ext/berth/v1/forwards?plan=1`。
- 没有请求体时，body 就是空串，`sha256("")`。
- 时间窗 ±60 秒；nonce 在 5 分钟内不能重复（Wharf 存在 `berth_nonce` 表里）。Berth 校验 Wharf 的请求也请这样做。
- 校验失败时 Wharf 返回 401，记一条访问记录（原因「Berth 接口：…」），并计入限速：15 分钟内 50 次失败后，该 IP 返回 429。
- Wharf 的接口也经过「面板访问控制」。如果按设备 MAC 限制了内网访问，要把 Berth 主机加进去。

Go 实现（可直接抄到 Berth）：

```go
func DeriveKey(token string) []byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("wharf-berth-sign-v1"))
	return m.Sum(nil)
}
```

## 2. 证书

服务器之间互相请求时，用配对时记录的指纹校验对方。Wharf 访问 Berth 时，满足以下任一条件就接受：

1. 证书链中任意一张证书（叶子或 CA）的 SHA-256 等于 `berth_fp`；
2. 证书对访问用的主机名是公共 CA 签发的有效证书。

Wharf 给 Berth 的 `wharf_fp` 是 Wharf 本地 CA 的指纹，叶子证书续期后它不会变。Wharf 提供证书链时会带上这张 CA，所以 Berth 用「链中任意一张匹配」的规则即可。如果 Wharf 用的是 `tls=files`，`wharf_fp` 是链里最后一张证书的指纹。

## 3. 配对

1. 用户在 Berth 里填写 Wharf 地址。Berth 生成一次性 `code`，打开：
   ```
   https://<wharf>/pair/berth?berth_url=<https://berth:port>&berth_fp=<64 位十六进制>&code=<code>&cb=<https://berth:port/...>
   ```
   - `berth_url` 必须是 https；
   - `cb` 必须和 `berth_url` 同主机、同端口。
2. Wharf 要求超级管理员登录。管理员确认权限范围、有效期（永久 / 30 / 90 / 365 天）和 Berth 主机（按 `berth_url` 的地址自动匹配设备），点「同意配对」。浏览器随后跳到：
   ```
   cb?state=<Berth 的 code>&code=<Wharf 的一次性码>&wharf_url=https://<wharf 地址>&wharf_fp=<指纹>&wharf_name=<面板名称>
   ```
   Berth 要核对 `state` 是自己发出的那个 `code`。
3. Berth 在 10 分钟内调用（不带签名，此时还没有令牌）：
   ```
   POST {wharf_url}/api/ext/berth/v1/pair/exchange
   {"code": "<Wharf 的一次性码>", "token": "berth_wrf_<随机，至少 20 位>", "name": "mini"}
   → 200 {"token": "wharf_bth_…", "scopes": [...], "targets": [{ip, mac, name}], "expires_at": 0, "wharf_name": "...", "wharf_url": "..."}
   ```
   - 这次请求要固定 `wharf_fp` 校验证书；
   - 一次性码只能用一次。
4. Wharf 约 2 秒后调用 Berth 的 `GET /ping`，验证反方向是否通。

**权限范围（scopes）**：`forwards`、`sni`、`ddns`、`devices.read`、`traffic.read`、`bans`、`alerts`、`sso`。

- Wharf 一侧只能收窄，Berth 会收到 `link.updated` 事件。要增加范围，需要重新配对。
- `targets` 是允许作为映射目标的 Berth 主机。带 MAC 的目标，换了 DHCP 地址后仍然有效。

**解除配对**：

- 任意一方都可以解除：
  - Berth 一侧调用 `POST /api/ext/berth/v1/unpair {"keep": true|false}`；
  - Wharf 一侧会先调用 Berth 的 `POST /api/ext/wharf/v1/unpair {"keep": …}`。
- `keep=true`：Berth 建的映射转为普通转发，归超级管理员；`keep=false`：删除这些映射。
- 不论选哪个，以下内容都会清除：
  - 443 登记的域名
  - 来自 Berth 的封禁
  - DDNS 分工
  - 用户对应
- 主通知方改回 Wharf。

**轮换令牌**：

- 在 Wharf 一侧发起，调用 Berth 的 `POST /rotate {"token": "wharf_bth_新"}`（用旧令牌签名）。
- Berth 保存新的 Wharf 令牌，并返回自己的新令牌 `{"token": "berth_wrf_新"}`。之后两边都使用新令牌。

**失效**：

- 过期后，Wharf 对所有请求返回 `401 对接已过期，请重新配对`。
- Berth 对 Wharf 返回 401 时，Wharf 把对接标为「对接已失效」。
- 两种情况下已建好的映射都保留。

---

## 4. Berth 调用 Wharf：`/api/ext/berth/v1/`

| 方法 路径 | 范围 | 说明 |
|---|---|---|
| `GET /ping` | — | `{ok, name, version, scopes, targets, expires_at, time}` |
| `POST /events` | — | Berth 通知 Wharf 的事件，见 §6 |
| `POST /unpair` | — | 解除配对 |
| `GET /forwards` | forwards | 全部端口转发（只读），用于冲突检查 |
| `POST /forwards[?plan=1]` | forwards | 新建；`plan=1` 只返回预览 |
| `PUT /forwards/{id}` | forwards | 修改（只限 Berth 建的） |
| `DELETE /forwards/{id}` | forwards | 删除（只限 Berth 建的） |
| `GET /sni` | sni | `{target, domains, proxy_protocol, front}` |
| `PUT /sni` | sni | 整体替换 Berth 登记的 443 域名（幂等）；`domains: []` 表示全部撤销 |
| `GET /ddns` | ddns | Wharf 的 DDNS 条目和每个域名的维护方 |
| `POST /ddns/claim` | ddns | `{domain, owner: "wharf"\|"berth"}` |
| `POST /ddns/{id}/run` | ddns | 立即更新一次 |
| `GET /devices` | devices.read | 设备列表 |
| `GET /hosts/{ip}/traffic?range=24h\|7d\|30d` | traffic.read | Berth 主机的公网流量、对端、国家分布 |
| `GET /hosts/{ip}/inbound?range=…` | traffic.read | 经端口转发进来的连接，按来源 IP 汇总并给出判定 |
| `GET /bans` | bans | Wharf 里标为「同步到 Berth」的封禁 |
| `POST /bans` | bans | 同步一条封禁过来 |
| `DELETE /bans/{id}` | bans | 撤回（只限 Berth 同步来的）；`{id}` 可以是 Wharf 的 id，也可以是 `remote:<Berth 的 id>` |
| `POST /alerts` | alerts | 投递告警（Wharf 是主通知方时） |
| `POST /sso/ticket` | sso | 申请免登录票据 |

### 4.1 端口映射

```json
POST /forwards
{
  "name": "berth: vault.example.net", "proto": "tcp", "wan_port": "8443",
  "target_ip": "192.168.1.20", "target_port": "443", "wan": "",
  "mode": "restrict", "allow_countries": ["HK", "TW"], "allow": [], "deny": [],
  "berth_ref": "site:vault.example.net", "berth_host": "mini",
  "note": "由 Berth 新建站点时创建", "enabled": true
}
→ 200 {"id": "owpr_1a2b3c4d"}
```

- `proto` 取值：`tcp`、`udp`、`tcp udp`。
- `mode` 取值：`all`、`restrict`；`allow_countries` 用 ISO 国家代码。
- `target_ip` 必须是配对时选定的主机。
- 冲突时返回 409：`{"error": "...", "issues": [{"level": "error"|"warn", "msg": "..."}]}`，检查的是端口和协议重叠、面板端口、分配给管理员的端口段。
- `?plan=1` 返回 `{summary, issues, changes: ["firewall.owpr_<新>（redirect …）", ...], ok}`，不做任何改动。
- `PUT` 的请求体与 `POST` 相同。省略 `berth_ref` 和 `berth_host` 时保留原值。
- 在 Wharf 界面上：
  - 普通管理员只能查看这些映射；
  - 超级管理员可以强制修改，之后 Wharf 发 `forward.changed` 事件（§6）。

`GET /forwards` 的每一项：`{id, name, proto, wan_port, wan, target_ip, target_port, enabled, mode, allow_countries, kind: ""|"berth"|"proxy", berth_ref, berth_host, note}`。

### 4.2 443 SNI 分流

```json
PUT /sni
{"target": "192.168.1.20:443", "domains": ["vault.example.net", "*.home.example.net"], "proxy_protocol": true}
```

- **代理扩展没开、分流器没运行，或分流端口不是 443 时**：返回 `409 {"error": "443 未被占用，请改用端口映射", "code": "no_front"}`。这时请改用 §4.1 映射 443。
- **优先级**：代理节点 > Wharf 面板域名 > Berth > 1Panel 网站 > 伪装站点。
  - 登记时如有冲突，返回 `409 {"error", "conflicts": [{"domain", "owner"}]}`。
  - 之后新建的节点即使和 Berth 的域名重叠，也会优先于 Berth。
- **通配符**：`*.zone` 只匹配多一级的子域名。
- **转发方式**：命中的连接不终止 TLS，原样转给 `target`。`proxy_protocol=true` 时先发一个 PROXY protocol v2 头，Berth 的 Caddy 要开 `proxy_protocol` 监听。
- **证书**：Wharf 不为这些域名申请证书，由 Berth 负责。Berth 只能用 DNS-01 或 TLS-ALPN-01 申请（ALPN 连接也会原样到达 Berth）。

### 4.3 DDNS

- `GET /ddns` 返回 `{items: [{id, name, domain, rtype, provider, enabled, last_ip, last_ok, last_err, owner}], owners: {domain: owner}}`。
- `POST /ddns/claim {domain, owner}`：
  - `owner=wharf` 且 Wharf 还没有这个域名的条目时，Wharf 会用同一区域已有条目的账号新建一条（Cloudflare、阿里云、DNSPod 等），返回 `{ddns_id}`；
  - 找不到同区域的账号时，返回 `409`。
- 维护方是 Berth 的域名，Wharf 不再更新，界面上只读，`run` 返回 409。
- **建议**：路由器拿到的公网 IP 最准，默认让 Wharf 维护。Berth 新建站点时只需要调用 `claim {owner: "wharf"}`。
- Wharf 会读取 Berth 的 `GET /ddns`，找出两边重复的域名，提示用户选择维护方，并发出 `ddns.owner` 事件。

### 4.4 设备与流量

- `GET /devices`：`{items: [{name, ip, mac, type, vendor, online, static}]}`
- `GET /hosts/{ip}/traffic`：`{ip, up, down, series: [{t, up, down}], remotes: [{ip, domain, country, org, inbound, up, down, conns}], countries: [{country, name, up, down}]}`
  - `series` 按小时；`remotes` 最多 100 个。
- `GET /hosts/{ip}/inbound`：`{ip, forwards: [{id, wan_port, target_port, proto, kind, service}], remotes: [{ip, country, org, conns, up, down, first, last, probes, short, verdict}], scanners, brute}`
  - `verdict` 取值：`scanner`、`brute`、`user`。
- `{ip}` 必须是 Berth 主机，否则返回 403。

### 4.5 封禁

```json
POST /bans
{"cidr": "203.0.113.7/32", "reason": "SSH 爆破", "source": "berth:mini:fail2ban", "expires_at": "2026-11-17T00:00:00Z", "id": 41}
→ 200 {"id": 7}
```

- `id` 是 Berth 自己的编号，之后可以用 `DELETE /bans/remote:41` 撤回。
- 同一网段重复投递时更新原条目，不会新增。
- **拒绝封禁**：
  - 内网和保留地址；
  - 路由器自己的公网地址；
  - 正在使用面板的人的地址；
  - 比 /16 更大的网段；
  - IPv6（目前只支持 IPv4）。
- **生效方式**：
  - ipset `owp_berth_ban`，配合两条 fw3 规则：`src wan` 到路由器 DROP，`src wan dest *` 转发 DROP。局域网不受影响。
  - 到期由面板清理，最迟 10 分钟内生效。
- **Wharf 一侧的封禁**：可以勾选「同步到 Berth」（默认不勾），之后可以单条撤回。

### 4.6 告警

```json
POST /alerts {"level": "warn"|"crit", "title": "...", "body": "...", "link": "https://<berth>/...", "dedupe_key": "..."}
```

- 只在 Wharf 是主通知方时接收；否则返回 `409 {"code": "not_primary"}`。
- Wharf 用自己的渠道发出，标题前加「[Berth · 名称]」。同一个 `dedupe_key` 10 分钟内只发一次。
- `crit` 不受 Wharf 免打扰时段限制。

### 4.7 免登录（Berth → Wharf）

```json
POST /sso/ticket {"berth_user": "wang", "return_to": "/forwards"}
→ 200 {"url": "https://<wharf>/sso/berth?t=<票据>"}
```

- 票据 60 秒内有效，只能用一次。它绑定配对时的 Wharf 地址，用别的主机名打开会被拒绝。
- `return_to` 只能是站内路径，其他值一律改成 `/`。
- 用户对应由 Wharf 超级管理员在「系统设置 → 集成 → Berth 泊位」里设置：
  - 没有对应的用户，返回 403；
  - 对应到超级管理员时，需要再输一次密码。
- 登录后会话按对应的 Wharf 用户权限运行。审计和访问记录里记为「经 Berth 跳转（Berth 用户 wang）」。

---

## 5. Wharf 调用 Berth：`/api/ext/wharf/v1/`（Berth 需要实现）

签名用 `X-Wharf-*` 头。以下接口按出现顺序排列；没实现的接口，Wharf 会显示 Berth 返回的错误。

| 方法 路径 | 何时调用 | 请求 / 期望的返回 |
|---|---|---|
| `GET /ping` | 配对后 | 200 即可 |
| `POST /events` | 见 §6 | `{type, ts, …}` → 200 |
| `POST /unpair` | Wharf 一侧解除配对 | `{keep}` → 200；之后 Berth 删除自己保存的 Wharf 令牌 |
| `POST /rotate` | 轮换令牌 | `{token: "wharf_bth_新"}` → `{token: "berth_wrf_新"}` |
| `POST /bans` | Wharf 的封禁勾选了同步 | `{cidr, reason, source: "wharf:<面板名>:<用户>", expires_at?, id}` → `{id}`（Berth 的编号） |
| `DELETE /bans/{id}` | 撤回同步 | `{id}` 是 Berth 的编号；返回 404 也视为已撤回 |
| `POST /alerts` | Berth 是主通知方时 | `{level, title, body, kind, dedupe_key, source}` → 200 |
| `POST /sso/ticket` | Wharf 用户点「打开 Berth」或 Berth 徽标 | `{wharf_user, return_to, ref}` → `{url}`；`url` 必须以 Berth 自己的地址开头 |
| `GET /ddns` | Wharf 的 DDNS 页面 | `{items: [{domain}]}` |
| `GET /hosts/{ip}` | Wharf 设备页的「Berth」标签页 | `{name?, sites: [{domain, state?, target?, ref?}], containers: [{name, image?, state?, ports?}], vms: [{name, state?, ip?}]}` |

- **审批类通知**（Telegram 里的批准 / 拒绝按钮）：Wharf 不会转交给 Berth，仍由自己发送。Berth 也应该这样做，不要把自己的审批按钮交给 Wharf。
- **`ref`**：Wharf 原样传回映射上的 `berth_ref`（例如 `site:vault.example.net`），由 Berth 决定跳到哪一页。

## 6. 事件（`POST /events`）

**Wharf → Berth**

| type | 字段 | 含义 |
|---|---|---|
| `forward.changed` | `id, berth_ref, change: modified\|deleted\|enabled\|disabled, by` | 超级管理员在 Wharf 里改了 Berth 的映射；Berth 把对应站点标为「外部修改」 |
| `ban.revoked` | `id`（Berth 的编号）`, cidr, by` | Wharf 里撤销了一条 Berth 同步来的封禁；Berth 取消该条的「已同步到 Wharf」 |
| `ddns.owner` | `domain, owner` | 用户在 Wharf 里选择了维护方 |
| `link.updated` | `scopes, targets` | Wharf 收窄了权限或改了 Berth 主机 |

**Berth → Wharf**（Wharf 已处理）

| type | 字段 | 含义 |
|---|---|---|
| `ban.revoked` | `id`（Wharf 的编号或 Berth 的编号） | Berth 删除了 Wharf 同步过去的封禁 |
| `ddns.owner` | `domain, owner` | 在 Berth 里选择了维护方 |
| `link.renamed` | `name` | Berth 改名 |

## 7. 数据（Wharf 一侧，迁移 v20）

- **表**：
  - `berth_link`：令牌只存哈希，签名密钥和 Berth 的令牌用数据目录里的 `berth.key` 以 AES-GCM 加密；
  - `berth_user_map`
  - `berth_bans`
  - `ddns_owner`
  - `berth_nonce`
- **设置**：
  - `alerts.primary`：`wharf` 或 `berth`；
  - `bans.default_sync_to_berth`：`0` 或 `1`；
  - `berth.sni`：Berth 登记的 443 域名。
- **端口映射**：Berth 建的映射在 `owpfwd.<id>` 里带 `kind=berth`、`berth_ref`、`berth_host`、`berth_link`，在 `owned` 表里的属主是 0。
