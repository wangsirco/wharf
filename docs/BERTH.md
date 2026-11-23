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
<P>-Key:   hex(sha256(token))[:16]        ← 协议 v2（Wharf 0.24.0 起），令牌本身不再发送
Authorization: Bearer <token>              ← 协议 v1，过渡期仍然接受
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
- **v2 切换**（§8.4）：Wharf 收到带 `X-Berth-Key` 的请求并验签通过后，记下 Berth 已支持 v2，之后 Wharf → Berth 也只发 `X-Wharf-Key`，不再发 `Authorization`。

Go 实现（可直接抄到 Berth）：

```go
func DeriveKey(token string) []byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("wharf-berth-sign-v1"))
	return m.Sum(nil)
}
```

## 2. 证书

服务器之间互相请求时，用配对时记录的指纹校验对方。Wharf 访问 Berth 的所有请求（ping、封禁、告警、事件、SSO、测延迟）都用同一个规则（`pinOrPublic`），满足以下任一条件就接受：

1. 证书链中任意一张证书（叶子或 CA）的 SHA-256 等于 `berth_fp`；
2. 证书对访问用的主机名是公共 CA 签发的有效证书。

Wharf 给 Berth 的 `wharf_fp` 是 Wharf 本地 CA 的指纹，叶子证书续期后它不会变。Wharf 提供证书链时会带上这张 CA，所以 Berth 用「链中任意一张匹配」的规则即可。如果 Wharf 用的是 `tls=files`，`wharf_fp` 是链里最后一张证书的指纹。

## 3. 配对

1. 用户在 Berth 里填写 Wharf 地址。Berth 生成一次性 `code`，打开：
   ```
   https://<wharf>/pair/berth?berth_url=<https://berth:port>&berth_urls=<地址1>,<地址2>&berth_fp=<64 位十六进制>&code=<code>&cb=<https://berth:port/...>
   ```
   - `berth_urls`（v2，可选）：Berth 的全部地址，逗号分隔，内网在前；见 §8.2。
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

**权限范围（scopes）**：`forwards`、`sni`、`ddns`、`devices.read`、`traffic.read`、`bans`、`alerts`、`sso`、`dns`（v2，§8.6）。

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

## 8. 协议 v2（Wharf 0.24.0 起）

Wharf 在 `GET /ping` 的回答里带 `"protocol": 2, "auth": ["key", "bearer"], "key_auth": <是否已切换>`。

### 8.1 配对页的两种地址

「Berth 服务器面板」页（未配对时）给两种地址：

- **同一个局域网（推荐）**：`https://wharf.lan:<端口>`（或路由器 IP），附 Wharf 本地 CA 指纹，Berth 看到的应该一样。
- **跨网（公网域名）**：「外网访问」里配置的公网名字，注明出示的是公网证书（签发者、到期日），Berth 按域名校验，不用核对指纹。

### 8.2 Berth 的多个地址

- 配对时带 `berth_urls`（逗号分隔或 JSON 数组，最多 8 个，都要 https）。Wharf 再按「私有 IP → `.lan/.local/.home.arpa/.internal` 名字 → 其他」排一次序，存在 `berth_link.urls`。
- 每次调 Berth：先用上次成功的地址（`berth_link.url`），失败按顺序换下一个，成功后记住。
- 写操作只在请求还没发出去时（连接、TLS 失败）才换地址，避免同一个改动发两次。
- 全部失败时，错误里列出每个地址各自的原因。
- 不依赖 `.local`（路由器一般不解析 mDNS）。

### 8.3 内网发现：「申请 / 允许」

管理员在「Berth 服务器面板」页点「允许 Berth 申请绑定（10 分钟）」，之后：

```
POST /api/ext/berth/v1/pair/request          （不签名）
{"code": "<Berth 的一次性码，20–128 位>", "berth_name": "mini",
 "berth_urls": ["https://192.168.1.20:7090", "https://mini.example.com"],
 "berth_fp": "<Berth 本地 CA 指纹>", "wharf_fp": "<Berth 看到的 Wharf 本地 CA 指纹>"}
→ 200 {"id": "<请求 id>", "sas": "123 456", "expires_at": <unix>}

POST /api/ext/berth/v1/pair/request/status   （不签名）
{"code": "<同上>"}
→ {"state": "waiting"} | {"state": "refused"} | {"state": "allowed", "code": "<Wharf 的一次性码>", "wharf_url": "https://…"}
```

- 只接受私有 / 回环 / 链路本地地址来的请求（经隧道、Cloudflare 来的都不算）。`pair/request` 只在开放窗口内回答，窗口外一律 404；`status` 在申请的 10 分钟有效期内都能查。每个来源 10 分钟最多 5 次申请；同时最多 5 个待处理。
- `wharf_fp` 必须等于 Wharf 本地 CA 指纹，否则 400（中间可能有人换了证书）。
- **校验码**：`sha256("berth-wharf-sas" + code + berth_fp + wharf_fp)`（直接拼接这几个字符串）取前 8 字节，`[0:4]` 和 `[4:8]` 各按大端 uint32 对 1000 取余，格式 `%03d %03d`。
- 申请在页面顶部显示（名字、来源 IP、地址、校验码）。管理员点「允许」时勾选范围、Berth 主机（按申请来源自动选好）、有效期，并且**无论用哪种登录方式都要再验证一次身份**（密码或 Passkey）。允许后窗口关闭，其他待处理的申请自动拒绝。
- `allowed` 时 Berth 用拿到的 `code` 走 §3 的 `POST /pair/exchange`，`wharf_url` 是 Berth 申请时访问 Wharf 用的地址。之后流程不变。

### 8.4 签名不带令牌

- 请求头 `X-Berth-Key: hex(sha256(token))[:16]`（小写），不带 `Authorization`。Wharf 按这个标识找到令牌（`substr(token_hash,1,16)`），验签方式不变。
- 过渡期两种都收：带了 `X-Berth-Key` 按新方式，否则按旧方式。
- Wharf 一旦收到 Berth 的 v2 请求就切换（`berth_link.key_auth=1`），之后 Wharf → Berth 只发 `X-Wharf-Key`。Berth 收到 `X-Wharf-Key` 时请按同样方式校验。
- 配对时的 `pair/exchange` 和轮换令牌时仍然需要传令牌本身（走固定指纹的 TLS）。

### 8.5 互联状态

`GET /api/berth/conn`（超级管理员，面板内部用）：页面每 30 秒取一次；服务端最多 25 秒测一次。

- 先用一个签名的 `GET /ping` 建立连接，再在这条连接上测 3 次，延迟取最小值，抖动取相邻样本差的平均。
- 对方 IP 取实际连接的远端地址（`httptrace.GotConn`），不用 DNS 结果。
- 分类：`tailscale`（100.64.0.0/10、`fd7a:115c:a1e0::/48`，先判断）→ `lan`（私有、回环、链路本地）→ `public`。
- 公网时的 `via`：证书指纹匹配为 `direct`；否则看响应头，`Cf-Ray` 或 `Server: cloudflare` 为 `cloudflare`，`X-Amz-Cf-Id` 为 `cloudfront`，`X-Served-By` / `X-Fastly-Request-Id` 为 `fastly`，其余为 `proxy`。后几种页面会提示加密在代理处解开。
- 位置只用本地国家库，不把对方 IP 发给任何外部服务。

### 8.6 本地域名（scope `dns`）

```
GET    /api/ext/berth/v1/dns/names                       → {"items": [{"name": "mini.lan", "ip": "192.168.1.20"}], "suffixes": ["lan"], "max": 5}
PUT    /api/ext/berth/v1/dns/names/{name}  {"ip": "…"}   → {"ok": true, "name": "mini.lan", "ip": "192.168.1.20"}
DELETE /api/ext/berth/v1/dns/names/{name}                → {"ok": true}
```

- 名字只能以 `.lan` 或 dnsmasq 配置的本地域名（`domain`）结尾，每段只能有字母、数字、连字符。
- IP 必须是 Berth 主机的地址（`targets` 里的，或带 MAC 的目标现在的地址），否则 403。
- 最多 5 个；和别人登记的「自定义解析」重名时 409。
- 写进 `/etc/config/dhcp` 的 `domain` 段（段名 `owpb_…`），`owned` 表里 `kind=berth_dns`、属主 0。「DHCP 与 DNS」和「网络工具 → 自定义解析」里标注「由 Berth 登记」，可以手动删除。
- 记入审计（执行者「Berth（名称）」，可还原）。解除配对时全部删除。

### 8.7 数据（迁移 v23）

- `berth_link.urls`：Berth 的全部地址（JSON 数组）；`berth_link.url` 是上次成功的那个。
- `berth_link.key_auth`：Berth 是否已改用 `X-Berth-Key`。

## 9. 协议 v3（Wharf 0.25.0 起）

`GET /ping` 回答 `"protocol": 3`。双方都 ≥ 3 时才使用本节；否则一切按 v2。

### 9.1 名字

```
GET /api/ext/berth/v1/names        （签名，不需要额外权限；Berth 提供同样的 /api/ext/wharf/v1/names）
→ {"lan": "https://wharf.lan", "public": "https://wharf.example.com", "lan_fp": "<本地 CA 指纹>"}
```

- `lan`：`https://<panel.lan_host>.<dnsmasq 域名>`。开启「不带端口」（`panel.lan443`）后没有端口，否则带面板端口。
- `public`：按顺序取第一个：经 443 或橙色云的公网名字 → 隧道名字 → 开了面板端口的公网名字（带端口）。没有就是空串。
- Wharf 读 Berth 的 `/names`：配对完成后、收到 `link.updated` / `names.changed` 事件后，以及测互联状态时（最多 5 分钟一次）。Wharf 自己的名字变了，会给 Berth 发 `link.updated`（带 `names`）。

### 9.2 互联方式

- `/pair/berth?...&mode=lan|public`、`pair/request {…, "mode"}`；内网发现一律是 `lan`。授权页第一步让管理员选，默认按 `mode`（没给时按 `berth_url` 是不是内网地址）。
- `pair/exchange` 返回多带 `"mode"`、`"names": {"lan", "public", "lan_fp"}`；`wharf_url` 是所选方式下 Wharf 的名字。
- 选定后只用对方那一种名字（`berth_link.mode` + `peer_lan` / `peer_public`），**连不上不换另一种**；错误按步骤说明（解析不到 / 连不上 / 证书不对 / 超时）。
- 切换：`POST /events {"type": "link.mode", "mode": "lan|public"}`，两个方向都一样，令牌不变。Wharf 一侧切换前会确认双方都有对应的名字。

### 9.3 免登录带上名字

- Berth → Wharf：`POST /sso/ticket {"berth_user", "return_to", "via": "lan|public"}` → `{"url", "via"}`，`url` 以 Wharf 对应的名字开头；没有那个名字时用另一个，`via` 说明实际用的是哪个。
- Wharf → Berth：`POST /sso/ticket {"wharf_user", "return_to", "ref", "via"}`。Wharf 接受以 Berth 任一已知名字或地址开头的 `url`。
- 浏览器一侧怎么选 `via`：页面是用内网名字或内网 IP 打开的 → `lan`；用公网名字打开的 → 后台试连 Berth 的内网名字 1.5 秒，不通用 `public`，通了就弹出选择菜单（推荐内网）；对方只有一种名字且和当前入口不一致时也弹菜单；菜单可以「记住这台设备的选择」。

### 9.4 统计（scope `stats`，只读）

| 接口 | 内容（和 Wharf 页面用的 JSON 相同） |
|---|---|
| `GET /stats/summary` | 见下 |
| `GET /stats/traffic?from=&to=`（或 `range=1h\|today\|24h\|7d\|30d\|90d`） | `/api/traffic/overview` |
| `GET /stats/geo?range=1h\|24h\|7d` | `/api/geo/flows` |
| `GET /stats/visitors?range=1h\|24h\|7d\|30d&cc=&q=&match=&limit=&before_id=` | `/api/visitors`（`{items, geo_ready}`） |
| `GET /stats/devices` | `/api/devices` |
| `GET /stats/devices/{mac}/traffic?from=&to=` | `/api/devices/{mac}/traffic` |
| `GET /stats/devices/{mac}/presence` | `/api/devices/{mac}/presence` |
| `GET /stats/dns?range=1h\|1d\|7d\|30d` | `/api/nextdns/summary`；没连接 NextDNS 时 404 |
| `GET /stats/forwards/{id}?range=` | `/api/forwards/{id}/stats`；不是 Berth 建的映射 404 |

`/stats/summary`：`devices {online,total}`、`today {up,down}`（今天 0 点起）、`visitors_24h {count,countries}`、`blocked_24h {attacks（被拒绝的面板访问）, dns（NextDNS 拦截次数）}`、`series_24h [{t,up,down}]`（按小时）、`top_devices`（今天前 5）、`top_countries`（24 小时访客前 5）、`pages`、`filters`（各页面支持的筛选参数）。服务端缓存 25 秒。

页面支持的筛选参数（`return_to` 用）：`/traffic?range=`、`/visitors?cc=&q=&match=&range=`、`/world?range=`、`/devices?q=`、`/devices/{mac}`、`/dns?range=&q=`。

### 9.5 不带端口：路由器的 443

LuCI（uhttpd）照旧监听 443。开启「不带端口」后，Wharf 加一条防火墙转发 `owp_lan443`：从 LAN 访问路由器 LAN 地址 443 的 TCP 连接转到 agent 的分流器（20445）。分流器只读 ClientHello、不解开 TLS：Wharf 的名字（内网名字、公网名字）交给面板（127.0.0.1:20090，带 PROXY 协议头），其余（用 IP 打开、其他名字、明文 HTTP）原样交给 127.0.0.1:443 的 uhttpd。关闭后删掉这条转发，443 回到 uhttpd 独占。在家里，公网名字也解析到 LAN 地址、经同一个分流器到面板。用 IP:端口 或旧名字打开面板时，浏览器先在后台试连内网名字，能打开（解析得到、证书已信任）才跳过去，否则在页面顶部提示怎么修。

### 9.6 数据（迁移 v24）

`berth_link.mode`（`''` = v2 地址列表）、`peer_lan`、`peer_public`、`peer_protocol`。设置：`panel.lan_host`、`panel.lan443`。路由器：uci `owp.lan443`（`enabled`、`list name`），防火墙 `owp_lan443`。
