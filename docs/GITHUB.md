# GitHub 仓库信息 · Repository metadata

## 名称 · Name
- 仓库：`wangsirco/wharf`
- 显示名：**Wharf 码头**
- 安装包：`luci-app-wharf`

## 简介（About，≤ 350 字符）· Description
- **English（建议用作 About）**：A multi-admin control panel for OpenWrt / iStoreOS — see who's online and what they talk to, share port forwards safely, and diagnose your network. 🇨🇳 中文界面
- **中文**：给全家人和多位管理员一起用的 OpenWrt 控制面板：设备与流量看得懂、端口转发分得清、网络问题查得到。

## 标签 · Topics（最多 20 个）
```
openwrt  istoreos  luci  luci-app  router  router-admin  home-network
network-monitoring  traffic-analysis  port-forwarding  firewall  dnsmasq
network-diagnostics  packet-capture  multi-user  rbac  golang  react  self-hosted  pwa
```

## 其他设置 · Other settings
- Website：留空，或填 README 地址
- Social preview（需要你在网页上手动上传）：Settings → General → Social preview → `docs/brand/wharf-logo/png/social-card-1280x640.png`
- 头像（可选，个人账号头像会影响所有仓库，建议不换）：`docs/brand/wharf-logo/png/github-avatar-512.png`
- 打开：Issues、Discussions（可选）、Private vulnerability reporting（Settings → Security）
- Release 标题：`Wharf v0.17.0`；标签：`v0.17.0`

## 发布新版本 · Releasing
1. 修改 `internal/version/version.go` 的 `Version`
2. 写 `docs/release-notes/v<版本>.md`，更新 `CHANGELOG.md`
3. 提交并推送，然后：`GITHUB_TOKEN=… scripts/release.sh`
4. 签名私钥在 `~/.config/wharf/release-ed25519.key`，**请备份到安全的地方**；丢失后旧版本面板将无法验证新版本，只能手动安装一次新版本更换公钥。
