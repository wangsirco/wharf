# Security Policy · 安全策略

Wharf runs on routers and can change firewall rules, so we take security reports seriously.
Wharf 运行在路由器上、可以修改防火墙，我们非常重视安全问题。

**Please do not open a public issue for vulnerabilities.** Report privately via
[GitHub Security Advisories](https://github.com/wangsirco/wharf/security/advisories/new).
**请不要公开提交漏洞**，请通过上面的 Security Advisories 私下报告。

Include the version, how to reproduce, and the impact. We aim to acknowledge within 7 days.
请附上版本、复现步骤和影响范围，我们会在 7 天内回复。

Only the latest release receives security fixes. Online updates are signed (ed25519); a release
without a valid signature is never applied by the panel.
只有最新版本会获得安全修复。在线更新使用 ed25519 签名，签名无效的更新不会被安装。
