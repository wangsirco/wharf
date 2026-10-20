# Contributing to Wharf · 参与贡献

Thanks for helping! 感谢参与！Issues and PRs are welcome in English or Chinese. 中英文都可以。

## Ground rules · 基本原则

- **Never break the network.** Changes to the router must use native OpenWrt mechanisms (uci, firewall, ipset, dnsmasq) and only `reload`, never restart network / WAN.
  **不能让路由器断网**：只用 OpenWrt 原生机制，只 reload，不重启网络。
- **Everything that changes the router is audited**, and restorable where possible.
  **所有改动路由器的操作都要记入审计**，能还原的要支持还原。
- **No shell strings.** Run commands as argument arrays and validate every input.
  **不要拼 shell 命令**：命令以参数数组执行，所有输入都要校验。
- **Keep data local.** No new online dependency without an off switch.
  **数据留在本地**：新增联网功能必须可以关闭。

## Development · 开发

```sh
cd web && npm ci && npm run dev      # UI on Vite (proxies /api to a panel)
go test ./internal/...
scripts/build-ipk.sh x86_64
```

`OWP_COLLECT=0 owp-agent …` runs an API-only agent that never touches the firewall — handy on a test router.

- Go code: `gofmt`, small packages, comments that explain *why*.
- UI: React + TypeScript + Tailwind + shadcn/ui (Base UI). Reuse components from `web/src/components` (see `docs/UI-KIT.md`); every page must work at 375 px width.
- Commit messages: imperative, one topic per commit.

## Translation · 翻译

The UI is Simplified Chinese today. An i18n layer and an English translation are very welcome — please open an issue first so we can agree on the approach.
界面目前是简体中文，欢迎贡献多语言支持，动手前请先开 Issue 讨论方案。
