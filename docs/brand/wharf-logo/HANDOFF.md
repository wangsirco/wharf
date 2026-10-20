# Wharf 码头 · Logo 交接（定稿 D5「船靠桩」）

> 给接手的 Claude：本目录是已定稿的 Wharf logo 全套资源。你的任务是把它们**接入面板**，替换掉现在临时用的 lucide `Router` 图标和旧 PNG。不要重新设计 logo。

- **设计简报**：[../LOGO-BRIEF.md](../LOGO-BRIEF.md)
- **图形含义**：侧视，一条小船（带船舱）停靠在一根码头桩前，船体用一圈白边和桩分开，表现前后层次。码头 = 路由器，船 = 数据包。**不使用字母 W**（太像万豪酒店，已否决）。

## 颜色

| 用途 | 值 |
|---|---|
| 主色（浅色背景上的图形标） | `#2563eb` |
| 深色模式图形标 | `#60a5fa` |
| 应用图标渐变（从上到下） | `#3b8bf6 → #1d5fe0` |
| 文字 `Wharf`（浅 / 深） | `#0f172a` / `#ffffff` |
| 文字 `码头`（浅 / 深） | `#64748b` / `#94a3b8` |
| PWA 背景 / 主题色（保持不变） | `#0b1220` / `#1d5fe0` |

字体：`Wharf` 用 Geist SemiBold，字距 -3%；`码头` 用 Noto Sans SC Medium。SVG 里的文字都已转成曲线，不依赖本机字体。

## 文件清单

```
docs/brand/wharf-logo/
├── favicon.ico                     32px（单尺寸，由 sips 生成）
├── svg/
│   ├── favicon.svg                 浏览器标签页图标，用 prefers-color-scheme 自动切换浅/深色
│   ├── mark.svg                    图形标 彩色 #2563eb（104×104，无留白）
│   ├── mark-dark.svg               图形标 深色模式 #60a5fa
│   ├── mark-white.svg / mark-black.svg   单色版
│   ├── app-icon.svg                圆角方块应用图标 512（渐变底 + 白色图形标）
│   ├── app-icon-maskable.svg       满版方块，图形标在中心 80% 安全区内
│   ├── app-icon-square.svg         满版方块（apple-touch / GitHub 头像用）
│   ├── wordmark-en-{light,dark}.svg        仅文字「Wharf」
│   ├── wordmark-zh-en-{light,dark}.svg     文字「Wharf 码头」
│   ├── lockup-horizontal-{light,dark,white,black}.svg   横版：图形 + Wharf 码头
│   ├── lockup-horizontal-en-{light,dark}.svg            横版：图形 + Wharf
│   └── readme-banner-{light,dark}.svg      README 横幅 1280×320，透明底
├── png/
│   ├── favicon-16.png / favicon-32.png / favicon-48.png
│   ├── icon-192.png / icon-512.png         PWA「any」（圆角，透明四角）
│   ├── icon-maskable-512.png               PWA maskable（满版）
│   ├── apple-touch-icon-180.png            iOS 主屏幕（满版，iOS 会自己加圆角）
│   ├── github-avatar-512.png               GitHub 仓库 / 组织头像
│   ├── social-card-1280x640.png            GitHub Social preview
│   ├── readme-banner-{light,dark}.png
│   └── mark-1024.png / mark-white-1024.png
└── source/
    ├── social-card.svg             社交图源文件（标语用系统字体，仅作源文件，不要直接引用）
    └── gen.py                      SVG 生成脚本
```

## 接入步骤（建议）

### 1. 替换 `web/public/` 里的静态图标

文件名和现有引用保持一致，这样 `index.html` 和 Go 端的 manifest 都不用改路径：

| 复制源 | → 目标 |
|---|---|
| `svg/favicon.svg` | `web/public/favicon.svg` |
| `svg/app-icon.svg` | `web/public/icon.svg`（先确认这个文件在哪里被引用） |
| `png/icon-192.png` | `web/public/icon-192.png` |
| `png/icon-512.png` | `web/public/icon-512.png` |
| `png/icon-maskable-512.png` | `web/public/icon-maskable.png` |
| `png/apple-touch-icon-180.png` | `web/public/apple-touch-icon.png` |
| `favicon.ico`（可选） | `web/public/favicon.ico` |

- Manifest 由 Go 动态生成：`internal/panel/handlers.go` 里的 `handleManifest`，引用的是 `/icon-192.png`、`/icon-512.png`、`/icon-maskable.png`。文件名不变就不用改代码。
- `web/index.html` 已经引用 `/favicon.svg` 和 `/apple-touch-icon.png`。可以再补一行 PNG 回退：`<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">`（需要同时把 `png/favicon-32.png` 复制过去）。
- `web/public/sw.js` 如果缓存了图标，记得改它的缓存版本号，否则已安装的 PWA 还会显示旧图标。
- `web/dist/` 是构建产物，重新 build 即可，不要手改。

### 2. 用图形标组件替换界面里的 `<Router>` 图标

下面这些地方现在用的是 lucide `Router` 图标加一个蓝色圆角块，充当临时 logo：

- `web/src/components/layout.tsx:57` 和 `:182`：侧栏和移动端顶栏，`size-8` 的蓝色圆角块
- `web/src/pages/login.tsx:30`：登录页，`size-11`
- `web/src/components/welcome.tsx:175`：欢迎页渐变头部里的白色半透明块

建议新建 `web/src/components/brand-mark.tsx`，内联 SVG，颜色用 `currentColor`，这样可以继承 `text-primary-foreground` 等 Tailwind 颜色：

```tsx
// 104×104 viewBox，图形本身无留白；外层容器负责留白和底色
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 104 104" fill="currentColor" aria-hidden className={className}>
      <path d="M92.76 0C95.74 0 98.6 1.19 100.71 3.29C102.81 5.4 104 8.26 104 11.24V104H81.51V101.52C84.58 99.54 87.13 96.57 89.23 93.36C91.6 89.75 93.71 85.38 95.57 80.59C99.29 70.99 102.2 59.13 103.94 46.97C104.26 44.7 103.3 42.43 101.43 41.08C99.57 39.74 97.11 39.54 95.05 40.57L81.51 47.33V11.24C81.51 8.26 82.7 5.4 84.81 3.29C86.92 1.19 89.77 0 92.76 0ZM97.82 46.1C94.45 69.71 86.57 91.63 77.58 96.69C75.33 97.82 72.71 98.38 69.71 98.38H6.75C2.25 98.38 0 96.13 0 91.63V55.09H79.83L97.82 46.1ZM39.91 31.48C41.4 31.48 42.83 32.07 43.89 33.13C44.94 34.18 45.53 35.61 45.53 37.1V42.72C45.53 44.21 44.94 45.64 43.89 46.7C42.83 47.75 41.4 48.34 39.91 48.34H14.61C13.12 48.34 11.69 47.75 10.64 46.7C9.59 45.64 8.99 44.21 8.99 42.72V37.1C8.99 35.61 9.59 34.18 10.64 33.13C11.69 32.07 13.12 31.48 14.61 31.48H39.91Z" />
    </svg>
  )
}
```

用法：保持现在的方块容器不变，只把 `<Router className="size-4.5" />` 换成 `<BrandMark className="size-5" />`。图形标在方块里约占 60–64% 时观感最好：`size-8` 方块用 `size-5`，`size-11` 方块用 `size-7`。容器底色可以从 `bg-primary` 换成 `bg-gradient-to-b from-[#3b8bf6] to-[#1d5fe0]`，和应用图标保持一致（可选）。

注意：`web/src/components/device-icon.tsx` 里的 `Router` 是**设备类型图标**（表示局域网里的一台路由器），不是 logo，**不要替换**。

### 3. LuCI 菜单（`package/luci-app-wharf`）

如果 LuCI 菜单或插件页需要图标，用 `svg/app-icon.svg`（圆角）或 `png/icon-192.png`。

### 4. README 和 GitHub

README 顶部横幅用 `<picture>` 按 GitHub 主题切换：

```html
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/wharf-logo/svg/readme-banner-dark.svg">
    <img alt="Wharf 码头" src="docs/brand/wharf-logo/svg/readme-banner-light.svg" width="640">
  </picture>
</p>
```

- GitHub Settings → Social preview：上传 `png/social-card-1280x640.png`（需要用户本人手动上传）
- 仓库或组织头像：`png/github-avatar-512.png`

## 已知局限 / 后续可做

- `favicon.ico` 只有 32px 一个尺寸；如果需要包含 16/32/48 的多尺寸 ico，得另外找工具生成（本机没有 ImageMagick / PIL）。
- PNG 是 headless Chrome 渲染 SVG 后再用 `sips` 缩小得到的，16px 没有做逐像素对齐。如果 16px 看起来发糊，可以在 Figma 里对 `mark/D5` 按 16 栅格微调后重新导出。
- 社交图里的中文标语是用系统字体（PingFang SC）渲染的；Figma 里的版本（`social-card` 画板）用的是 Noto Sans SC，两者略有差别。
- 生成脚本：`source/gen.py` 会根据三段路径数据（图形 / Wharf / 码头，来自 Figma 导出）重新生成 `svg/` 和 `source/social-card.svg`，用法是 `python3 source/gen.py docs/brand/wharf-logo`。要改颜色或尺寸就改这个脚本；PNG 需要另外用 headless Chrome 渲染后再用 `sips` 缩小。
