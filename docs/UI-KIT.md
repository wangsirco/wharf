# Wharf UI Kit：可复用到其他网站的设计与组件清单

> 从 Wharf 面板（`web/`）里整理出来、可以直接拿去做网站的部分：开源库、设计令牌（颜色 / 圆角 / 字体）、自研小组件、图表、图标，以及手机端适配的经验。
> 所有路径都相对于本仓库的 `web/src/`。

---

## 1. 技术栈总览

| 用途 | 库 | 版本 | 许可证 | 说明 |
|---|---|---|---|---|
| 框架 | [React](https://react.dev) | 19.3 | MIT | |
| 构建 | [Vite](https://vite.dev) + `@vitejs/plugin-react` | 8.3 | MIT | |
| 样式 | [Tailwind CSS v4](https://tailwindcss.com) + `@tailwindcss/vite` | 4.3 | MIT | v4 不需要 `tailwind.config.js`，主题写在 CSS 的 `@theme` 里 |
| 组件骨架 | [shadcn/ui](https://ui.shadcn.com)，风格 **base-nova** | CLI 4.21 | MIT | 组件源码会被**复制进你的项目**（`components/ui/`），可以随意改 |
| 无样式交互原语 | [Base UI](https://base-ui.com)（`@base-ui/react`） | 1.8 | MIT | shadcn 新版可以选 Base UI 代替 Radix；这里选的是 Base UI |
| 图标 | [Lucide](https://lucide.dev)（`lucide-react`） | 1.52 | ISC | 全站统一用这一套线性图标 |
| 字体 | [Geist](https://vercel.com/font)（`@fontsource-variable/geist`） | 5.3 | OFL-1.1 | 本地打包，不走 Google Fonts |
| 提示消息 | [Sonner](https://sonner.emilkowal.ski) | 2.0 | MIT | 右下角 toast |
| 变体管理 | [class-variance-authority](https://cva.style) | 0.7 | Apache-2.0 | 按钮等组件的 `variant` / `size` |
| 类名合并 | `cn` | 0.4 | MIT | 相当于 `clsx + tailwind-merge` |
| 动画 | `tw-animate-css` | 1.4 | MIT | 弹窗、抽屉的进出动画 |
| 路由 | React Router | 7.18 | MIT | |
| 世界地图 | [Apache ECharts](https://echarts.apache.org)（按需引入） | 6.1 | Apache-2.0 | 只在地图页懒加载 |
| 地图数据 | [world-atlas](https://github.com/topojson/world-atlas) + [topojson-client](https://github.com/topojson/topojson-client) | 2.0 / 3.1 | ISC | Natural Earth 110m 国界 |

**普通图表（环形图、面积图、柱状图、热力图）都是手写的 SVG / div，没有引入图表库**，体积小、风格统一。

所有资源都打包在本地，没有任何 CDN 请求。这是故意的：面板要部署在内网和公网，不能依赖外部网络。

---

## 2. 从零搭一个同款项目

```bash
npm create vite@latest my-site -- --template react-ts
```

```bash
cd my-site && npm i tailwindcss @tailwindcss/vite @fontsource-variable/geist lucide-react sonner
```

```bash
npx shadcn@latest init
```

`init` 时选择 **Base UI** 和 **base-nova** 风格，基础色选 **neutral**。完成后的 `components.json` 关键字段如下：

```json
{
  "style": "base-nova",
  "tailwind": { "css": "src/index.css", "baseColor": "neutral", "cssVariables": true },
  "iconLibrary": "lucide"
}
```

按需加组件（本项目用到的全部组件）：

```bash
npx shadcn@latest add button input textarea label select checkbox switch tabs table dialog sheet dropdown-menu tooltip badge card alert avatar separator skeleton sonner
```

然后把下一节的 `index.css` 整段替换进去，**整套配色就一样了**。

`vite.config.ts` 里加上 `@` 别名：

```ts
import path from 'node:path'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, 'src') } },
})
```

---

## 3. 设计令牌（`src/index.css`）

风格参考 UniFi：浅灰画布、白色卡片、蓝色强调色。颜色全部用 **OKLCH** 定义，好处是明暗两套主题的亮度更均匀，调色也更直观（L = 亮度，C = 饱和度，H = 色相）。

```css
@import "tailwindcss";
@import "tw-animate-css";
@import "shadcn/tailwind.css";
@import "@fontsource-variable/geist";

@custom-variant dark (&:is(.dark *));

@theme inline {
  --font-heading: var(--font-sans);
  --font-sans: 'Geist Variable', sans-serif;
  /* 把 CSS 变量注册成 Tailwind 颜色：bg-primary、text-success、bg-chart-1 …… */
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-popover: var(--popover);
  --color-popover-foreground: var(--popover-foreground);
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  --color-secondary: var(--secondary);
  --color-secondary-foreground: var(--secondary-foreground);
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  --color-accent: var(--accent);
  --color-accent-foreground: var(--accent-foreground);
  --color-destructive: var(--destructive);
  --color-success: var(--success);   /* shadcn 默认没有，自己加的 */
  --color-warning: var(--warning);   /* 同上 */
  --color-border: var(--border);
  --color-input: var(--input);
  --color-ring: var(--ring);
  --color-chart-1: var(--chart-1);
  --color-chart-2: var(--chart-2);
  --color-chart-3: var(--chart-3);
  --color-chart-4: var(--chart-4);
  --color-chart-5: var(--chart-5);
  --color-sidebar: var(--sidebar);
  --color-sidebar-foreground: var(--sidebar-foreground);
  --color-sidebar-primary: var(--sidebar-primary);
  --color-sidebar-primary-foreground: var(--sidebar-primary-foreground);
  --color-sidebar-accent: var(--sidebar-accent);
  --color-sidebar-accent-foreground: var(--sidebar-accent-foreground);
  --color-sidebar-border: var(--sidebar-border);
  --color-sidebar-ring: var(--sidebar-ring);
  /* 圆角阶梯：全部由一个 --radius 派生 */
  --radius-sm: calc(var(--radius) * 0.6);
  --radius-md: calc(var(--radius) * 0.8);
  --radius-lg: var(--radius);
  --radius-xl: calc(var(--radius) * 1.4);
  --radius-2xl: calc(var(--radius) * 1.8);
  --radius-3xl: calc(var(--radius) * 2.2);
  --radius-4xl: calc(var(--radius) * 2.6);
}

:root {
  /* UniFi-like: neutral light grey canvas, white surfaces, blue accent */
  --background: oklch(0.975 0.003 264);
  --foreground: oklch(0.24 0.01 264);
  --card: oklch(1 0 0);
  --card-foreground: oklch(0.24 0.01 264);
  --popover: oklch(1 0 0);
  --popover-foreground: oklch(0.24 0.01 264);
  --primary: oklch(0.58 0.21 258);
  --primary-foreground: oklch(0.99 0 0);
  --secondary: oklch(0.955 0.005 264);
  --secondary-foreground: oklch(0.3 0.01 264);
  --muted: oklch(0.955 0.005 264);
  --muted-foreground: oklch(0.55 0.015 264);
  --accent: oklch(0.95 0.02 258);
  --accent-foreground: oklch(0.45 0.18 258);
  --destructive: oklch(0.6 0.22 25);
  --success: oklch(0.65 0.15 155);
  --warning: oklch(0.78 0.15 75);
  --border: oklch(0.92 0.005 264);
  --input: oklch(0.9 0.006 264);
  --ring: oklch(0.58 0.21 258);
  --chart-1: oklch(0.58 0.21 258);
  --chart-2: oklch(0.7 0.15 160);
  --chart-3: oklch(0.75 0.15 70);
  --chart-4: oklch(0.62 0.2 300);
  --chart-5: oklch(0.65 0.2 25);
  --radius: 0.5rem;
  --sidebar: oklch(1 0 0);
  --sidebar-foreground: oklch(0.35 0.01 264);
  --sidebar-primary: oklch(0.58 0.21 258);
  --sidebar-primary-foreground: oklch(0.99 0 0);
  --sidebar-accent: oklch(0.95 0.02 258);
  --sidebar-accent-foreground: oklch(0.5 0.2 258);
  --sidebar-border: oklch(0.92 0.005 264);
  --sidebar-ring: oklch(0.58 0.21 258);
}

.dark {
  --background: oklch(0.17 0.006 264);
  --foreground: oklch(0.93 0.004 264);
  --card: oklch(0.215 0.007 264);
  --card-foreground: oklch(0.93 0.004 264);
  --popover: oklch(0.235 0.007 264);
  --popover-foreground: oklch(0.93 0.004 264);
  --primary: oklch(0.65 0.18 256);
  --primary-foreground: oklch(0.99 0 0);
  --secondary: oklch(0.27 0.008 264);
  --secondary-foreground: oklch(0.93 0.004 264);
  --muted: oklch(0.27 0.008 264);
  --muted-foreground: oklch(0.68 0.01 264);
  --accent: oklch(0.3 0.04 258);
  --accent-foreground: oklch(0.82 0.1 256);
  --destructive: oklch(0.68 0.19 25);
  --success: oklch(0.72 0.14 155);
  --warning: oklch(0.8 0.14 75);
  --border: oklch(1 0 0 / 9%);     /* 深色下用半透明白边，比实色更柔和 */
  --input: oklch(1 0 0 / 14%);
  --ring: oklch(0.65 0.18 256);
  --chart-1: oklch(0.65 0.18 256);
  --chart-2: oklch(0.72 0.14 160);
  --chart-3: oklch(0.78 0.14 70);
  --chart-4: oklch(0.68 0.18 300);
  --chart-5: oklch(0.7 0.18 25);
  --sidebar: oklch(0.2 0.007 264);
  --sidebar-foreground: oklch(0.85 0.006 264);
  --sidebar-primary: oklch(0.65 0.18 256);
  --sidebar-primary-foreground: oklch(0.99 0 0);
  --sidebar-accent: oklch(0.3 0.04 258);
  --sidebar-accent-foreground: oklch(0.85 0.1 256);
  --sidebar-border: oklch(1 0 0 / 9%);
  --sidebar-ring: oklch(0.65 0.18 256);
}

@layer base {
  * { @apply border-border outline-ring/50; }
  body { @apply bg-background text-foreground; }
  html { @apply font-sans; }
}
@layer base {
  /* 数字等宽：网速、流量跳动时不抖 */
  body { @apply antialiased; font-feature-settings: "tnum" 1; }
  /* 手机端关键修复：grid 子元素允许缩到比内容还窄，
     否则一个长表格 / 长日志会把整列撑出屏幕 */
  :where(.grid) > * { min-width: 0; }
  html, body { overflow-x: clip; }
}
```

### 颜色怎么用

| 令牌 | 用在哪里 | 典型写法 |
|---|---|---|
| `background` | 页面底色（浅灰） | `bg-background` |
| `card` | 所有卡片、表格容器（纯白） | `rounded-xl border bg-card` |
| `primary` | 主按钮、选中态、链接、主数据线 | `bg-primary text-primary-foreground` |
| `accent` | 侧栏当前项、蓝色标签的浅底 | `bg-accent text-accent-foreground` |
| `muted` / `muted-foreground` | 次要文字、图标底块、进度条底 | `text-muted-foreground`、`bg-muted` |
| `success` | 在线、正常、上行 | `bg-success`、`bg-success/12 text-success` |
| `warning` | 提醒、关键操作标记 | `bg-warning/18` |
| `destructive` | 断网、删除、错误 | `bg-destructive/10 text-destructive` |
| `chart-1` … `chart-5` | 图表系列色（蓝、绿、黄、紫、红） | `bg-chart-1`、`var(--chart-2)` |

**核心手法：彩色元素一律用"10%～18% 透明度的浅底 + 同色文字"**，例如 `bg-destructive/10 text-destructive`。这样不会刺眼，深色模式也自动适配。实色只用在主按钮和小圆点上。

### 主题切换（`lib/theme.ts`）

```ts
export type Theme = 'light' | 'dark' | 'system'

export function getTheme(): Theme {
  try { return (localStorage.getItem('owp-theme') as Theme) || 'system' } catch { return 'system' }
}

export function applyTheme(t: Theme) {
  try { localStorage.setItem('owp-theme', t) } catch { /* private mode */ }
  const dark = t === 'dark' || (t === 'system' && matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.classList.toggle('dark', dark)
}
```

---

## 4. 排版与间距约定

整个面板显得"精致"，主要靠下面这些一致的小规则：

| 元素 | 规则 |
|---|---|
| 页面标题 | `text-xl font-semibold tracking-tight`，下面一行说明 `text-sm text-muted-foreground` |
| 卡片 | `rounded-xl border bg-card`，**没有阴影**，只靠 1px 浅边框区分层级 |
| 卡片标题栏 | `border-b px-4 py-3`，标题 `text-sm font-semibold` + 说明 `text-xs text-muted-foreground` |
| 列表行 | `divide-y` 分隔，行内 `px-4 py-2.5`，不用斑马纹 |
| 大数字 | `text-xl sm:text-2xl font-semibold tracking-tight tabular-nums` |
| 小标签文字 | `text-[11px]` 或 `text-xs`；MAC、IP、端口用 `font-mono` |
| 卡片之间 | `gap-4`，手机上 `gap-3` |
| 页面边距 | `p-3 sm:p-4 md:p-6` |
| 控件高度 | 按钮和输入框统一 `h-8`（小号 `h-7`），表格行内按钮用 `size="icon-sm"` |
| 侧栏 | 宽 `w-56`，当前项 `bg-accent text-accent-foreground`，图标 `size-4` |
| 顶栏 | `sticky top-0 h-12 border-b bg-background/85 backdrop-blur`（半透明毛玻璃） |

---

## 5. 自研小组件（可直接复制）

这些在 `components/common.tsx`、`components/monitor.tsx`、`components/device-icon.tsx` 里，都只依赖 Tailwind 和 `cn`。

### Section：带标题栏的卡片（全站最常用）

```tsx
export function Section({ title, desc, children, action, className }: {
  title: string; desc?: string; children: ReactNode; action?: ReactNode; className?: string
}) {
  return (
    <section className={cn('rounded-xl border bg-card', className)}>
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b px-4 py-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">{title}</h2>
          {desc && <p className="text-xs text-muted-foreground">{desc}</p>}
        </div>
        {action}
      </div>
      <div>{children}</div>
    </section>
  )
}
```

### Kpi：数字卡片

```tsx
export function Kpi({ icon: Icon, label, value, sub, tone, onClick, big }: {
  icon: LucideIcon; label: string; value: ReactNode; sub?: ReactNode
  tone?: 'red' | 'amber' | 'green'; onClick?: () => void; big?: boolean
}) {
  const t = tone === 'red' ? 'text-destructive'
    : tone === 'amber' ? 'text-[color-mix(in_oklch,var(--warning),black_30%)] dark:text-warning'
    : tone === 'green' ? 'text-success' : ''
  return (
    <div onClick={onClick} className={cn('min-w-0 rounded-xl border bg-card p-3 sm:p-4', onClick && 'cursor-pointer transition-colors hover:bg-muted/50')}>
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground"><Icon className="size-3.5" />{label}</div>
      <div className={cn('mt-1.5 font-semibold tracking-tight tabular-nums', big ? 'text-2xl sm:text-4xl' : 'text-xl sm:text-2xl', t)}>{value}</div>
      {sub && <div className="mt-0.5 truncate text-xs text-muted-foreground">{sub}</div>}
    </div>
  )
}
```

放在 `grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4` 里：手机两列，大屏四列。

> 小技巧：黄色文字在白底上对比度不够，所以用 `color-mix(in_oklch, var(--warning), black 30%)` 把它压暗，深色模式再换回原色。

### Pill：圆角状态标签

```tsx
export function Pill({ tone = 'muted', children }: { tone?: 'muted' | 'blue' | 'green' | 'amber' | 'red'; children: ReactNode }) {
  const c = {
    muted: 'bg-muted text-muted-foreground',
    blue: 'bg-accent text-accent-foreground',
    green: 'bg-success/12 text-success',
    amber: 'bg-warning/18 text-[color-mix(in_oklch,var(--warning),black_35%)] dark:text-warning',
    red: 'bg-destructive/10 text-destructive',
  }[tone]
  return <span className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium whitespace-nowrap', c)}>{children}</span>
}
```

### Tag：带描边的方角小标签（如"PVE 虚拟机"）

```tsx
export function Tag({ children }: { children: ReactNode }) {
  return <span className="inline-flex shrink-0 items-center rounded-md border border-violet-500/30 bg-violet-500/10 px-1.5 py-px text-[10px] font-medium whitespace-nowrap text-violet-600 dark:text-violet-300">{children}</span>
}
```

Pill（全圆角）表示**状态**，Tag（小圆角 + 描边）表示**属性 / 分类**，两者别混用。

### Dot：状态小圆点

```tsx
export function Dot({ tone }: { tone: 'ok' | 'warn' | 'bad' | 'off' }) {
  const c = { ok: 'bg-success', warn: 'bg-warning', bad: 'bg-destructive', off: 'bg-muted-foreground/40' }[tone]
  return <span className={cn('inline-block size-2 shrink-0 rounded-full', c)} />
}
```

"正在活跃"的呼吸点：

```tsx
<span className="relative flex size-2.5">
  <span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-60" />
  <span className="relative inline-flex size-2.5 rounded-full bg-success" />
</span>
```

### Meter：条状进度（CPU、磁盘、占比）

```tsx
function Meter({ value }: { value: number }) {
  return (
    <div className="h-1.5 w-full rounded-full bg-muted">
      <div className={cn('h-1.5 rounded-full transition-all', value > 90 ? 'bg-destructive' : value > 70 ? 'bg-warning' : 'bg-primary')}
        style={{ width: `${Math.min(100, value)}%` }} />
    </div>
  )
}
```

渐变版排行条（全球流量的国家排行）：

```tsx
<div className="h-1 rounded-full bg-muted">
  <div className="h-1 rounded-full bg-gradient-to-r from-sky-500 to-cyan-300" style={{ width: `${pct}%` }} />
</div>
```

### IconTile：带在线角标的图标块（设备图标）

```tsx
<span className="relative grid size-8 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground">
  <Icon className="size-4" />
  <span className={cn('absolute -bottom-0.5 -right-0.5 size-2.5 rounded-full border-2 border-card', online ? 'bg-success' : 'bg-muted-foreground/40')} />
</span>
```

`border-2 border-card` 让角标和卡片底色之间留出一圈"缝"，这是看起来精致的关键。

设备类型到 Lucide 图标的对应表在 `components/device-icon.tsx`，例如 Smartphone、Laptop、Tv、Camera、HardDrive、Server。

### Empty / ErrorBox / Field

```tsx
export const Empty = ({ children }: { children: ReactNode }) =>
  <div className="px-4 py-12 text-center text-sm text-muted-foreground">{children}</div>

export const ErrorBox = ({ children }: { children: ReactNode }) =>
  <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">{children}</div>

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="grid gap-1.5">
      <Label className="text-xs font-medium text-muted-foreground">{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}
```

### HalfPanel：右侧半屏抽屉

基于 shadcn 的 `Sheet`：桌面端占半屏，手机端全屏。用来编辑表单，不打断列表上下文。源码在 `components/common.tsx`。

### useConfirm：Promise 风格的确认框

```tsx
const { confirm, dialog } = useConfirm()
if (!(await confirm('删除这条规则？', '删除后无法恢复。', { danger: true, ok: '删除' }))) return
// …… 记得在 JSX 里渲染 {dialog}
```

比到处写 `open/setOpen` 状态干净得多。源码在 `components/common.tsx`。

### 分段切换（简要 / 专业）

```tsx
<div className="flex shrink-0 items-center rounded-lg bg-muted p-[3px] text-xs whitespace-nowrap">
  {options.map((o) => (
    <button key={o} onClick={() => set(o)}
      className={o === value ? 'rounded-md bg-background px-2.5 py-1 font-medium shadow-sm' : 'rounded-md px-2.5 py-1 text-muted-foreground hover:text-foreground'}>
      {o}
    </button>
  ))}
</div>
```

---

## 6. 图表（全部手写，零依赖）

| 组件 | 文件 | 特点 |
|---|---|---|
| `AreaChart` | `components/chart.tsx` | SVG 面积图，多系列、自动 Y 轴、悬停十字线与提示框；`preserveAspectRatio="none"` + `vector-effect: non-scaling-stroke`，宽度任意拉伸线条也不变粗 |
| `Donut` | `components/charts.tsx` | SVG 环形图，最多 9 段，其余并入"其他"；悬停时中心显示该段；点击可筛选 |
| `LevelDonut` | `components/charts.tsx` | Donut 加"简要 / 详细"两档切换 |
| `Bars` | `components/charts.tsx` | 纯 div 堆叠柱（下行 + 上行），`max-w-6` 防止数据少时柱子过粗 |
| `Heatmap` | `components/charts.tsx` | 星期 × 24 小时热力格，颜色深浅表示用量 |
| `HourBars` | `components/charts.tsx` | 24 小时分布小柱 |
| `RangePicker` | `components/charts.tsx` | 今天 / 7 天 / 30 天 / 自定义时间段 |

图表色板（`PALETTE`）：前 5 个取 `--chart-1..5`，后 5 个是低饱和补充色，深色模式会自动跟着变：

```ts
export const PALETTE = ['var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)',
  'oklch(0.7 0.12 200)', 'oklch(0.72 0.13 340)', 'oklch(0.68 0.1 120)', 'oklch(0.6 0.08 40)', 'oklch(0.75 0.06 260)']
```

约定：**"其他"永远用灰色**（`var(--muted-foreground)`），不确定的数据也用灰色，让人一眼看出它不重要。

### 大屏风格世界地图（`components/worldmap.tsx`）

这是 ECharts 的 `geo` + `lines`（飞线）+ `effectScatter`（涟漪点）组合：
- 按需引入：`echarts/core` 加上 `LinesChart`、`EffectScatterChart`、`GeoComponent`、`CanvasRenderer`，懒加载后约 227 KB（gzip）。
- 底色是径向渐变 `radial-gradient(ellipse at center, #0b1730 0%, #060b16 75%)`，国土色 `#10213b`，国界线 `#3b6aa8`，飞线 `#38bdf8`，起点用金色 `#facc15` 加发光。
- 线宽和光点大小按对数缩放，大流量国家不会把小国家压得看不见。
- 以太平洋为中心：经度小于 -25° 的点加 360°，同时消除俄罗斯、斐济跨 180° 经线造成的横线。适合亚太地区的用户。

---

## 7. 图标

- **全站只用 Lucide**：统一 1.5～2px 线宽的线性风格。尺寸约定：正文和按钮 `size-4`、标题前小图标 `size-3.5`、大块图标 `size-6`。
- 按钮里的图标直接写 `<Button><Download /> 下载</Button>`，按钮会自动处理大小和间距。
- 应用图标（`web/public/icon.svg`）是蓝色渐变圆角方块加白色 Lucide「Router」图形，可以作为模板换成别的图形：

```svg
<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3b8bf6"/><stop offset="1" stop-color="#1d5fe0"/></linearGradient></defs>
  <rect width="512" height="512" rx="112" fill="url(#g)"/>
  <g transform="translate(96 96) scale(13.333)" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
    <!-- 把这里换成任意 Lucide 图标的 path（24×24 坐标） -->
    <rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6.01 18H6"/><path d="M10.01 18H10"/><path d="M15 10v4"/>
    <path d="M17.84 7.17a4 4 0 0 0-5.66 0"/><path d="M20.66 4.34a8 8 0 0 0-11.31 0"/>
  </g>
</svg>
```

在 macOS 上转成 PNG：

```bash
qlmanage -t -s 512 -o . icon.svg
```

---

## 8. 手机端适配经验（踩过的坑）

1. **Grid 列被撑爆**：grid 子元素默认 `min-width: auto`，一个长表格就会让整列超出屏幕。全局加上 `:where(.grid) > * { min-width: 0 }` 即可（见第 3 节）。`:where()` 的优先级为 0，不会和组件自己的类冲突。
2. **表格里的文字截断**：单元格写 `w-full max-w-0`，里面的元素才能 `truncate`。
3. **表格列太多**：手机上把次要列 `hidden md:table-cell`，把关键信息（IP、网速）折到名称下面的第二行，并加上 `md:hidden`。
4. **标签页太多**：`TabsList` 加 `max-w-full overflow-x-auto [scrollbar-width:none]`，触发器加 `shrink-0`，就能横向滑动。
5. **工具栏（筛选 + 搜索）**：容器写 `flex w-full flex-wrap gap-2 sm:w-auto`，搜索框写 `min-w-40 flex-1 sm:flex-none`。
6. **顶栏**：手机上搜索框只留图标，文字加 `hidden sm:inline`；分段切换加 `whitespace-nowrap shrink-0`，否则中文会被挤成竖排。
7. **地图、图表的高度随宽度变化**：`height: min(560px, max(240px, 62vw))`。
8. **数字卡片**：手机上两列（`grid-cols-2`），字号降一档（`text-xl sm:text-2xl`）。
9. **自动检查**：在浏览器控制台运行下面的代码，列出超出屏幕右边缘、而且不在滚动容器里的元素：

```js
const W = document.documentElement.clientWidth
;[...document.querySelectorAll('body *')].filter((e) => {
  const r = e.getBoundingClientRect()
  if (!r.width || r.right <= W + 1) return false
  for (let a = e.parentElement; a && a !== document.body; a = a.parentElement)
    if (getComputedStyle(a).overflowX !== 'visible') return false
  return true
}).slice(0, 10)
```

---

## 9. PWA（添加到主屏幕）

需要的文件在 `web/public/`：`manifest.webmanifest`、`icon-192.png`、`icon-512.png`、`icon-maskable.png`、`apple-touch-icon.png`（无圆角满版，iOS 会自己加圆角）、`sw.js`。`index.html` 里的 meta 如下：

```html
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
<meta name="theme-color" content="#1d5fe0" />
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-title" content="Wharf" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
<link rel="manifest" href="/manifest.webmanifest" />
```

---

## 10. 实用小函数（`lib/format.ts`）

| 函数 | 作用 | 示例 |
|---|---|---|
| `bytes(n)` | 字节转可读单位（1024 进制） | `231.9 MB` |
| `bitrate(Bps)` | 字节/秒转网速（1000 进制，按 bit） | `113.3 Kbps` |
| `duration(sec)` | 秒转中文时长 | `45 天 10 小时` |
| `datetime(ts)` | Unix 时间戳格式化 | `2026-10-05 22:16:10` |
| `ago(ts)` | 相对时间 | `3 分钟前` |

---

## 11. 许可证注意事项

- 上面列出的库全部可以商用（MIT / ISC / Apache-2.0 / OFL）。
  - Apache-2.0（ECharts、cva）要求分发时保留 LICENSE 和 NOTICE。
  - Geist 字体（OFL）可以随网站使用，但不能单独出售字体文件。
- shadcn/ui 的组件是复制到你项目里的源码，属于你自己的代码，可以随意修改。
- 本文档里的令牌、自研组件和图表都是这个项目自己写的，可以直接复用到你的其他网站。
- **不要照搬的部分**：`pages/` 下的业务页面，以及 `policy.tsx`、`monitor.tsx` 里和路由器 API 绑定的逻辑（`LiveDevices`、`EventsFeed` 等）。它们依赖 Wharf 的后端接口。

---

## 12. 想快速看效果

建议直接复制的文件：

| 文件 | 内容 |
|---|---|
| `index.css` | 整套配色、字体、全局修复 |
| `components/ui/*` | 按钮、输入框、表格、弹窗、标签页等基础组件（已调成本项目风格） |
| `components/common.tsx` | Section、Pill、Dot、Empty、ErrorBox、Field、HalfPanel、useConfirm |
| `components/charts.tsx`、`components/chart.tsx` | 全部图表 |
| `components/worldmap.tsx` | 大屏世界地图 |
| `lib/format.ts`、`lib/theme.ts` | 格式化函数、明暗主题 |
| `components/layout.tsx` | 侧栏 + 顶栏 + 手机抽屉的整体骨架（删掉权限判断和导航条目即可复用） |
