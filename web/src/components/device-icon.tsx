import { Camera, Cpu, Gamepad2, HardDrive, HelpCircle, Laptop, Printer, Refrigerator, Router, Server, Smartphone, Speaker, Tablet, Tv, Watch } from 'lucide-react'
import { cn } from '@/lib/utils'

const ICONS: Record<string, typeof Smartphone> = {
  手机: Smartphone, 平板: Tablet, 电脑: Laptop, 手表: Watch, '电视/投屏': Tv, 智能音箱: Speaker, 摄像头: Camera,
  智能家电: Refrigerator, '路由/AP': Router, 'NAS/服务器': HardDrive, 虚拟机: Server, 游戏机: Gamepad2, 打印机: Printer, 物联网: Cpu,
}

export function DeviceIcon({ type, online, className }: { type?: string; online?: boolean; className?: string }) {
  const Icon = (type && ICONS[type]) || HelpCircle
  return (
    <span className={cn('relative grid size-8 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground', className)}>
      <Icon className="size-4" />
      {online !== undefined && <span className={cn('absolute -bottom-0.5 -right-0.5 size-2.5 rounded-full border-2 border-card', online ? 'bg-success' : 'bg-muted-foreground/40')} />}
    </span>
  )
}

export const TYPE_BY: Record<string, string> = { manual: '手动设置', hostname: '按主机名', vendor: '按 MAC 厂商', dns: '按访问的平台', random: '隐私 MAC（多为手机 / 平板）' }
