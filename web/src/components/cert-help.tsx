import { useState } from 'react'
import { Download, ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'
import { buttonVariants } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'

const STEPS: [string, string[]][] = [
  ['iPhone / iPad', [
    '用 Safari 打开本页，点下面的「下载证书」，选「允许」',
    '打开「设置」→ 顶部「已下载描述文件」→ 安装（需要输入锁屏密码）',
    '「设置」→「通用」→「关于本机」→ 拉到底「证书信任设置」→ 打开这张证书的开关',
    '回到 Safari 重新打开面板；添加到主屏幕的 App 也能正常打开了',
  ]],
  ['Android', [
    '点「下载证书」保存文件',
    '「设置」→「安全」→「加密与凭据」→「安装证书」→「CA 证书」，选刚下载的文件',
    '不同品牌菜单名称略有不同，可在设置里搜索「证书」',
  ]],
  ['Mac', [
    '下载后双击，加入「钥匙串访问」的「登录」钥匙串',
    '在钥匙串里双击这张证书 →「信任」→「使用此证书时」选「始终信任」',
  ]],
  ['Windows', [
    '下载后双击 →「安装证书」→「当前用户」',
    '选「将所有证书都放入下列存储」→「受信任的根证书颁发机构」→ 完成',
    '重启浏览器（Firefox 需在设置里开启「信任系统根证书」）',
  ]],
]

// CertHelp: how to make the browser stop warning about the panel's certificate.
export function CertHelp({ cert, className }: { cert: { name: string; sha256: string }; className?: string }) {
  const [open, setOpen] = useState(false)
  const [os, setOs] = useState(() => (/iPhone|iPad|iPod/.test(navigator.userAgent) ? 0 : /Android/.test(navigator.userAgent) ? 1 : /Mac/.test(navigator.userAgent) ? 2 : /Windows/.test(navigator.userAgent) ? 3 : 0))
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} className={cn('flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground', className)}>
        <ShieldCheck className="size-3.5" />浏览器提示「不安全」或手机打不开？安装面板证书
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader><DialogTitle>安装面板证书</DialogTitle></DialogHeader>
          <div className="grid gap-4 text-sm">
            <p className="text-muted-foreground">
              面板用自己的本地证书加密连接。每台设备装一次后，就不会再出现「不安全」警告，iPhone 添加到主屏幕的 App 也能打开。
              这张证书被限制为只能用于局域网地址（10.x、192.168.x、.lan 等），不能用来冒充任何公网网站。
            </p>
            <div className="flex flex-wrap gap-1.5">
              {STEPS.map(([l], i) => (
                <button key={l} type="button" onClick={() => setOs(i)} className={cn('rounded-full border px-3 py-1 text-xs', os === i ? 'border-primary bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted')}>{l}</button>
              ))}
            </div>
            <ol className="grid list-decimal gap-1.5 pl-5">{STEPS[os][1].map((s) => <li key={s}>{s}</li>)}</ol>
            <a href="/ca.crt" className={buttonVariants()}><Download /> 下载证书</a>
            <div className="grid gap-0.5 rounded-lg bg-muted/50 p-2.5 text-[11px] text-muted-foreground">
              <span>证书名称：{cert.name}</span>
              <span className="break-all font-mono">SHA-256：{cert.sha256.match(/.{2}/g)?.join(':').toUpperCase()}</span>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
