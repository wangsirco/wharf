import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { Globe, Home } from 'lucide-react'
import { berthStatus, openBerth, rememberVia, type BerthStatus, type OpenOpts, type Via } from '@/lib/berth'
import { cn } from '@/lib/utils'
import { Pill } from '@/components/common'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'

// BerthChooser: "打开内网 https://mini.lan / 打开公网 https://…", the recommended one first,
// with "remember for this device". Shown when openBerth cannot tell which name works here.
export function BerthChooser() {
  const [ask, setAsk] = useState<{ rec: Via; opts: OpenOpts } | null>(null)
  const [s, setS] = useState<BerthStatus | null>(null)
  const [remember, setRemember] = useState(false)
  useEffect(() => {
    const on = (e: Event) => { setAsk((e as CustomEvent).detail); setRemember(false); berthStatus().then(setS) }
    window.addEventListener('owp:berth-choose', on)
    return () => window.removeEventListener('owp:berth-choose', on)
  }, [])
  if (!ask || !s) return null
  const opts = ([['lan', '打开内网', s.lan, Home], ['public', '打开公网', s.public, Globe]] as const)
    .filter(([, , url]) => !!url)
    .sort(([a]) => (a === ask.rec ? -1 : 1))
  const pick = (v: Via) => {
    if (remember) rememberVia(v)
    setAsk(null)
    openBerth(ask.opts, v).catch((e) => toast.error((e as Error).message))
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) setAsk(null) }}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>用哪个地址打开 Berth？</DialogTitle>
          <DialogDescription>{location.hostname.match(/\.(lan|local)$|^(10|192\.168)\./) ? '你在家里打开的面板。' : '你是用公网地址打开的面板，'}{ask.rec === 'lan' ? '但家里的地址也能连上，可能就在家。' : 'Berth 只有这一个地址。'}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-2">
          {opts.map(([v, label, url, Icon]) => (
            <button key={v} type="button" onClick={() => pick(v)} className={cn('flex items-center gap-3 rounded-xl border p-3 text-left hover:border-primary/50', v === ask.rec && 'border-primary bg-accent/40')}>
              <Icon className="size-5 shrink-0 text-primary" />
              <span className="min-w-0 flex-1"><span className="block text-sm font-medium">{label}</span><span className="block truncate font-mono text-xs text-muted-foreground">{url}</span></span>
              {v === ask.rec && <Pill tone="blue">推荐</Pill>}
            </button>
          ))}
          <label className="flex items-center gap-2 text-sm text-muted-foreground"><Checkbox checked={remember} onCheckedChange={(c) => setRemember(!!c)} />记住这台设备的选择</label>
        </div>
      </DialogContent>
    </Dialog>
  )
}
