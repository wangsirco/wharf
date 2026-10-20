import { createContext, useContext, useState, type ReactNode } from 'react'

// UI mode: "simple" (observe only: speed, usage, what devices do) or "pro" (everything).
export type Mode = 'simple' | 'pro'
const KEY = 'owp-mode'

function read(): Mode {
  try { return localStorage.getItem(KEY) === 'simple' ? 'simple' : 'pro' } catch { return 'pro' }
}

const Ctx = createContext<{ mode: Mode; setMode: (m: Mode) => void }>({ mode: 'pro', setMode: () => {} })

export function ModeProvider({ children }: { children: ReactNode }) {
  const [mode, set] = useState<Mode>(read)
  const setMode = (m: Mode) => { set(m); try { localStorage.setItem(KEY, m) } catch { /* private mode */ } }
  return <Ctx.Provider value={{ mode, setMode }}>{children}</Ctx.Provider>
}

export const useMode = () => useContext(Ctx)

export function ModeSwitch() {
  const { mode, setMode } = useMode()
  return (
    <div className="flex shrink-0 items-center rounded-lg bg-muted p-[3px] text-xs whitespace-nowrap">
      {(['simple', 'pro'] as const).map((m) => (
        <button key={m} type="button" onClick={() => { setMode(m); window.history.pushState({}, '', '/'); window.dispatchEvent(new PopStateEvent('popstate')) }}
          className={m === mode ? 'rounded-md bg-background px-2.5 py-1 font-medium shadow-sm' : 'rounded-md px-2.5 py-1 text-muted-foreground hover:text-foreground'}>
          {m === 'simple' ? '简要' : '专业'}<span className="hidden sm:inline">模式</span>
        </button>
      ))}
    </div>
  )
}
