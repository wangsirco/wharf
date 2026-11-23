import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { api, humanError } from '@/lib/api'

// A page that throws while rendering would otherwise unmount the whole app (a blank
// white screen with no clue). This keeps the sidebar, shows the error, and reports it to
// the router's log so it can be fixed.
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    api('POST', '/client-error', {
      path: location.pathname,
      message: String(error?.message || error).slice(0, 500),
      stack: String(error?.stack || '').slice(0, 2000),
      component: String(info?.componentStack || '').slice(0, 1500),
      agent: navigator.userAgent,
    }).catch(() => {})
  }

  componentDidUpdate() {
    // the app was updated while this tab was open: the old page chunks are gone; reload once
    const e = this.state.error
    if (e && /dynamically imported module|Importing a module script failed/i.test(String(e.message)) && !sessionStorage.getItem('owp-chunk-reload')) {
      sessionStorage.setItem('owp-chunk-reload', '1')
      location.reload()
    }
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    const raw = String(error.message || error)
    const plain = humanError(-1, raw).text
    return (
      <div className="mx-auto mt-10 max-w-xl rounded-xl border bg-card p-5">
        <h2 className="font-semibold">这一页没能显示出来</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {plain !== raw ? plain : '可能是路由器返回的数据不完整，或者面板里有个问题。点「重试」一般就好；问题已经自动记到路由器日志里了。'}
        </p>
        <div className="mt-4 flex gap-2">
          <Button size="sm" onClick={() => this.setState({ error: null })}>重试</Button>
          <Button size="sm" variant="outline" onClick={() => location.reload()}>刷新页面</Button>
        </div>
        <details className="mt-3 text-xs text-muted-foreground">
          <summary className="cursor-pointer">技术细节（反馈问题时可以附上）</summary>
          <pre className="mt-2 max-h-48 overflow-auto rounded-lg bg-muted p-3 whitespace-pre-wrap">{raw}</pre>
        </details>
      </div>
    )
  }
}

// CardBoundary: one card that cannot draw shows "暂时没有数据" in its place; the rest of the
// page stays. (Usually the router sent something incomplete.)
export class CardBoundary extends Component<{ children: ReactNode; label?: string }, { error: Error | null }> {
  state = { error: null as Error | null }
  static getDerivedStateFromError(error: Error) { return { error } }
  componentDidCatch(error: Error, info: ErrorInfo) {
    api('POST', '/client-error', {
      path: location.pathname, message: String(error?.message || error).slice(0, 500), stack: String(error?.stack || '').slice(0, 2000),
      component: String(info?.componentStack || '').slice(0, 1500), agent: navigator.userAgent,
    }).catch(() => {})
  }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="flex items-center justify-between gap-3 rounded-xl border border-dashed bg-card px-4 py-6 text-sm text-muted-foreground">
        <span>{this.props.label ? `「${this.props.label}」` : '这一块'}暂时没有数据</span>
        <Button size="sm" variant="ghost" onClick={() => this.setState({ error: null })}>重试</Button>
      </div>
    )
  }
}
