import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'

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

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <div className="mx-auto mt-10 max-w-xl rounded-xl border bg-card p-5">
        <h2 className="font-semibold">这个页面出错了</h2>
        <p className="mt-1 text-sm text-muted-foreground">错误已记录到路由器日志。可以重试，或者刷新整个页面。</p>
        <pre className="mt-3 max-h-48 overflow-auto rounded-lg bg-muted p-3 text-xs whitespace-pre-wrap">{String(error.message || error)}</pre>
        <div className="mt-4 flex gap-2">
          <Button size="sm" onClick={() => this.setState({ error: null })}>重试</Button>
          <Button size="sm" variant="outline" onClick={() => location.reload()}>刷新页面</Button>
        </div>
      </div>
    )
  }
}
