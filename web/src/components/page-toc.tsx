import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'

// Page table of contents, built from the page's own sections (every <Section>
// carries data-toc). Wide screens get a sticky list on the right, narrower ones a
// sticky strip of chips under the page title. Pages with fewer than 4 sections
// get nothing.

interface Item { id: string; title: string; el: HTMLElement }

const MIN = 4

function useTocItems() {
  const loc = useLocation()
  const [items, setItems] = useState<Item[]>([])
  const [active, setActive] = useState('')
  useEffect(() => {
    const main = document.querySelector('main')
    if (!main) return
    let raf = 0
    const scan = () => {
      cancelAnimationFrame(raf)
      raf = requestAnimationFrame(() => {
        const els = [...main.querySelectorAll<HTMLElement>('section[data-toc]')].filter((el) => el.offsetParent !== null && !el.parentElement?.closest('section[data-toc]'))
        const seen: Record<string, number> = {}
        const next = els.map((el) => {
          const title = el.dataset.toc ?? ''
          seen[title] = (seen[title] ?? 0) + 1
          const id = 'sec-' + encodeURIComponent(title).replace(/%/g, '').slice(0, 40) + (seen[title] > 1 ? '-' + seen[title] : '')
          if (el.id !== id) el.id = id
          return { id, title, el }
        })
        setItems((old) => (old.length === next.length && old.every((x, i) => x.id === next[i].id && x.el === next[i].el) ? old : next))
      })
    }
    scan()
    const mo = new MutationObserver(scan)
    mo.observe(main, { childList: true, subtree: true })
    return () => { mo.disconnect(); cancelAnimationFrame(raf) }
  }, [loc.pathname])

  useEffect(() => {
    if (items.length < MIN) return
    const onScroll = () => {
      let cur = items[0].id
      for (const it of items) {
        if (it.el.getBoundingClientRect().top <= 140) cur = it.id
      }
      // at the very bottom, the last section counts even if its top never reaches the line
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) cur = items[items.length - 1].id
      setActive(cur)
    }
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [items])

  // open the section named in the URL hash (#sec-…), e.g. from search or another page
  useEffect(() => {
    if (!loc.hash || !items.length) return
    const it = items.find((x) => '#' + x.id === loc.hash)
    if (it) it.el.scrollIntoView({ block: 'start' })
  }, [loc.hash, items])

  return { items: items.length >= MIN ? items : [], active }
}

const go = (it: Item) => {
  it.el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  history.replaceState(null, '', '#' + it.id)
}

/** The chip strip right under the top bar (below 2xl). */
export function TocBar() {
  const { items, active } = useTocItems()
  useEffect(() => {
    document.getElementById('toc-chip-' + active)?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
  }, [active])
  if (!items.length) return null
  return (
    <nav aria-label="本页目录" className="sticky top-12 z-20 -mx-3 -mt-3 mb-3 border-b bg-background/90 px-3 py-2 backdrop-blur sm:-mx-4 sm:-mt-4 sm:px-4 md:-mx-6 md:-mt-6 md:mb-4 md:px-6 2xl:hidden">
      <div className="flex gap-1.5 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {items.map((it) => (
          <button key={it.id} id={'toc-chip-' + it.id} type="button" onClick={() => go(it)}
            className={cn('shrink-0 rounded-full border px-3 py-1 text-xs whitespace-nowrap transition-colors', active === it.id ? 'border-primary bg-primary text-primary-foreground' : 'bg-card text-muted-foreground hover:text-foreground')}>
            {it.title}
          </button>
        ))}
      </div>
    </nav>
  )
}

/** The list on the right of wide screens (2xl and up). */
export function TocSide() {
  const { items, active } = useTocItems()
  if (!items.length) return null
  return (
    <aside className="hidden w-52 shrink-0 2xl:block">
      <nav aria-label="本页目录" className="sticky top-20 grid gap-0.5 border-l pl-3 text-sm">
        <div className="mb-1 text-xs font-medium text-muted-foreground">本页目录</div>
        {items.map((it) => (
          <button key={it.id} type="button" onClick={() => go(it)}
            className={cn('-ml-[13px] border-l-2 py-1 pl-3 text-left transition-colors', active === it.id ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>
            {it.title}
          </button>
        ))}
      </nav>
    </aside>
  )
}
