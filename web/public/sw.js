// v2 (Wharf logo)
// Minimal service worker: makes the panel installable and shows an offline notice.
// It never caches API responses — router data must always be live.
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()))
self.addEventListener('fetch', (e) => {
  if (e.request.mode !== 'navigate') return
  e.respondWith(fetch(e.request).catch(() => new Response(
    '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wharf</title>' +
    '<body style="font-family:system-ui;background:#0b1220;color:#cbd5e1;display:grid;place-items:center;height:100vh;margin:0;text-align:center">' +
    '<div><h2 style="margin:0 0 8px">无法连接面板</h2><p style="opacity:.7">请检查网络后下拉刷新</p></div>',
    { headers: { 'Content-Type': 'text/html; charset=utf-8' } })))
})
