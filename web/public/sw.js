// v3: retired. The earlier worker answered page loads itself and showed "无法连接面板"
// whenever its own request failed — on a device that does not trust the panel's
// certificate that is every request after the first visit, so the panel looked down
// while it was fine. This version only removes itself; nothing is intercepted.
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil((async () => {
  await self.registration.unregister()
  for (const c of await self.clients.matchAll({ type: 'window' })) c.navigate(c.url)
})()))
