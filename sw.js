/* Game OS service worker: offline shell + notification display */
const CACHE = 'gameos-shell-v15';
const SHELL = ['app.html', 'styles.css', 'script.js', 'pwa.js', 'appnav.js?v=1', 'emulator.js?v=emu8', 'manifest.webmanifest', 'icons/icon-192.png'];

// Digital Abyss: cached up front so it runs offline after the first launch; refreshed whenever online.
const DIGITAL_ABYSS = ['games/digital-abyss/index.html', 'games/digital-abyss/styles.css', 'games/digital-abyss/game.js',
    'games/digital-abyss/achievements.js', 'games/gameos-drm.js', 'games/digital-abyss/gameos-sdk.js', 'games/digital-abyss/scenarios/scenario-data.json',
    'games/digital-abyss/achievements.json', 'games/digital-abyss/cover.svg', 'login.html', 'signup.html'];

self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).then(() => Promise.all(DIGITAL_ABYSS.map(u => c.add(u).catch(() => {}))))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
    e.waitUntil(caches.keys()
        .then(keys => Promise.all(keys.filter(k => k !== CACHE && k !== 'gameos-emu').map(k => caches.delete(k))))
        .then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
    if (e.request.method !== 'GET') return;
    const u = new URL(e.request.url);
    if (u.hostname === 'cdn.emulatorjs.org') {
        // emulator files: cache-first so games run offline
        e.respondWith(caches.open('gameos-emu').then(c => c.match(e.request).then(hit => hit ||
            fetch(e.request).then(res => { if (res.ok) c.put(e.request, res.clone()); return res; }))));
        return;
    }
    if (u.origin !== location.origin) return;
    e.respondWith(fetch(e.request).then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
    }).catch(() => caches.match(e.request).then(hit => hit || caches.match(e.request, { ignoreSearch: true }))));
});
self.addEventListener('push', e => {
    let d = {};
    try { d = e.data ? e.data.json() : {}; } catch (_) {}
    e.waitUntil(self.registration.showNotification(d.title || 'Game OS', {
        body: d.body || '', icon: 'icons/icon-192.png', data: { url: d.url || 'app.html' }
    }));
});
self.addEventListener('notificationclick', e => {
    e.notification.close();
    e.waitUntil(clients.openWindow((e.notification.data && e.notification.data.url) || 'app.html'));
});
