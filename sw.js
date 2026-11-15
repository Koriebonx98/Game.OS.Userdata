/* Game OS service worker: offline shell + notification display */
const CACHE = 'gameos-shell-v20';
const SHELL = ['app.html', 'styles.css', 'script.js', 'pwa.js', 'appnav.js?v=1', 'emulator.js?v=emu8', 'manifest.webmanifest', 'icons/icon-192.png'];
// Extra pages/scripts cached best-effort so the whole site opens offline.
const PAGES = ['index.html', 'games.html', 'game.html', 'account.html', 'inbox.html', 'friends.html', 'profile.html', 'dev-game.html', 'community.js', 'gameos-bridge.js', 'sdk/gameos.js', 'games/gameos-lan.js', 'emulator.js', 'script.js?v=emu8', 'appnav.js'];
const IMG_CACHE = 'gameos-img';
const IMG_MAX = 400;

// Digital Abyss: cached up front so it runs offline after the first launch; refreshed whenever online.
const DIGITAL_ABYSS = ['games/digital-abyss/index.html', 'games/digital-abyss/styles.css', 'games/digital-abyss/game.js',
    'games/digital-abyss/achievements.js', 'games/gameos-drm.js', 'games/digital-abyss/gameos-sdk.js', 'games/digital-abyss/scenarios/scenario-data.json',
    'games/digital-abyss/achievements.json', 'games/digital-abyss/cover.svg', 'login.html', 'signup.html'];

const SNAKE_PLUS = ['games/snake-plus/index.html', 'games/snake-plus/styles.css', 'games/snake-plus/game.js', 'games/snake-plus/online.js',
    'games/snake-plus/achievements.js', 'games/snake-plus/leaderboard.js', 'games/snake-plus/gameos-sdk.js', 'games/gameos-lan.js', 'games/snake-plus/achievements.json', 'games/snake-plus/cover.svg'];

const QUIZY = ['index.html', 'styles.css', 'game.js', 'online.js', 'engine.js', 'questions-1.js', 'questions-2.js', 'achievements.js',
    'leaderboard.js', 'gameos-sdk.js', 'achievements.json', 'weekly.json', 'cover.svg'].map(f => 'games/quizy/' + f);

self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).then(() => Promise.all(DIGITAL_ABYSS.concat(SNAKE_PLUS, QUIZY, PAGES).map(u => c.add(u).catch(() => {}))))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
    e.waitUntil(caches.keys()
        .then(keys => Promise.all(keys.filter(k => k !== CACHE && k !== 'gameos-emu' && k !== IMG_CACHE).map(k => caches.delete(k))))
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
    if (u.origin !== location.origin) {
        // Game covers: stale-while-revalidate so the library renders instantly and offline (CORS responses only; opaque ones bloat storage)
        if (e.request.destination === 'image' && e.request.mode === 'cors') {
            e.respondWith(caches.open(IMG_CACHE).then(c => c.match(e.request).then(hit => {
                const net = fetch(e.request).then(res => {
                    if (res.ok) { c.put(e.request, res.clone()); trimImages(c); }
                    return res;
                }).catch(() => hit);
                return hit || net;
            })));
        }
        return;
    }
    if (e.request.mode === 'navigate') {
        // Pages: network first, but fall back to the cached copy after 2.5s so slow phone connections still open instantly
        e.respondWith(new Promise(resolve => {
            let done = false;
            const cached = () => caches.match(e.request, { ignoreSearch: true });
            const timer = setTimeout(() => cached().then(hit => { if (hit && !done) { done = true; resolve(hit); } }), 2500);
            fetch(e.request).then(res => {
                clearTimeout(timer);
                const copy = res.clone();
                if (res.ok) caches.open(CACHE).then(c => c.put(e.request, copy));
                if (!done) { done = true; resolve(res); }
            }).catch(() => { clearTimeout(timer); cached().then(hit => { if (!done) { done = true; resolve(hit || Response.error()); } }); });
        }));
        return;
    }
    // Static assets and game files: serve from cache immediately, refresh in the background
    e.respondWith(caches.open(CACHE).then(c => c.match(e.request).then(hit => {
        const net = fetch(e.request).then(res => { if (res.ok) c.put(e.request, res.clone()); return res; });
        if (hit) { net.catch(() => {}); return hit; }
        return net.catch(() => c.match(e.request, { ignoreSearch: true }).then(h => h || Response.error()));
    })));
});
function trimImages(c) {
    c.keys().then(keys => { if (keys.length > IMG_MAX) keys.slice(0, keys.length - IMG_MAX).forEach(k => c.delete(k)); });
}
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
