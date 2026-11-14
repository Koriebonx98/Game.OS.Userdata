/* Game OS SDK for Digital Abyss: login + ownership check (DRM), cloud saves, achievements and playtime sync.
 * Runs on top of the site's script.js (sessions, GitHub-backed user data). */
(function () {
    'use strict';
    const GAME = { platform: 'PC', title: 'Digital Abyss', titleId: 'digital-abyss' };
    const FLUSH_MS = 45 * 1000;
    const A = window.DAAchievements;
    const DRM = window.GameOSDRM;

    const isDesktop = /GameOSDesktop/i.test(navigator.userAgent) || new URLSearchParams(location.search).get('client') === 'desktop';
    let user = null, state = null, offline = false, running = false, playTimer = null, flushTimer = null, queue = Promise.resolve();
    const dirty = { save: false, ach: false, play: false };

    const lower = () => user.username.toLowerCase();
    const saveKey = () => 'gameOS_da_save_' + lower();
    const cloudPath = () => `accounts/${lower()}/Saves/${GAME.platform}/${GAME.title}/save.json`;
    const achPath = () => `accounts/${lower()}/Achievements/${GAME.platform}/${GAME.titleId}/achievements.json`;
    const cloudEnabled = () => typeof MODE !== 'undefined' && MODE !== 'demo';

    const emptyState = () => ({ v: 1, updatedAt: '', runUpdatedAt: '', achievements: {}, run: null,
        stats: { playSeconds: 0, runs: 0, wins: 0, losses: 0, solved: [], perfectCases: [], bestTimeMs: {} } });

    const union = (a, b) => Array.from(new Set([...(a || []), ...(b || [])]));

    function merge(a, b) {
        const out = emptyState();
        a = a || emptyState(); b = b || emptyState();
        for (const src of [a, b]) {
            for (const [id, at] of Object.entries(src.achievements || {})) {
                if (!out.achievements[id] || at < out.achievements[id]) out.achievements[id] = at;
            }
        }
        const sa = a.stats || {}, sb = b.stats || {};
        for (const k of ['playSeconds', 'runs', 'wins', 'losses']) out.stats[k] = Math.max(sa[k] || 0, sb[k] || 0);
        out.stats.solved = union(sa.solved, sb.solved);
        out.stats.perfectCases = union(sa.perfectCases, sb.perfectCases);
        for (const src of [sa, sb]) {
            for (const [id, ms] of Object.entries(src.bestTimeMs || {})) {
                if (!(id in out.stats.bestTimeMs) || ms < out.stats.bestTimeMs[id]) out.stats.bestTimeMs[id] = ms;
            }
        }
        const newer = (a.runUpdatedAt || '') >= (b.runUpdatedAt || '') ? a : b;
        out.run = newer.run || null;
        out.runUpdatedAt = newer.runUpdatedAt || '';
        out.updatedAt = (a.updatedAt || '') > (b.updatedAt || '') ? a.updatedAt : b.updatedAt;
        return out;
    }

    function readLocal() {
        try { return JSON.parse(localStorage.getItem(saveKey()) || 'null'); } catch (_) { return null; }
    }
    function persistLocal() {
        state.updatedAt = new Date().toISOString();
        try { localStorage.setItem(saveKey(), JSON.stringify(state)); } catch (_) {}
    }

    // ── Gate (login + ownership) ────────────────────────────────────────────────
    function gate(html) {
        let el = document.getElementById('gos-gate');
        if (!el) {
            el = document.createElement('div');
            el.id = 'gos-gate';
            document.body.appendChild(el);
        }
        el.innerHTML = `<div class="gos-card"><div class="gos-logo">🎮 Game OS</div>${html}</div>`;
        return el;
    }
    function closeGate() { const el = document.getElementById('gos-gate'); if (el) el.remove(); }

    async function loadLibrary() {
        if (!cloudEnabled()) return getDemoGameLibrary(user.username);
        return getGameLibraryGitHub(user.username);
    }
    const findEntry = lib => (lib || []).find(g => g.platform === GAME.platform && String(g.title || '').toLowerCase() === GAME.title.toLowerCase());
    const isOwned = lib => !!findEntry(lib);

    // Claiming issues the user's licence key and adds the game to their library; nothing is added before this.
    async function claim() {
        const licenseKey = await DRM.makeKey(GAME.titleId, user.username);
        const entry = () => ({
            platform: GAME.platform, title: GAME.title, titleId: GAME.titleId,
            coverUrl: new URL('cover.svg', location.href).href,
            achievementsUrl: new URL('achievements.json', location.href).href,
            licenseKey, addedAt: new Date().toISOString()
        });
        if (!cloudEnabled()) {
            const lib = getDemoGameLibrary(user.username);
            if (!isOwned(lib)) { lib.push(entry()); saveDemoGameLibrary(user.username, lib); }
        } else {
            await updateJson(`accounts/${lower()}/games.json`, lib => {
                lib = Array.isArray(lib) ? lib : [];
                if (isOwned(lib)) return undefined;
                return lib.concat(entry());
            }, `Add game: ${GAME.title} (${GAME.platform})`);
        }
        DRM.setLocal(GAME.titleId, user.username, licenseKey);
    }

    // Library entry must carry this user's key. Older entries without one get a key issued; a wrong key is rejected.
    async function checkLicense(lib) {
        const entry = findEntry(lib);
        if (!entry) return 'missing';
        if (entry.licenseKey) {
            if (!(await DRM.verify(entry.licenseKey, GAME.titleId, user.username))) return 'invalid';
            DRM.setLocal(GAME.titleId, user.username, entry.licenseKey);
            return 'ok';
        }
        const licenseKey = await DRM.makeKey(GAME.titleId, user.username);
        if (!cloudEnabled()) {
            entry.licenseKey = licenseKey; saveDemoGameLibrary(user.username, lib);
        } else {
            await updateJson(`accounts/${lower()}/games.json`, l => {
                const e = findEntry(l);
                if (!e || e.licenseKey) return undefined;
                e.licenseKey = licenseKey; return l;
            }, `Issue licence: ${GAME.title}`);
        }
        DRM.setLocal(GAME.titleId, user.username, licenseKey);
        return 'ok';
    }
    const invalidGate = () => gate(`<h2>Invalid licence</h2><p>The licence key on this account doesn't match ${GAME.title}.</p><button class="gos-btn" onclick="location.reload()">Retry</button>`);

    async function updateJson(path, fn, message) {
        for (let attempt = 0; ; attempt++) {
            const file = await githubRead(path);
            const next = fn(file ? file.content : null);
            if (next === undefined) return;
            try { await githubWrite(path, next, message, file ? file.sha : undefined); return; }
            catch (err) { if (attempt >= 2) throw err; }
        }
    }

    function waitForClaim() {
        return new Promise(resolve => {
            gate(`<h2>${GAME.title}</h2><p>A Game OS exclusive. Claim it to get your licence key and add it to your library; then play on PC, the website and the iOS app, with cloud saves and synced achievements.</p>
                <button class="gos-btn" id="gos-claim">🔑 Claim &amp; unlock (free)</button><p class="gos-msg" id="gos-msg"></p>`);
            document.getElementById('gos-claim').onclick = async () => {
                const msg = document.getElementById('gos-msg');
                msg.textContent = 'Claiming…';
                try { await claim(); resolve(); } catch (_) { msg.textContent = 'Could not claim the game. Check your connection and try again.'; }
            };
        });
    }

    // Cloud is configured for this site but unreachable right now (offline, or script.js fell back to demo mode).
    const cloudConfigured = () => typeof GITHUB_TOKEN !== 'undefined' && GITHUB_TOKEN.length > 0;
    const cloudUnreachable = () => cloudConfigured() && (!navigator.onLine || MODE === 'demo');

    async function boot() {
        const startOffline = cloudConfigured() && !navigator.onLine;
        if (!startOffline && typeof modeReady !== 'undefined' && modeReady) { try { await modeReady; } catch (_) {} }
        user = getCurrentUser();
        if (!user) {
            const next = encodeURIComponent('games/digital-abyss/index.html' + location.search);
            gate(`<h2>Sign in to play</h2><p>${GAME.title} requires a Game OS account so your progress, achievements and playtime are saved.</p>
                <a class="gos-btn" href="../../login.html?next=${next}">Sign in</a> <a class="gos-btn alt" href="../../signup.html">Create account</a>`);
            return null;
        }

        let owned = false;
        try {
            if (cloudUnreachable()) throw new Error('offline');
            let lib = await loadLibrary();
            if (!isOwned(lib)) { await waitForClaim(); lib = await loadLibrary(); }
            const status = await checkLicense(lib);
            if (status !== 'ok') { DRM.clearLocal(GAME.titleId, user.username); invalidGate(); return null; }
            owned = true;
        } catch (_) {
            if (await DRM.verify(DRM.getLocal(GAME.titleId, user.username), GAME.titleId, user.username)) { owned = true; offline = true; }
            else {
                gate(`<h2>Can't verify your license</h2><p>Connect to the internet once so Game OS can verify you own ${GAME.title}.</p><button class="gos-btn" onclick="location.reload()">Retry</button>`);
                return null;
            }
        }
        if (!owned) return null;

        state = merge(readLocal(), null);
        if (cloudEnabled() && !offline && !cloudUnreachable()) {
            try {
                const cloud = await githubRead(cloudPath());
                state = merge(state, cloud ? cloud.content : null);
                dirty.save = true; dirty.ach = true; dirty.play = true;
            } catch (_) { offline = true; }
        }
        persistLocal();
        closeGate();
        scheduleFlush();
        window.addEventListener('online', reconnect);
        document.addEventListener('visibilitychange', () => { if (document.hidden) flush(); });
        window.addEventListener('pagehide', () => flush());
        startPlayClock();
        return { user, state, offline };
    }

    // Back online after an offline session: re-verify ownership, merge the cloud save, push local progress.
    async function reconnect() {
        if (!state || !cloudConfigured()) return;
        const wasOffline = offline || MODE === 'demo';
        if (!wasOffline) return;
        try {
            if (MODE === 'demo') MODE = 'github';
            const lib = await loadLibrary();
            const status = await checkLicense(lib);
            if (status !== 'ok') {
                DRM.clearLocal(GAME.titleId, user.username);
                gate(`<h2>License not found</h2><p>This account no longer owns ${GAME.title}.</p><button class="gos-btn" onclick="location.reload()">Reload</button>`);
                return;
            }
            const cloud = await githubRead(cloudPath());
            state = merge(state, cloud ? cloud.content : null);
            persistLocal();
            offline = false;
            dirty.save = dirty.ach = dirty.play = true;
            window.dispatchEvent(new CustomEvent('da-reconnected'));
            flush();
        } catch (_) { offline = true; }
    }

    // ── Playtime ─────────────────────────────────────────────────────────────────
    function startPlayClock() {
        if (playTimer) return;
        playTimer = setInterval(() => {
            if (!running || document.hidden) return;
            state.stats.playSeconds += 5;
            dirty.play = true; dirty.save = true;
            if (state.stats.playSeconds % 60 === 0) persistLocal();
        }, 5000);
    }
    function setRunning(v) { running = !!v; }

    // ── Achievements ─────────────────────────────────────────────────────────────
    function report(type, ctx) {
        if (!state) return [];
        const ids = A.evaluate(type, ctx, state);
        const now = new Date().toISOString();
        const s = state.stats;
        if (type === 'start') s.runs++;
        if (type === 'lost') s.losses++;
        if (type === 'solved') {
            s.wins++;
            s.solved = union(s.solved, [ctx.scenarioId]);
            if (ctx.wrongAttempts === 0) s.perfectCases = union(s.perfectCases, [ctx.scenarioId]);
            const best = s.bestTimeMs[ctx.scenarioId];
            if (!best || ctx.elapsedMs < best) s.bestTimeMs[ctx.scenarioId] = Math.round(ctx.elapsedMs);
        }
        ids.forEach(id => { state.achievements[id] = now; });
        persistLocal();
        dirty.save = true;
        if (ids.length) {
            dirty.ach = true;
            ids.forEach(id => window.dispatchEvent(new CustomEvent('da-achievement', { detail: A.present(A.byId[id], now) })));
            flush();
        } else scheduleFlush();
        return ids;
    }

    function list() {
        return A.DEFS.map(d => A.present(d, state ? state.achievements[d.id] : ''));
    }

    // ── Run (cloud save of an in-progress case) ──────────────────────────────────
    function saveRun(run) {
        if (!state) return;
        state.run = run ? Object.assign({}, run, { savedAt: new Date().toISOString() }) : null;
        state.runUpdatedAt = new Date().toISOString();
        persistLocal();
        dirty.save = true;
        scheduleFlush();
    }
    const getRun = () => (state && state.run) || null;

    // ── Sync ─────────────────────────────────────────────────────────────────────
    function scheduleFlush() {
        if (flushTimer || !cloudEnabled()) return;
        flushTimer = setTimeout(() => { flushTimer = null; flush(); }, FLUSH_MS);
    }

    function flush() {
        if (!state || !cloudEnabled() || offline) return queue;
        if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
        queue = queue.then(doFlush).catch(() => { flushTimer = null; scheduleFlush(); });
        return queue;
    }

    async function doFlush() {
        const snapshot = JSON.parse(JSON.stringify(state));
        const todo = Object.assign({}, dirty);
        dirty.save = dirty.ach = dirty.play = false;
        try {
            if (todo.save) {
                await updateJson(cloudPath(), cloud => {
                    const next = merge(snapshot, cloud);
                    const same = o => JSON.stringify(Object.assign({}, o, { updatedAt: '' }));
                    return cloud && same(next) === same(merge(cloud, null)) ? undefined : next;
                }, `Cloud save: ${GAME.title}`);
            }
            if (todo.ach) await syncAchievements(snapshot);
            if (todo.play) await syncPlaytime(snapshot);
        } catch (err) {
            Object.keys(todo).forEach(k => { if (todo[k]) dirty[k] = true; });
            throw err;
        }
    }

    async function syncAchievements(snap) {
        const unlocked = snap.achievements;
        await updateJson(achPath(), cur => {
            const list = Array.isArray(cur) ? cur : [];
            const have = new Map(list.map(a => [String(a.achievementId), a]));
            let changed = false;
            for (const d of A.DEFS) {
                const at = unlocked[d.id] || '';
                if (d.hidden && !at) continue;
                const prev = have.get(d.id);
                if (!prev) {
                    list.push({ platform: GAME.platform, gameTitle: GAME.title, achievementId: d.id, name: d.name, description: d.description, unlockedAt: at });
                    changed = true;
                } else if (at && !prev.unlockedAt) { prev.unlockedAt = at; changed = true; }
            }
            return changed ? list : undefined;
        }, `Achievements: ${GAME.title}`);

        const ids = Object.keys(unlocked);
        if (!ids.length) return;
        await updateJson(`accounts/${lower()}/achievements.json`, cur => {
            const list = Array.isArray(cur) ? cur : [];
            let changed = false;
            for (const id of ids) {
                const d = A.byId[id];
                if (!d) continue;
                const hit = list.find(a => a.gameTitle === GAME.title && String(a.achievementId) === id);
                if (!hit) {
                    list.push({ platform: GAME.platform, gameTitle: GAME.title, achievementId: id, name: d.name, description: d.description, unlockedAt: unlocked[id] });
                    changed = true;
                }
            }
            return changed ? list : undefined;
        }, `Achievement: ${GAME.title}`);
    }

    async function syncPlaytime(snap) {
        const minutes = Math.floor(snap.stats.playSeconds / 60);
        if (minutes < 1) return;
        await updateJson(`accounts/${lower()}/games.json`, lib => {
            lib = Array.isArray(lib) ? lib : [];
            const g = lib.find(x => x.platform === GAME.platform && String(x.title || '').toLowerCase() === GAME.title.toLowerCase());
            if (!g) return undefined;
            if (minutes <= (g.playtimeMinutes || 0)) return undefined;
            g.playtimeMinutes = minutes;
            g.lastPlayedAt = new Date().toISOString();
            return lib;
        }, `Playtime: ${GAME.title} – ${minutes}min`);
    }

    window.GameOSSDK = { GAME, isDesktop, boot, report, list, saveRun, getRun, setRunning, flush,
        get user() { return user; }, get state() { return state; }, get offline() { return offline; }, reconnect, get cloud() { return cloudEnabled() && !offline; } };
})();
