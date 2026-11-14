/* Snake Plus online play, run through the Game OS backend like a console game:
 *   host  -> backend: opens a room and invites a Game OS friend (they get a "Join" invite in their inbox)
 *   friend -> backend: joins the room from the invite; the backend relays game traffic between the players
 * Everyone is signed in with their Game OS account, only friends can be invited, and no IP addresses are shared.
 * The host runs the game; guests send steering and receive snapshots. */
(function () {
    'use strict';
    const GAME_KEY = 'snake-plus';
    const DEFAULT_BACKEND = 'https://gameos.up.railway.app';
    const INVITE_TTL_MS = 10 * 60 * 1000;
    const TICKET_TTL_MS = 12 * 60 * 60 * 1000;
    const CONNECT_TIMEOUT_MS = 15 * 1000;

    const cloud = () => typeof MODE !== 'undefined' && MODE !== 'demo';
    const me = () => getCurrentUser().username;
    const supported = () => cloud() && typeof WebSocket === 'function' && !!(window.crypto && crypto.subtle);

    function backendBase() {
        let base = '';
        try { base = (typeof getBackendBase === 'function' && getBackendBase()) || localStorage.getItem('gameOS_backendUrl') || ''; } catch (_) {}
        return (base || DEFAULT_BACKEND).replace(/\/$/, '');
    }

    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    async function sha256(text) { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))); }

    // The website signs in with GitHub, not the backend, so the player proves their Game OS login by writing a
    // short-lived game ticket (hash only) to their own account folder; the backend checks it there.
    async function credential() {
        const user = me(), lower = user.toLowerCase(), key = 'gameOS_gameTicket_' + lower;
        try {
            const saved = JSON.parse(localStorage.getItem(key) || 'null');
            if (saved && saved.exp > Date.now() + 60 * 60 * 1000) return saved.value;
        } catch (_) {}
        const value = 'gost_' + lower + '.' + hex(crypto.getRandomValues(new Uint8Array(32)));
        const entry = { h: await sha256(value), exp: Date.now() + TICKET_TTL_MS };
        const path = `accounts/${lower}/game-tickets.json`;
        let lastErr;
        for (let i = 0; i < 4; i++) {
            try {
                const file = await githubRead(path);
                const live = (file && Array.isArray(file.content) ? file.content : []).filter(t => t && t.exp > Date.now());
                await githubWrite(path, [...live, entry].slice(-10), `Game ticket for ${lower}`, file ? file.sha : undefined);
                localStorage.setItem(key, JSON.stringify({ value, exp: entry.exp }));
                return value;
            } catch (err) { lastErr = err; await new Promise(r => setTimeout(r, 500 * (i + 1))); }
        }
        throw lastErr || new Error('Could not sign in to online play.');
    }

    async function api(method, path, body) {
        const auth = await credential();
        let last;
        // A brand new ticket can take a moment to become visible to the backend.
        for (let i = 0; i < 3; i++) {
            let resp;
            try {
                resp = await fetch(backendBase() + path, {
                    method, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + auth },
                    body: body ? JSON.stringify(body) : undefined
                });
            } catch (_) { throw new Error('Online play is unavailable right now. Check your connection and try again.'); }
            const data = await resp.json().catch(() => ({}));
            if (resp.ok) return data;
            last = new Error(data.message || `Online play error ${resp.status}`);
            if (resp.status !== 401) throw last;
            await new Promise(r => setTimeout(r, 1500));
        }
        throw last;
    }

    async function openSocket(roomId) {
        const url = backendBase().replace(/^http/i, 'ws') + '/game/' + encodeURIComponent(roomId) + '?auth=' + encodeURIComponent(await credential());
        return new WebSocket(url);
    }

    async function listFriends() {
        const u = me();
        const list = cloud() ? await getFriendsGitHub(u) : getDemoFriends(u);
        return (Array.isArray(list) ? list : []).map(f => typeof f === 'string' ? f : (f && f.username) || '').filter(Boolean);
    }

    let room = null; // the room this player hosts: { id, ws, invites: Map(friendLower -> invite) }

    function closeRoom() {
        const r = room; room = null;
        if (!r) return;
        r.invites.forEach(inv => inv.finish(true));
        try { r.ws.close(); } catch (_) {}
        api('DELETE', '/api/game-rooms/' + r.id).catch(() => {});
    }

    async function ensureRoom() {
        if (room && room.ws.readyState <= 1) return room;
        const created = await api('POST', '/api/game-rooms', { game: GAME_KEY });
        const ws = await openSocket(created.roomId);
        const r = { id: created.roomId, ws, invites: new Map() };
        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('Could not open the online lobby.')), CONNECT_TIMEOUT_MS);
            ws.onopen = () => { clearTimeout(timer); resolve(); };
            ws.onerror = () => { clearTimeout(timer); reject(new Error('Could not open the online lobby.')); };
        });
        ws.onmessage = e => {
            let m; try { m = JSON.parse(e.data); } catch (_) { return; }
            const inv = m.who ? r.invites.get(String(m.who).toLowerCase()) : null;
            if (m.t === 'join' && inv) inv.opened();
            else if (m.t === 'leave' && inv) inv.finish(true);
            else if (m.t === 'msg') { const from = r.invites.get(String(m.from).toLowerCase()); if (from && from.peer.open) from.cb.onMessage && from.cb.onMessage(from.peer, m.d); }
        };
        ws.onclose = () => { if (room === r) { room = null; r.invites.forEach(inv => inv.finish(true)); } };
        room = r;
        return r;
    }

    /** Host side: invites `friend` to the lobby and reports when they join. Returns {peer, cancel()}. */
    async function invite(friend, cb) {
        if (!supported()) throw new Error('Online play needs a signed-in Game OS account.');
        const r = await ensureRoom();
        const key = friend.toLowerCase();
        let timer = null, done = false;
        const peer = {
            friend, open: false,
            send(obj) { if (peer.open && r.ws.readyState === 1) r.ws.send(JSON.stringify({ to: friend, d: obj })); },
            close() { if (peer.open || !done) { try { r.ws.send(JSON.stringify({ kick: friend })); } catch (_) {} } entry.finish(true); }
        };
        const entry = {
            cb, peer,
            opened() {
                if (peer.open) return;
                clearTimeout(timer); peer.open = true;
                cb.onOpen && cb.onOpen(peer);
            },
            finish(report) {
                if (done) return;
                done = true; clearTimeout(timer);
                if (r.invites.get(key) === entry) r.invites.delete(key);
                const wasOpen = peer.open; peer.open = false;
                if (!report) return;
                if (wasOpen) cb.onClose && cb.onClose(peer);
                else cb.onFail && cb.onFail(peer);
            }
        };
        r.invites.set(key, entry);
        try {
            await api('POST', '/api/game-rooms/' + r.id + '/invite', { toUsername: friend });
        } catch (err) { r.invites.delete(key); throw err; }
        cb.onStatus && cb.onStatus(`Invite sent to ${friend}. Waiting for them to join…`);
        timer = setTimeout(() => { cb.onStatus && cb.onStatus(`${friend} didn't join in time.`); entry.finish(true); }, INVITE_TTL_MS);
        return { peer, cancel() { entry.finish(false); } };
    }

    /** Guest side: joins the room `roomId` that `host` invited you to. Resolves once connected. */
    async function join(host, roomId, cb) {
        if (!supported()) throw new Error('Online play needs a signed-in Game OS account.');
        cb.onStatus && cb.onStatus(`Connecting to ${host}…`);
        const ws = await openSocket(roomId);
        let opened = false;
        const peer = {
            friend: host, get open() { return opened && ws.readyState === 1; },
            send(obj) { if (peer.open) ws.send(JSON.stringify({ d: obj })); },
            close() { try { ws.close(); } catch (_) {} }
        };
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => { try { ws.close(); } catch (_) {} reject(new Error(`Could not connect to ${host}. They may have closed the lobby.`)); }, CONNECT_TIMEOUT_MS);
            let failure = '';
            ws.onmessage = e => {
                let m; try { m = JSON.parse(e.data); } catch (_) { return; }
                if (m.t === 'hello') { opened = true; clearTimeout(timer); cb.onOpen && cb.onOpen(peer); resolve(peer); }
                else if (m.t === 'error') failure = m.message || '';
                else if (m.t === 'ended') failure = m.reason || '';
                else if (m.t === 'msg') cb.onMessage && cb.onMessage(peer, m.d);
            };
            ws.onclose = () => {
                clearTimeout(timer);
                if (opened) { opened = false; cb.onClose && cb.onClose(peer); }
                else reject(new Error(failure || `Could not connect to ${host}. They may have closed the lobby.`));
            };
            ws.onerror = () => {};
        });
    }

    window.SnakeOnline = { supported, listFriends, invite, join, closeRoom, GAME_KEY };
})();
