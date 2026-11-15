/* Snake Plus online play, run through the Game OS backend like a console game:
 *   host  -> backend: opens a room and invites a Game OS friend (they get a "Join" invite in their inbox)
 *   friend -> backend: joins the room from the invite; the backend relays game traffic between the players
 * Everyone is signed in with their Game OS account, only friends can be invited, and no IP addresses are shared.
 * If the game server can't be reached, play connects directly between the two players, with the connection details
 * exchanged through the same Game OS chat messages (this shares IP addresses with the invited friend).
 * The host runs the game; guests send steering and receive snapshots. */
(function () {
    'use strict';
    const GAME_KEY = 'snake-plus';
    const DEFAULT_BACKEND = 'https://gameos.up.railway.app';
    const INVITE_TTL_MS = 10 * 60 * 1000;
    const TICKET_TTL_MS = 12 * 60 * 60 * 1000;
    const CONNECT_TIMEOUT_MS = 15 * 1000;

    // A Game OS LAN / dedicated server (see games/gameos-lan.js) replaces the official servers and GitHub accounts.
    const lan = () => !!(window.GameOSLAN && window.GameOSLAN.active);
    const cloud = () => lan() || (typeof MODE !== 'undefined' && MODE !== 'demo');
    const me = () => getCurrentUser().username;
    const supported = () => cloud() && !!(window.crypto && crypto.subtle) && (typeof WebSocket === 'function' || typeof RTCPeerConnection === 'function');

    function backendBase() {
        if (lan()) return window.GameOSLAN.base;
        let base = '';
        try { base = (typeof getBackendBase === 'function' && getBackendBase()) || localStorage.getItem('gameOS_backendUrl') || ''; } catch (_) {}
        return (base || DEFAULT_BACKEND).replace(/\/$/, '');
    }

    const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
    async function sha256(text) { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))); }

    // The website signs in with GitHub, not the backend, so the player proves their Game OS login by writing a
    // short-lived game ticket (hash only) to their own account folder; the backend checks it there.
    async function credential() {
        if (lan()) return window.GameOSLAN.credential(me());
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
            } catch (_) { const e = new Error('Online play is unavailable right now. Check your connection and try again.'); e.unreachable = true; throw e; }
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
        if (lan()) return window.GameOSLAN.players();
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


    // ── Direct play (no game server) ────────────────────────────────────────────
    // Used when the Game OS game server can't be reached. The invite travels through the same hidden Game OS chat
    // messages as every other invite; the WebRTC offer/answer ride along in them, then the players connect directly.
    const P2P_PREFIX = 'p2p-';
    const ICE = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
    const SIGNAL_POLL_MS = 3000;

    async function postSignal(friend, envelope) {
        const path = conversationKey(me(), friend);
        for (let i = 0; ; i++) {
            try {
                const file = await githubRead(path);
                const msgs = file ? [...file.content] : [];
                msgs.push({ from: me(), text: INVITE_MESSAGE_MARKER + JSON.stringify(envelope), sentAt: new Date().toISOString() });
                await githubWrite(path, msgs.slice(-200), `Game invite from ${me()} to ${friend}`, file ? file.sha : undefined);
                return;
            } catch (err) {
                if (i >= 3) throw err;
                await new Promise(r => setTimeout(r, 400 * (i + 1)));
            }
        }
    }

    async function readSignals(friend, roomId, kind) {
        const file = await githubRead(conversationKey(me(), friend));
        const from = friend.toLowerCase();
        let found = null;
        for (const m of (file && Array.isArray(file.content) ? file.content : [])) {
            if ((m && m.from || '').toLowerCase() !== from) continue;
            const env = parseInviteEnvelope(m.text);
            if (env && env.Signal && env.Signal.room === roomId && env.Signal.kind === kind) found = env.Signal;
        }
        return found;
    }

    function gathered(pc) {
        return new Promise(resolve => {
            if (pc.iceGatheringState === 'complete') return resolve();
            const done = () => { clearTimeout(t); pc.removeEventListener('icegatheringstatechange', check); resolve(); };
            const check = () => { if (pc.iceGatheringState === 'complete') done(); };
            const t = setTimeout(done, 5000);
            pc.addEventListener('icegatheringstatechange', check);
        });
    }

    function wireChannel(channel, peer, handlers) {
        channel.onopen = () => handlers.open();
        channel.onclose = () => handlers.close();
        channel.onmessage = e => { let d; try { d = JSON.parse(e.data); } catch (_) { return; } handlers.message(d); };
    }

    async function inviteDirect(friend, cb) {
        const roomId = P2P_PREFIX + hex(crypto.getRandomValues(new Uint8Array(6)));
        const pc = new RTCPeerConnection(ICE);
        const channel = pc.createDataChannel('snake');
        let timer = null, poll = null, done = false, wasOpen = false;
        const peer = {
            friend, open: false,
            send(obj) { if (peer.open && channel.readyState === 'open') channel.send(JSON.stringify(obj)); },
            close() { finish(true); }
        };
        function finish(report) {
            if (done) return;
            done = true; clearTimeout(timer); clearInterval(poll);
            peer.open = false;
            try { channel.close(); pc.close(); } catch (_) {}
            if (!report) return;
            if (wasOpen) cb.onClose && cb.onClose(peer); else cb.onFail && cb.onFail(peer);
        }
        wireChannel(channel, peer, {
            open() { if (done || peer.open) return; clearTimeout(timer); clearInterval(poll); wasOpen = peer.open = true; cb.onOpen && cb.onOpen(peer); },
            close() { finish(true); },
            message(d) { if (peer.open) cb.onMessage && cb.onMessage(peer, d); }
        });
        pc.onconnectionstatechange = () => { if (pc.connectionState === 'failed' || pc.connectionState === 'closed') finish(true); };

        await pc.setLocalDescription(await pc.createOffer());
        await gathered(pc);
        const sentAt = new Date().toISOString();
        await postSignal(friend, {
            Invite: {
                inviteId: 'msg-' + GAME_KEY + '-' + roomId, from: me(), gameName: 'Snake Plus', platform: 'PC', connectionType: 'Game OS Online',
                game: GAME_KEY, kind: 'game', roomId, sentAt
            },
            Signal: { room: roomId, kind: 'offer', sdp: pc.localDescription.sdp }
        });
        cb.onStatus && cb.onStatus(`Invite sent to ${friend}. Waiting for them to join…`);

        let applying = false;
        poll = setInterval(async () => {
            if (applying || done || pc.signalingState !== 'have-local-offer') return;
            applying = true;
            try {
                const answer = await readSignals(friend, roomId, 'answer');
                if (answer && pc.signalingState === 'have-local-offer') await pc.setRemoteDescription({ type: 'answer', sdp: answer.sdp });
            } catch (_) {} finally { applying = false; }
        }, SIGNAL_POLL_MS);
        timer = setTimeout(() => { cb.onStatus && cb.onStatus(`${friend} didn't join in time.`); finish(true); }, INVITE_TTL_MS);
        return { peer, cancel() { finish(false); } };
    }

    async function joinDirect(host, roomId, cb) {
        cb.onStatus && cb.onStatus(`Connecting to ${host}…`);
        const offer = await readSignals(host, roomId, 'offer');
        if (!offer) throw new Error(`Could not find ${host}'s invite. They may have closed the lobby.`);
        const pc = new RTCPeerConnection(ICE);
        let channel = null, opened = false;
        const peer = {
            friend: host, get open() { return opened && !!channel && channel.readyState === 'open'; },
            send(obj) { if (peer.open) channel.send(JSON.stringify(obj)); },
            close() { try { if (channel) channel.close(); pc.close(); } catch (_) {} }
        };
        return new Promise((resolve, reject) => {
            const fail = () => { peer.close(); reject(new Error(`Could not connect to ${host}. They may have closed the lobby.`)); };
            const timer = setTimeout(fail, 30 * 1000);
            pc.ondatachannel = e => {
                channel = e.channel;
                wireChannel(channel, peer, {
                    open() { opened = true; clearTimeout(timer); cb.onOpen && cb.onOpen(peer); resolve(peer); },
                    close() { clearTimeout(timer); if (opened) { opened = false; cb.onClose && cb.onClose(peer); } else fail(); },
                    message(d) { cb.onMessage && cb.onMessage(peer, d); }
                });
            };
            pc.onconnectionstatechange = () => { if (pc.connectionState === 'failed' && !opened) fail(); };
            (async () => {
                await pc.setRemoteDescription({ type: 'offer', sdp: offer.sdp });
                await pc.setLocalDescription(await pc.createAnswer());
                await gathered(pc);
                await postSignal(host, { Signal: { room: roomId, kind: 'answer', sdp: pc.localDescription.sdp } });
            })().catch(err => { clearTimeout(timer); peer.close(); reject(err); });
        });
    }

    /** Host side: invites `friend` to the lobby and reports when they join. Returns {peer, cancel()}. */
    async function invite(friend, cb) {
        if (!supported()) throw new Error('Online play needs a signed-in Game OS account.');
        let r;
        try { r = await ensureRoom(); } catch (err) {
            if (!lan() && typeof RTCPeerConnection === 'function') return inviteDirect(friend, cb);
            throw err;
        }
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
        if (String(roomId).startsWith(P2P_PREFIX)) return joinDirect(host, roomId, cb);
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
