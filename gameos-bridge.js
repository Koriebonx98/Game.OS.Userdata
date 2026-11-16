/* Game OS bridge (runs in the Game OS page, e.g. dev-game.html): gives a community game, running in a sandboxed frame, access to
 * the signed-in player's account through postMessage. The game never sees tokens; it can only call the whitelisted methods below
 * through sdk/gameos.js. Methods: init, ach.unlock, ach.list, save.get, save.set, playtime (automatic), mp.* (multiplayer).
 * Needs script.js (githubRead/githubWrite, MODE, getCurrentUser) and optionally games/gameos-lan.js. */
(function () {
    'use strict';
    const MAX_SAVE_BYTES = 256 * 1024;
    const MAX_MSG_BYTES = 16 * 1024;
    const cloud = () => typeof MODE !== 'undefined' && MODE !== 'demo';
    const lan = () => !!(window.GameOSLAN && window.GameOSLAN.active);
    const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
    const sha256 = async t => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t))));
    const sleep = ms => new Promise(r => setTimeout(r, ms));

    async function updateJson(path, fn, message) {
        for (let attempt = 0; ; attempt++) {
            const file = await githubRead(path);
            const next = fn(file ? file.content : null);
            if (next === undefined) return;
            try { await githubWrite(path, next, message, file ? file.sha : undefined); return; }
            catch (err) { if (attempt >= 2) throw err; }
        }
    }

    function attach(opts) {
        const { frame, game, definitionsUrl } = opts;
        const user = getCurrentUser();
        const lower = user.username.toLowerCase();
        const titleId = game.TitleID;
        const title = game.Title;
        const key = s => `gameOS_dev_${s}_${titleId}_${lower}`;
        const readLocal = (s, d) => { try { return JSON.parse(localStorage.getItem(key(s))) || d; } catch (_) { return d; } };
        const writeLocal = (s, v) => { try { localStorage.setItem(key(s), JSON.stringify(v)); } catch (_) {} };
        const post = msg => { try { frame.contentWindow.postMessage(Object.assign({ gos: 1 }, msg), '*'); } catch (_) {} };

        // ── Achievements ────────────────────────────────────────────────
        let defs = null;
        async function definitions() {
            if (defs) return defs;
            let list = [];
            try {
                const r = await fetch(definitionsUrl);
                if (r.ok) { const d = await r.json(); list = Array.isArray(d) ? d : (d.Items || d.items || []); }
            } catch (_) { list = (await _kvCache.get('devach:' + titleId)) || []; }
            if (list.length) _kvCache.set('devach:' + titleId, list);
            defs = list.map(a => ({ id: String(a.achievementId || a.id), name: String(a.Name || a.name || ''), description: String(a.Description || a.description || ''), hidden: !!a.hidden }))
                .filter(a => /^[\w.-]{1,64}$/.test(a.id));
            return defs;
        }
        let achDirty = false;
        async function unlock(id) {
            const d = (await definitions()).find(x => x.id === String(id));
            if (!d) throw new Error('Unknown achievement "' + id + '". Declare it in achievements.json.');
            const have = readLocal('ach', {});
            if (have[d.id]) return { unlocked: false };
            have[d.id] = new Date().toISOString();
            writeLocal('ach', have);
            achDirty = true; scheduleFlush();
            toast('🏆 Achievement unlocked: ' + d.name);
            return { unlocked: true };
        }
        async function listAch() {
            const have = readLocal('ach', {});
            return (await definitions()).filter(d => !d.hidden || have[d.id]).map(d => ({ id: d.id, name: d.name, description: d.description, unlockedAt: have[d.id] || '' }));
        }
        async function syncAch() {
            const have = readLocal('ach', {}), ds = await definitions();
            const entries = ds.filter(d => have[d.id]).map(d => ({ platform: 'PC', gameTitle: title, achievementId: d.id, name: d.name, description: d.description, unlockedAt: have[d.id] }));
            if (!entries.length) return;
            await updateJson(`accounts/${lower}/Achievements/PC/${titleId}/achievements.json`, cur => {
                const list = Array.isArray(cur) ? cur : [];
                let changed = false;
                for (const e of entries) if (!list.some(a => String(a.achievementId) === e.achievementId)) { list.push(e); changed = true; }
                return changed ? list : undefined;
            }, `Achievements: ${title}`);
            await updateJson(`accounts/${lower}/achievements.json`, cur => {
                const list = Array.isArray(cur) ? cur : [];
                let changed = false;
                for (const e of entries) if (!list.some(a => a.gameTitle === title && String(a.achievementId) === e.achievementId)) { list.push(e); changed = true; }
                return changed ? list : undefined;
            }, `Achievement: ${title}`);
        }

        // ── Cloud save ──────────────────────────────────────────────────
        const savePath = `accounts/${lower}/Saves/PC/${title}/save.json`;
        let saveDirty = false, saveLoaded = false;
        async function getSave() {
            let local = readLocal('save', null);
            if (cloud() && !saveLoaded) {
                try {
                    const f = await githubRead(savePath);
                    saveLoaded = true;
                    if (f && f.content && (!local || (f.content.updatedAt || '') > (local.updatedAt || ''))) { local = f.content; writeLocal('save', local); }
                } catch (_) {}
            }
            return local ? local.data : null;
        }
        async function setSave(data) {
            const text = JSON.stringify(data === undefined ? null : data);
            if (text.length > MAX_SAVE_BYTES) throw new Error('Save data is too big (limit 256 KB).');
            writeLocal('save', { updatedAt: new Date().toISOString(), data: JSON.parse(text) });
            saveDirty = true; scheduleFlush();
            return true;
        }
        async function syncSave() {
            const local = readLocal('save', null);
            if (!local) return;
            await updateJson(savePath, cur => (cur && (cur.updatedAt || '') >= local.updatedAt ? undefined : local), `Cloud save: ${title}`);
        }

        // ── Playtime ────────────────────────────────────────────────────
        let seconds = readLocal('play', 0), playDirty = false;
        const clock = setInterval(() => { if (!document.hidden) { seconds += 5; playDirty = true; if (seconds % 60 === 0) writeLocal('play', seconds); } }, 5000);
        async function syncPlay() {
            const minutes = Math.floor(seconds / 60);
            if (minutes < 1) return;
            await updateJson(`accounts/${lower}/games.json`, lib => {
                lib = Array.isArray(lib) ? lib : [];
                const g = lib.find(x => x.platform === 'PC' && String(x.title || '').toLowerCase() === title.toLowerCase());
                if (!g || minutes <= (g.playtimeMinutes || 0)) return undefined;
                g.playtimeMinutes = minutes; g.lastPlayedAt = new Date().toISOString();
                return lib;
            }, `Playtime: ${title} – ${minutes}min`);
        }

        let timer = null, queue = Promise.resolve();
        function scheduleFlush() { if (!timer) timer = setTimeout(() => { timer = null; flush(); }, 20000); }
        function flush() {
            writeLocal('play', seconds);
            if (!cloud()) return Promise.resolve(); // demo accounts keep everything on this device
            queue = queue.then(async () => {
                const todo = { a: achDirty, s: saveDirty, p: playDirty };
                achDirty = saveDirty = playDirty = false;
                try { if (todo.a) await syncAch(); if (todo.s) await syncSave(); if (todo.p) await syncPlay(); }
                catch (_) { achDirty = achDirty || todo.a; saveDirty = saveDirty || todo.s; playDirty = playDirty || todo.p; }
            });
            return queue;
        }
        const flushTimer = setInterval(() => { if (playDirty || achDirty || saveDirty) flush(); }, 60000);
        window.addEventListener('pagehide', flush);
        document.addEventListener('visibilitychange', () => { if (document.hidden) flush(); });

        function toast(text) {
            const el = document.createElement('div');
            el.textContent = text;
            el.style.cssText = 'position:fixed;top:56px;right:12px;z-index:99999;background:#111827;color:#fde68a;padding:10px 14px;border-radius:10px;font:14px system-ui,sans-serif;box-shadow:0 6px 24px #0008;';
            document.body.appendChild(el);
            setTimeout(() => el.remove(), 4000);
        }

        // ── Multiplayer (rooms relayed by the Game OS server, the LAN server or a dedicated server) ──
        const mp = createMultiplayer(titleId, lower, user.username, ev => post({ ev: 'mp', type: ev.type, data: ev.data }));

        const methods = {
            init: async () => ({ user: { username: user.username }, game: { titleId, title }, offline: !cloud(), lan: lan(), launch: opts.launch || null, sdk: 1 }),
            'ach.unlock': a => unlock(a[0]),
            'ach.list': () => listAch(),
            'save.get': () => getSave(),
            'save.set': a => setSave(a[0]),
            'mp.host': a => mp.host(a[0] || {}),
            'mp.join': a => mp.join(String(a[0]), String(a[1])),
            'mp.listPublic': () => mp.listPublic(),
            'mp.players': () => mp.players(),
            'mp.invite': a => mp.invite(String(a[0])),
            'mp.setInfo': a => mp.setInfo(a[0] || {}),
            'mp.send': a => mp.send(a[0], a[1]),
            'mp.kick': a => mp.kick(String(a[0])),
            'mp.leave': () => mp.leave()
        };
        function onMessage(e) {
            if (e.source !== frame.contentWindow) return;
            const d = e.data;
            if (!d || d.gos !== 1 || typeof d.m !== 'string' || !Object.prototype.hasOwnProperty.call(methods, d.m)) return;
            Promise.resolve().then(() => methods[d.m](Array.isArray(d.a) ? d.a : []))
                .then(r => post({ id: d.id, ok: true, r }), err => post({ id: d.id, ok: false, e: String((err && err.message) || err) }));
        }
        window.addEventListener('message', onMessage);
        return { flush, detach() { clearInterval(clock); clearInterval(flushTimer); window.removeEventListener('message', onMessage); mp.leave(); flush(); } };
    }

    function createMultiplayer(titleId, lower, username, emit) {
        const gameKey = titleId; // "dev-<id>": the relay accepts community games under this key
        let room = null; // { id, ws, role }

        async function credential() {
            if (lan()) return window.GameOSLAN.credential(username);
            const k = 'gameOS_gameTicket_' + lower;
            try { const s = JSON.parse(localStorage.getItem(k) || 'null'); if (s && s.exp > Date.now() + 3600000) return s.value; } catch (_) {}
            if (!cloud()) throw new Error('Online play needs a signed-in Game OS account.');
            const value = 'gost_' + lower + '.' + hex(crypto.getRandomValues(new Uint8Array(32)));
            const entry = { h: await sha256(value), exp: Date.now() + 12 * 3600000 };
            const path = `accounts/${lower}/game-tickets.json`;
            let last;
            for (let i = 0; i < 4; i++) {
                try {
                    const f = await githubRead(path);
                    const live = (f && Array.isArray(f.content) ? f.content : []).filter(t => t && t.exp > Date.now());
                    await githubWrite(path, [...live, entry].slice(-10), `Game ticket for ${lower}`, f ? f.sha : undefined);
                    localStorage.setItem(k, JSON.stringify({ value, exp: entry.exp }));
                    return value;
                } catch (e) { last = e; await sleep(500 * (i + 1)); }
            }
            throw last || new Error('Could not sign in to online play.');
        }
        function base() {
            if (lan()) return window.GameOSLAN.base;
            let b = '';
            try { b = (typeof getBackendBase === 'function' && getBackendBase()) || localStorage.getItem('gameOS_backendUrl') || ''; } catch (_) {}
            return (b || 'https://gameos.up.railway.app').replace(/\/$/, '');
        }
        async function api(method, path, body) {
            const auth = await credential();
            let last;
            for (let i = 0; i < 3; i++) { // a brand new ticket can take a moment to become visible to the server
                let r;
                try { r = await fetch(base() + path, { method, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + auth }, body: body ? JSON.stringify(body) : undefined }); }
                catch (_) { throw new Error('Online play is unavailable right now. Check your connection and try again.'); }
                const d = await r.json().catch(() => ({}));
                if (r.ok) return d;
                last = new Error(d.message || 'Online play error ' + r.status);
                if (r.status !== 401) throw last;
                await sleep(1500);
            }
            throw last;
        }
        async function socket(roomId) {
            return new WebSocket(base().replace(/^http/i, 'ws') + '/game/' + encodeURIComponent(roomId) + '?auth=' + encodeURIComponent(await credential()));
        }
        function wire(ws, role, resolve, reject) {
            let opened = false;
            const timer = setTimeout(() => { try { ws.close(); } catch (_) {} reject(new Error('Could not connect to the lobby.')); }, 15000);
            let failure = '';
            ws.onmessage = e => {
                let m; try { m = JSON.parse(e.data); } catch (_) { return; }
                if (m.t === 'hello') { opened = true; clearTimeout(timer); resolve(m); }
                else if (m.t === 'join') emit({ type: 'join', data: { username: m.who } });
                else if (m.t === 'leave') emit({ type: 'leave', data: { username: m.who } });
                else if (m.t === 'msg') emit({ type: 'message', data: { from: m.from, data: m.d } });
                else if (m.t === 'error') failure = m.message || '';
                else if (m.t === 'ended') { failure = m.reason || ''; emit({ type: 'ended', data: { reason: m.reason || '' } }); }
            };
            ws.onclose = () => {
                clearTimeout(timer);
                if (room && room.ws === ws) { room = null; if (opened) emit({ type: 'ended', data: { reason: failure || 'Disconnected.' } }); }
                if (!opened) reject(new Error(failure || 'Could not connect to the lobby.'));
            };
            ws.onerror = () => {};
        }

        // ── Direct play (no game server) ────────────────────────────────
        // Used when the Game OS game server can't be reached, like Snake Plus and Quizy: the invite and the WebRTC
        // offer/answer travel through the hidden Game OS chat messages, then the two players connect directly.
        const P2P = 'p2p-';
        const ICE = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
        const canDirect = () => !lan() && cloud() && typeof RTCPeerConnection === 'function';
        async function postSignal(friend, envelope) {
            const path = conversationKey(username, friend);
            for (let i = 0; ; i++) {
                try {
                    const f = await githubRead(path);
                    const msgs = f ? [...f.content] : [];
                    msgs.push({ from: username, text: INVITE_MESSAGE_MARKER + JSON.stringify(envelope), sentAt: new Date().toISOString() });
                    await githubWrite(path, msgs.slice(-200), `Game invite from ${username} to ${friend}`, f ? f.sha : undefined);
                    return;
                } catch (e) { if (i >= 3) throw e; await sleep(400 * (i + 1)); }
            }
        }
        async function readSignal(friend, roomId, kind) {
            const f = await githubRead(conversationKey(username, friend));
            let found = null;
            for (const m of (f && Array.isArray(f.content) ? f.content : [])) {
                if (String((m && m.from) || '').toLowerCase() !== friend.toLowerCase()) continue;
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
        function wireChannel(ch, friend, h) {
            ch.onopen = h.open;
            ch.onclose = h.close;
            ch.onmessage = e => {
                let m; try { m = JSON.parse(e.data); } catch (_) { return; }
                if (m && m.t === 'end') h.end && h.end(String(m.reason || ''));
                else emit({ type: 'message', data: { from: friend, data: m ? m.d : null } });
            };
        }
        async function inviteDirect(friend) {
            const r = room, key = friend.toLowerCase();
            if (r.peers.has(key)) throw new Error(friend + ' is already invited.');
            if (r.peers.size + 1 >= r.maxPlayers) throw new Error('The room is full.');
            const pc = new RTCPeerConnection(ICE), ch = pc.createDataChannel('gos');
            const peer = { friend, pc, ch, open: false };
            let poll = null, timer = null, done = false;
            const finish = () => {
                if (done) return;
                done = true; clearInterval(poll); clearTimeout(timer);
                const wasOpen = peer.open; peer.open = false;
                if (r.peers.get(key) === peer) r.peers.delete(key);
                try { ch.close(); pc.close(); } catch (_) {}
                if (wasOpen) emit({ type: 'leave', data: { username: friend } });
            };
            peer.finish = finish;
            r.peers.set(key, peer);
            wireChannel(ch, friend, {
                open() { if (done || peer.open) return; clearInterval(poll); clearTimeout(timer); peer.open = true; emit({ type: 'join', data: { username: friend } }); },
                close: finish
            });
            pc.onconnectionstatechange = () => { if (pc.connectionState === 'failed' || pc.connectionState === 'closed') finish(); };
            try {
                await pc.setLocalDescription(await pc.createOffer());
                await gathered(pc);
                await postSignal(friend, {
                    Invite: { inviteId: 'msg-' + titleId + '-' + r.id, from: username, gameName: title, platform: 'PC', connectionType: 'Game OS Online', game: titleId, kind: 'game', roomId: r.id, sentAt: new Date().toISOString() },
                    Signal: { room: r.id, kind: 'offer', sdp: pc.localDescription.sdp }
                });
            } catch (e) { finish(); throw e; }
            let applying = false;
            poll = setInterval(async () => {
                if (applying || done || pc.signalingState !== 'have-local-offer') return;
                applying = true;
                try {
                    const a = await readSignal(friend, r.id, 'answer');
                    if (a && pc.signalingState === 'have-local-offer') await pc.setRemoteDescription({ type: 'answer', sdp: a.sdp });
                } catch (_) {} finally { applying = false; }
            }, 3000);
            timer = setTimeout(finish, 10 * 60 * 1000);
            return true;
        }
        async function joinDirect(host, roomId) {
            const offer = await readSignal(host, roomId, 'offer');
            if (!offer) throw new Error(`Could not find ${host}'s invite. They may have closed the lobby.`);
            const pc = new RTCPeerConnection(ICE);
            const r = { id: roomId, role: 'guest', direct: true, pc, ch: null, host };
            room = r;
            return new Promise((resolve, reject) => {
                let opened = false;
                const close = () => { try { if (r.ch) r.ch.close(); pc.close(); } catch (_) {} };
                const fail = err => { clearTimeout(timer); close(); if (room === r) room = null; reject(err); };
                const timer = setTimeout(() => fail(new Error(`Could not connect to ${host}. They may have closed the lobby.`)), 30000);
                let reason = '';
                pc.ondatachannel = e => {
                    r.ch = e.channel;
                    wireChannel(r.ch, host, {
                        open() { opened = true; clearTimeout(timer); resolve({ host, you: username }); },
                        close() {
                            if (!opened) return fail(new Error(`Could not connect to ${host}. They may have closed the lobby.`));
                            if (room === r) { room = null; emit({ type: 'ended', data: { reason: reason || 'Disconnected.' } }); }
                        },
                        end(why) { reason = why; }
                    });
                };
                pc.onconnectionstatechange = () => { if (pc.connectionState === 'failed' && !opened) fail(new Error(`Could not connect to ${host}.`)); };
                (async () => {
                    await pc.setRemoteDescription({ type: 'offer', sdp: offer.sdp });
                    await pc.setLocalDescription(await pc.createAnswer());
                    await gathered(pc);
                    await postSignal(host, { Signal: { room: roomId, kind: 'answer', sdp: pc.localDescription.sdp } });
                })().catch(fail);
            });
        }
        function closeDirect(r) {
            if (r.role === 'host') r.peers.forEach(p => { try { if (p.ch.readyState === 'open') p.ch.send(JSON.stringify({ t: 'end', reason: 'The host left.' })); } catch (_) {} p.finish(); });
            else { try { r.ch && r.ch.close(); r.pc.close(); } catch (_) {} }
        }
        const need = () => { if (!room) throw new Error('Not in a lobby.'); return room; };

        return {
            async host(o) {
                this.leave();
                try {
                    const created = await api('POST', '/api/game-rooms', { game: gameKey, maxPlayers: o.maxPlayers, public: !!o.public, mode: o.mode });
                    const ws = await socket(created.roomId);
                    room = { id: created.roomId, ws, role: 'host' };
                    await new Promise((res, rej) => wire(ws, 'host', res, rej));
                    return { roomId: created.roomId, maxPlayers: created.maxPlayers };
                } catch (err) {
                    room = null;
                    if (!canDirect()) throw err;
                    const maxPlayers = Math.max(2, Math.min(Number(o.maxPlayers) || 2, 4));
                    room = { id: P2P + hex(crypto.getRandomValues(new Uint8Array(6))), role: 'host', direct: true, peers: new Map(), maxPlayers };
                    return { roomId: room.id, maxPlayers };
                }
            },
            async join(host, roomId) {
                this.leave();
                if (String(roomId).startsWith(P2P)) return joinDirect(host, roomId);
                const ws = await socket(roomId);
                room = { id: roomId, ws, role: 'guest' };
                const hello = await new Promise((res, rej) => wire(ws, 'guest', res, rej));
                return { host: hello.host, you: hello.you };
            },
            listPublic: async () => (await api('GET', '/api/game-rooms/public?game=' + encodeURIComponent(gameKey))).rooms || [],
            async players() {
                if (lan()) return window.GameOSLAN.players();
                const list = cloud() ? await getFriendsGitHub(username) : [];
                return (Array.isArray(list) ? list : []).map(f => typeof f === 'string' ? f : (f && f.username) || '').filter(Boolean);
            },
            async invite(friend) { const r = need(); if (r.direct) return inviteDirect(friend); await api('POST', '/api/game-rooms/' + r.id + '/invite', { toUsername: friend }); return true; },
            async setInfo(info) {
                const r = need();
                if (r.direct) return true;
                const body = {};
                if (typeof info.public === 'boolean') body.public = info.public;
                if (typeof info.open === 'boolean') body.open = info.open;
                if (typeof info.mode === 'string') body.mode = info.mode;
                await api('POST', '/api/game-rooms/' + r.id + '/info', body);
                return true;
            },
            async send(data, to) {
                const r = need();
                const text = JSON.stringify({ d: data === undefined ? null : data, to: r.role === 'host' && typeof to === 'string' ? to : undefined });
                if (text.length > MAX_MSG_BYTES) throw new Error('Message too big (limit 16 KB).');
                if (r.direct) {
                    const packet = JSON.stringify({ d: data === undefined ? null : data });
                    const targets = r.role === 'host' ? [...r.peers.values()].filter(p => p.open && (typeof to !== 'string' || p.friend.toLowerCase() === to.toLowerCase())) : [r];
                    const channels = targets.map(p => p.ch).filter(c => c && c.readyState === 'open');
                    if (!channels.length) throw new Error('Connection closed.');
                    channels.forEach(c => c.send(packet));
                    return true;
                }
                if (r.ws.readyState !== 1) throw new Error('Connection closed.');
                r.ws.send(text);
                return true;
            },
            async kick(name) {
                const r = need(); if (r.role !== 'host') throw new Error('Only the host can kick players.');
                if (r.direct) { const p = r.peers.get(String(name).toLowerCase()); if (p) { try { p.ch.send(JSON.stringify({ t: 'end', reason: 'You were removed by the host.' })); } catch (_) {} p.finish(); } return true; }
                r.ws.send(JSON.stringify({ kick: name })); return true; },
            leave() {
                if (!room) return true;
                const r = room; room = null;
                if (r.direct) { closeDirect(r); return true; }
                try { if (r.role === 'host') api('DELETE', '/api/game-rooms/' + r.id).catch(() => {}); r.ws.close(); } catch (_) {}
                return true;
            }
        };
    }

    window.GameOSBridge = { attach };
})();
