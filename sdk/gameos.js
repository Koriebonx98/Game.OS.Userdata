/*! Game OS SDK for community games (v1)
 *  Add to your game:  <script src="https://koriebonx98.github.io/Game.OS.Userdata/sdk/gameos.js"></script>
 *  Works only when the game is launched from Game OS (store / library). Outside Game OS every call rejects with
 *  "Not running inside Game OS", so you can keep a plain-browser fallback.  Full docs: DEVELOPER_API.md */
(function (root) {
    'use strict';
    const pending = new Map();
    const listeners = {};
    let seq = 0, info = null, initPromise = null;
    const embedded = root.parent && root.parent !== root;

    function call(m, ...a) {
        if (!embedded) return Promise.reject(new Error('Not running inside Game OS'));
        return new Promise((resolve, reject) => {
            const id = ++seq;
            const t = setTimeout(() => { pending.delete(id); reject(new Error('Game OS did not answer')); }, 30000);
            pending.set(id, { resolve, reject, t });
            root.parent.postMessage({ gos: 1, id, m, a }, '*');
        });
    }
    root.addEventListener('message', e => {
        const d = e.data;
        if (e.source !== root.parent || !d || d.gos !== 1) return;
        if (d.ev === 'mp') { emit(d.type, d.data); return; }
        const p = pending.get(d.id);
        if (!p) return;
        pending.delete(d.id); clearTimeout(p.t);
        d.ok ? p.resolve(d.r) : p.reject(new Error(d.e || 'Game OS error'));
    });
    function emit(type, data) { (listeners[type] || []).slice().forEach(fn => { try { fn(data); } catch (e) { console.error(e); } }); }

    const GameOS = {
        version: 1,
        /** Resolves with { user: {username}, game, offline, lan, launch } – launch is { join, room } when opened from a lobby invite. */
        ready() { return initPromise || (initPromise = call('init').then(r => (info = r))); },
        get info() { return info; },
        achievements: {
            /** Unlocks an achievement declared in your repo's achievements.json. Resolves { unlocked: true } the first time. */
            unlock: id => call('ach.unlock', id),
            list: () => call('ach.list')
        },
        save: {
            /** Cloud save (any JSON, max 256 KB). get() resolves null when nothing is saved yet. */
            get: () => call('save.get'),
            set: data => call('save.set', data)
        },
        multiplayer: {
            /** Open a lobby. opts: { maxPlayers (2-8), public, mode }. Resolves { roomId, maxPlayers }. */
            host: opts => call('mp.host', opts || {}),
            /** Join a lobby from an invite or the public list. Resolves { host, you }. */
            join: (host, roomId) => call('mp.join', host, roomId),
            listPublic: () => call('mp.listPublic'),
            /** Friends you can invite (on a LAN server: other players on that server). */
            players: () => call('mp.players'),
            invite: username => call('mp.invite', username),
            /** Host only: { public, open, mode } – what the public lobby list shows. */
            setInfo: info => call('mp.setInfo', info),
            /** Guests send to the host; the host sends to everyone, or to one player when `to` is given. data: any JSON (max 16 KB). */
            send: (data, to) => call('mp.send', data, to),
            kick: username => call('mp.kick', username),
            leave: () => call('mp.leave')
        },
        /** Events: 'join' {username}, 'leave' {username}, 'message' {from, data}, 'ended' {reason}. */
        on(type, fn) { (listeners[type] = listeners[type] || []).push(fn); return GameOS; },
        off(type, fn) { listeners[type] = (listeners[type] || []).filter(f => f !== fn); return GameOS; }
    };
    root.GameOS = GameOS;
})(typeof window !== 'undefined' ? window : globalThis);
