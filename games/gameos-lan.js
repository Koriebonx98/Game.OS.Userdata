/* Game OS LAN / dedicated server support for games.
 * When the page is served by a Game OS LAN server (lan-server/), or a server address is saved on this device, online play
 * goes through that server with its own offline accounts instead of the official servers. Needs no GitHub or internet.
 *   GameOSLAN.active            true once a LAN/dedicated server was found
 *   GameOSLAN.base              the server's URL
 *   GameOSLAN.credential(name)  ticket for the multiplayer relay (signs the device in to the server)
 *   GameOSLAN.players()         other players recently active on the server
 *   GameOSLAN.setServer(url)    save a server address ('' to go back to the official servers) */
(function () {
    'use strict';
    const KEY = 'gameOS_lanServer', SECRET = 'gameOS_lanSecret';
    const store = {
        get: k => { try { return localStorage.getItem(k) || ''; } catch (_) { return ''; } },
        set: (k, v) => { try { v ? localStorage.setItem(k, v) : localStorage.removeItem(k); } catch (_) {} }
    };
    const LAN = { active: false, base: '', name: '', ready: null };
    const tickets = new Map();

    function deviceSecret() {
        let s = store.get(SECRET);
        if (!s) { s = Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, '0')).join(''); store.set(SECRET, s); }
        return s;
    }
    async function probe(base) {
        try {
            const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 2500);
            const r = await fetch(base + '/api/lan/info', { signal: ctl.signal });
            clearTimeout(t);
            const d = r.ok ? await r.json() : null;
            return d && d.lan ? d : null;
        } catch (_) { return null; }
    }
    LAN.ready = (async () => {
        const saved = store.get(KEY).replace(/\/$/, '');
        const candidates = [];
        if (saved) candidates.push(saved);
        if (/^https?:$/.test(location.protocol)) candidates.push(location.origin);
        for (const base of candidates) {
            const info = await probe(base);
            if (info) { LAN.active = true; LAN.base = base; LAN.name = info.name || ''; break; }
        }
        render();
        if (LAN.active) pollInvites();
        return LAN.active;
    })();

    LAN.credential = async function (username) {
        const key = username.toLowerCase(), hit = tickets.get(key);
        if (hit && hit.exp > Date.now() + 60000) return hit.ticket;
        const r = await fetch(LAN.base + '/api/lan/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, secret: deviceSecret() }) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.message || 'Could not sign in to the LAN server.');
        tickets.set(key, { ticket: d.ticket, exp: d.exp });
        return d.ticket;
    };
    LAN.players = async function () {
        const me = (typeof getCurrentUser === 'function' && getCurrentUser()) || null;
        if (!me) return [];
        const ticket = await LAN.credential(me.username);
        const r = await fetch(LAN.base + '/api/lan/players', { headers: { Authorization: 'Bearer ' + ticket } });
        return r.ok ? (await r.json()).players || [] : [];
    };
    LAN.setServer = function (url) {
        url = String(url || '').trim().replace(/\/$/, '');
        if (url && !/^https?:\/\/[^\s/]+$/i.test(url)) throw new Error('Enter an address like http://192.168.1.20:3002');
        store.set(KEY, url);
        location.reload();
    };

    // Invites on a LAN server arrive as a small banner with a Join link.
    const shown = new Set();
    function pollInvites() {
        const tick = async () => {
            try {
                const me = (typeof getCurrentUser === 'function' && getCurrentUser()) || null;
                if (me && !document.hidden) {
                    const ticket = await LAN.credential(me.username);
                    const r = await fetch(LAN.base + '/api/lan/invites', { headers: { Authorization: 'Bearer ' + ticket } });
                    ((r.ok && (await r.json()).invites) || []).forEach(inv => {
                        if (shown.has(inv.roomId)) return;
                        shown.add(inv.roomId);
                        banner(inv);
                    });
                }
            } catch (_) {}
            setTimeout(tick, 4000);
        };
        tick();
    }
    function banner(inv) {
        const root = location.href.includes('/games/') ? location.href.slice(0, location.href.indexOf('/games/') + 1) : new URL('./', location.href).href;
        const q = 'join=' + encodeURIComponent(inv.from) + '&room=' + encodeURIComponent(inv.roomId);
        const href = /^dev-/.test(inv.game)
            ? root + 'dev-game.html?id=' + encodeURIComponent(inv.game.slice(4)) + '&' + q
            : root + 'games/' + encodeURIComponent(inv.game) + '/index.html?' + q;
        const el = document.createElement('div');
        el.style.cssText = 'position:fixed;left:12px;right:12px;bottom:56px;z-index:99998;max-width:420px;background:#111827;color:#fff;border-radius:10px;padding:12px 14px;box-shadow:0 6px 24px #0008;font:14px system-ui,sans-serif;';
        const text = document.createElement('span');
        text.textContent = inv.from + ' invited you to play ' + inv.gameName + '. ';
        const join = document.createElement('a');
        join.href = href; join.textContent = '▶ Join'; join.style.cssText = 'color:#86efac;font-weight:700;margin-right:10px;';
        const x = document.createElement('a');
        x.href = '#'; x.textContent = 'Dismiss'; x.style.color = '#9ca3af'; x.onclick = e => { e.preventDefault(); el.remove(); };
        el.append(text, join, x);
        document.body.appendChild(el);
    }

    function render() {
        if (!document.body) return document.addEventListener('DOMContentLoaded', render, { once: true });
        const b = document.createElement('button');
        b.type = 'button';
        b.textContent = LAN.active ? '📡 ' + (LAN.name || 'LAN') : '📡';
        b.title = LAN.active ? 'Playing on a LAN / dedicated server. Click to change.' : 'Play on a LAN or dedicated server';
        b.style.cssText = 'position:fixed;left:8px;bottom:8px;z-index:99997;border:0;border-radius:16px;padding:6px 10px;font-size:12px;background:' + (LAN.active ? '#16a34a' : '#1f2937') + ';color:#fff;opacity:' + (LAN.active ? '.95' : '.45') + ';cursor:pointer;';
        b.onclick = () => {
            const v = prompt('Game server address (e.g. http://192.168.1.20:3002).\nLeave empty to use the official Game OS servers.', store.get(KEY));
            if (v === null) return;
            if (v && location.protocol === 'https:' && /^http:\/\/(?!localhost|127\.)/i.test(v.trim()) &&
                !confirm('This page is secure (https) so the browser will block a plain http server. Open the server address directly in your browser instead.\n\nSave it anyway?')) return;
            try { LAN.setServer(v); } catch (e) { alert(e.message); }
        };
        document.body.appendChild(b);
    }

    window.GameOSLAN = LAN;
})();
