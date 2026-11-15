#!/usr/bin/env node
// Game OS LAN / dedicated server.
//   node server.js [--port 3002] [--name "Living room"] [--data ./data]
// Serves the Game OS games over your local network and runs the multiplayer lobby relay with its own offline accounts,
// so players on the same Wi-Fi can play Snake Plus, Quizy and community games when the official servers are unreachable.
// Players open http://<this-computer>:<port>/ in a browser; their lobbies, invites and public game list stay on this server.
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const http = require('http');
try { require.resolve('express'); } catch (_) { module.paths.push(path.join(__dirname, '..', 'backend', 'node_modules')); }
const express = require('express');
const { mountGameRooms } = require('../backend/game-rooms');
const { createStore } = require('./store');

const TICKET_TTL_MS = 12 * 60 * 60 * 1000;
const ONLINE_MS = 2 * 60 * 1000;
const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,23}$/;
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const INVITE_MARKER = '\u2063\u2063GOSINV1:';

function createLanServer(opts = {}) {
    const store = createStore(opts.dataDir || path.join(__dirname, 'data'));
    const name = String(opts.name || os.hostname()).slice(0, 40);
    const siteRoot = path.resolve(opts.siteRoot || path.join(__dirname, '..'));
    const lastSeen = new Map(); // usernameLower -> ms
    const hits = new Map();
    const rateOk = (ip, limit) => {
        const now = Date.now(), e = hits.get(ip);
        if (!e || now > e.reset) { hits.set(ip, { n: 1, reset: now + 60000 }); return true; }
        return ++e.n <= limit;
    };
    setInterval(() => { const now = Date.now(); for (const [k, e] of hits) if (now > e.reset) hits.delete(k); }, 5 * 60000).unref();

    const app = express();
    app.disable('x-powered-by');
    app.use(express.json({ limit: '64kb' }));
    app.use('/api', (req, res, next) => {
        res.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS' });
        if (req.method === 'OPTIONS') return res.sendStatus(204);
        next();
    });

    const server = http.createServer(app);
    const rooms = mountGameRooms(app, server, {
        getFile: store.getFile,
        putFile: store.putFile,
        areFriends: async () => true, // everyone on a LAN server can invite everyone else
        sanitiseUsername: u => /^[a-z0-9][a-z0-9._-]{0,31}$/.test(u),
        conversationPath: (_from, to) => `inbox/${String(to).toLowerCase()}.json`,
        parseTokenUsername: () => null,
        verifyApiToken: async () => null,
        checkRateLimit: ip => rateOk('game:' + ip, 240)
    }).rooms;

    async function userFromTicket(req) {
        const h = req.headers.authorization || '';
        const raw = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
        const m = /^gost_([^.]+)\./.exec(raw);
        if (!m) return null;
        const lower = m[1].toLowerCase();
        const tickets = await store.getFile(`accounts/${lower}/game-tickets.json`);
        const hash = sha256(raw);
        if (!tickets || !tickets.content.some(t => t && t.h === hash && t.exp > Date.now())) return null;
        const profile = await store.getFile(`accounts/${lower}/profile.json`);
        return profile ? { username: profile.content.username, lower } : null;
    }
    const auth = async (req, res, next) => {
        try {
            const u = await userFromTicket(req);
            if (!u) return res.status(401).json({ success: false, message: 'Sign in to the LAN server first.' });
            req.lanUser = u; lastSeen.set(u.lower, Date.now()); next();
        } catch (e) { res.status(500).json({ success: false, message: 'Server error.' }); }
    };

    app.get('/health', (_req, res) => res.json({ ok: true }));
    app.get('/api/lan/info', (_req, res) => res.json({ success: true, lan: true, name, version: 1, rooms: rooms.size }));

    // First login with a name claims it on this server; the device keeps a random secret so nobody else can take the name.
    app.post('/api/lan/login', async (req, res) => {
        try {
            if (!rateOk('login:' + (req.ip || ''), 30)) return res.status(429).json({ success: false, message: 'Too many attempts.' });
            const username = String((req.body && req.body.username) || '').trim();
            const secret = String((req.body && req.body.secret) || '');
            if (!USERNAME_RE.test(username)) return res.status(400).json({ success: false, message: 'Use 2-24 letters, numbers, dots, dashes or underscores.' });
            if (secret.length < 16) return res.status(400).json({ success: false, message: 'Missing device secret.' });
            const lower = username.toLowerCase();
            const pFile = await store.getFile(`accounts/${lower}/profile.json`);
            if (pFile && pFile.content.secretHash !== sha256(secret)) return res.status(403).json({ success: false, message: `"${pFile.content.username}" is already used on this server by another device.` });
            if (!pFile) await store.putFile(`accounts/${lower}/profile.json`, { username, secretHash: sha256(secret), createdAt: new Date().toISOString(), lan: true });
            const display = pFile ? pFile.content.username : username;
            const ticket = 'gost_' + lower + '.' + crypto.randomBytes(24).toString('hex');
            const tf = await store.getFile(`accounts/${lower}/game-tickets.json`);
            const live = (tf ? tf.content : []).filter(t => t && t.exp > Date.now());
            const exp = Date.now() + TICKET_TTL_MS;
            await store.putFile(`accounts/${lower}/game-tickets.json`, [...live, { h: sha256(ticket), exp }].slice(-10));
            lastSeen.set(lower, Date.now());
            res.json({ success: true, username: display, ticket, exp });
        } catch (e) { console.error(e); res.status(500).json({ success: false, message: 'Server error.' }); }
    });

    // Other players who have been active recently (used as the "friends" list for invites).
    app.get('/api/lan/players', auth, (req, res) => {
        const now = Date.now();
        const players = [...lastSeen].filter(([l, t]) => l !== req.lanUser.lower && now - t < ONLINE_MS).map(([l]) => l);
        Promise.all(players.map(async l => { const p = await store.getFile(`accounts/${l}/profile.json`); return p ? p.content.username : l; }))
            .then(names => res.json({ success: true, players: names }));
    });

    // Pending lobby invites for the signed-in player (only for rooms that still exist).
    app.get('/api/lan/invites', auth, async (req, res) => {
        const f = await store.getFile(`inbox/${req.lanUser.lower}.json`);
        const out = [];
        for (const m of (f ? f.content : []).slice(-20)) {
            if (typeof m.text !== 'string' || !m.text.startsWith(INVITE_MARKER)) continue;
            try { const inv = JSON.parse(m.text.slice(INVITE_MARKER.length)).Invite; if (inv && rooms.has(inv.roomId)) out.push(inv); } catch (_) {}
        }
        res.json({ success: true, invites: out });
    });

    // The Game OS site itself, so games run from this server on any device with a browser (nothing else is exposed).
    const allowed = /^\/(?:(?:games|sdk|icons|screenshots)\/.+|[\w.-]+\.(?:html|js|css|json|webmanifest|png|svg|ico))$/;
    const serve = express.static(siteRoot, { index: 'index.html', dotfiles: 'deny', maxAge: '1h' });
    app.use((req, res, next) => (req.method === 'GET' && (req.path === '/' || allowed.test(req.path)) ? serve(req, res, next)
        : res.status(404).json({ success: false, message: 'Not found.' })));

    return { app, server, rooms, name };
}

function lanAddresses(port) {
    const out = [];
    for (const list of Object.values(os.networkInterfaces())) for (const i of list || [])
        if (i.family === 'IPv4' && !i.internal) out.push(`http://${i.address}:${port}/`);
    return out;
}

if (require.main === module) {
    const arg = k => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : undefined; };
    const port = parseInt(arg('port') || process.env.PORT || '3002', 10);
    const lan = createLanServer({ name: arg('name') || process.env.LAN_NAME, dataDir: arg('data') || process.env.LAN_DATA });
    lan.server.listen(port, '0.0.0.0', () => {
        console.log(`Game OS LAN server "${lan.name}" is running.`);
        console.log('Players on this network can open:');
        lanAddresses(port).forEach(u => console.log('  ' + u + 'games/snake-plus/index.html   (or any Game OS game)'));
        console.log('Accounts and lobbies live on this server only; no internet needed.');
    });
}
module.exports = { createLanServer };
