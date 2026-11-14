// Run with: node --test backend/test-game-rooms.js
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const { mountGameRooms } = require('./game-rooms');

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const ticket = u => 'gost_' + u + '.' + crypto.randomBytes(8).toString('hex');

async function setup() {
    const files = new Map();
    const put = (path, content) => files.set(path, { content, sha: crypto.randomBytes(4).toString('hex') });
    const users = { alice: ticket('alice'), bob: ticket('bob'), carol: ticket('carol'), dave: ticket('dave') };
    for (const [u, t] of Object.entries(users)) {
        put(`accounts/${u}/profile.json`, { username: u[0].toUpperCase() + u.slice(1) });
        put(`accounts/${u}/game-tickets.json`, [{ h: sha(t), exp: Date.now() + 60000 }]);
    }
    put('accounts/alice/friends.json', ['bob', 'carol']);
    put('accounts/bob/friends.json', ['alice']);

    const app = express();
    app.use(express.json());
    const server = http.createServer(app);
    mountGameRooms(app, server, {
        getFile: async p => files.get(p) || null,
        putFile: async (p, c) => put(p, c),
        areFriends: async (a, b) => ((files.get(`accounts/${a}/friends.json`) || { content: [] }).content).includes(b),
        sanitiseUsername: u => /^[a-z0-9._-]{1,32}$/.test(u),
        conversationPath: (a, b) => `accounts/messages/${[a, b].map(x => x.toLowerCase()).sort().join('_')}.json`,
        verifyApiToken: async () => null,
        checkRateLimit: () => true
    });
    await new Promise(r => server.listen(0, r));
    const base = 'http://127.0.0.1:' + server.address().port;
    const api = async (method, path, who, body) => {
        const r = await fetch(base + path, { method, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + users[who] }, body: body && JSON.stringify(body) });
        return { status: r.status, body: await r.json() };
    };
    const open = [];
    const socket = (room, who) => new Promise((resolve, reject) => {
        const ws = new WebSocket(base.replace('http', 'ws') + '/game/' + room + '?auth=' + encodeURIComponent(users[who]));
        open.push(ws);
        const inbox = [];
        const waiters = [];
        ws.on('message', d => { const m = JSON.parse(d); const w = waiters.shift(); if (w) w(m); else inbox.push(m); });
        ws.next = () => new Promise(res => { const m = inbox.shift(); if (m) res(m); else waiters.push(res); });
        ws.on('open', () => resolve(ws));
        ws.on('error', reject);
    });
    return { files, api, socket, close: () => { open.forEach(w => w.terminate()); server.closeAllConnections(); server.close(); } };
}

test('host invites a friend and game traffic is relayed both ways', async () => {
    const t = await setup();
    try {
        const { body: created } = await t.api('POST', '/api/game-rooms', 'alice', { game: 'snake-plus' });
        const host = await t.socket(created.roomId, 'alice');
        assert.strictEqual((await host.next()).role, 'host');

        const inv = await t.api('POST', `/api/game-rooms/${created.roomId}/invite`, 'alice', { toUsername: 'bob' });
        assert.strictEqual(inv.status, 200);
        const thread = t.files.get('accounts/messages/alice_bob.json').content;
        const env = JSON.parse(thread[0].text.slice('\u2063\u2063GOSINV1:'.length)).Invite;
        assert.strictEqual(env.roomId, created.roomId);
        assert.strictEqual(env.game, 'snake-plus');
        assert.ok(env.inviteId.startsWith('msg-'));

        const guest = await t.socket(created.roomId, 'bob');
        assert.strictEqual((await guest.next()).host, 'Alice');
        assert.deepStrictEqual(await host.next(), { t: 'join', who: 'Bob' });

        guest.send(JSON.stringify({ d: { t: 'dir', d: [1, 0] } }));
        assert.deepStrictEqual(await host.next(), { t: 'msg', from: 'Bob', d: { t: 'dir', d: [1, 0] } });
        host.send(JSON.stringify({ to: 'Bob', d: { t: 'start' } }));
        assert.deepStrictEqual(await guest.next(), { t: 'msg', from: 'Alice', d: { t: 'start' } });

        guest.close();
        assert.deepStrictEqual(await host.next(), { t: 'leave', who: 'Bob' });
        host.close();
    } finally { t.close(); }
});

test('only friends can be invited and only invited users can join', async () => {
    const t = await setup();
    try {
        const { body: created } = await t.api('POST', '/api/game-rooms', 'alice', { game: 'snake-plus' });
        const host = await t.socket(created.roomId, 'alice');
        await host.next();
        assert.strictEqual((await t.api('POST', `/api/game-rooms/${created.roomId}/invite`, 'alice', { toUsername: 'dave' })).status, 403);
        assert.strictEqual((await t.api('POST', `/api/game-rooms/${created.roomId}/invite`, 'bob', { toUsername: 'alice' })).status, 403);
        const stranger = await t.socket(created.roomId, 'carol');
        assert.match((await stranger.next()).message, /not invited/);
        host.close();
    } finally { t.close(); }
});

test('closes the room when the host leaves', async () => {
    const t = await setup();
    try {
        const { body: created } = await t.api('POST', '/api/game-rooms', 'alice', { game: 'snake-plus' });
        const host = await t.socket(created.roomId, 'alice');
        await host.next();
        await t.api('POST', `/api/game-rooms/${created.roomId}/invite`, 'alice', { toUsername: 'bob' });
        const guest = await t.socket(created.roomId, 'bob');
        await guest.next();
        host.close();
        assert.strictEqual((await guest.next()).t, 'ended');
    } finally { t.close(); }
});
