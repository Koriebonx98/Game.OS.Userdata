// Run: node --test lan-server/test-lan-server.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const WebSocket = require('ws');
const { createLanServer } = require('./server');

async function start() {
    const lan = createLanServer({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'lan-')), name: 'Test' });
    await new Promise(r => lan.server.listen(0, r));
    const base = 'http://127.0.0.1:' + lan.server.address().port;
    const call = async (method, p, token, body) => {
        const r = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body && JSON.stringify(body) });
        return { status: r.status, body: await r.json().catch(() => ({})) };
    };
    const login = async (username, secret = 'x'.repeat(20)) => (await call('POST', '/api/lan/login', null, { username, secret }));
    return { base, call, login, close: () => { lan.server.closeAllConnections(); lan.server.close(); } };
}

test('accounts are claimed per device and tickets work', async () => {
    const t = await start();
    try {
        const a = await t.login('Alice');
        assert.strictEqual(a.status, 200);
        assert.ok(a.body.ticket.startsWith('gost_alice.'));
        assert.strictEqual((await t.login('alice', 'y'.repeat(20))).status, 403);
        assert.strictEqual((await t.login('alice')).status, 200);
        assert.strictEqual((await t.login('../x')).status, 400);
        assert.strictEqual((await t.call('GET', '/api/lan/players', 'gost_alice.bad')).status, 401);
    } finally { t.close(); }
});

test('lobbies, public list and invites work between LAN players', async () => {
    const t = await start();
    try {
        const a = (await t.login('Alice')).body, b = (await t.login('Bob')).body;
        assert.deepStrictEqual((await t.call('GET', '/api/lan/players', a.ticket)).body.players, ['Bob']);
        const room = (await t.call('POST', '/api/game-rooms', a.ticket, { game: 'quizy', public: true })).body;
        assert.ok(room.roomId);
        const host = new WebSocket(t.base.replace('http', 'ws') + '/game/' + room.roomId + '?auth=' + a.ticket);
        const hello = new Promise(r => host.once('message', r));
        assert.strictEqual(JSON.parse(await hello).role, 'host');
        const list = (await t.call('GET', '/api/game-rooms/public?game=quizy', b.ticket)).body.rooms;
        assert.strictEqual(list.length, 1);
        assert.strictEqual((await t.call('POST', `/api/game-rooms/${room.roomId}/invite`, a.ticket, { toUsername: 'bob' })).status, 200);
        const inv = (await t.call('GET', '/api/lan/invites', b.ticket)).body.invites;
        assert.strictEqual(inv[0].roomId, room.roomId);
        assert.strictEqual(inv[0].from, 'Alice');
        host.terminate();
    } finally { t.close(); }
});

test('only game files are served, never server or backend code', async () => {
    const t = await start();
    try {
        assert.strictEqual((await fetch(t.base + '/games/quizy/index.html')).status, 200);
        assert.strictEqual((await fetch(t.base + '/lan-server/server.js')).status, 404);
        assert.strictEqual((await fetch(t.base + '/backend/index.js')).status, 404);
        assert.strictEqual((await fetch(t.base + '/games/../backend/index.js')).status, 404);
    } finally { t.close(); }
});
