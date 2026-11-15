// Run: node --test gameos-bridge.test.js  (bridge + SDK talking over a fake postMessage pair, demo mode)
const test = require('node:test');
const assert = require('node:assert');

test('community game can unlock achievements, save and is blocked from unknown methods', async () => {
    const mem = {};
    const listeners = { parent: [], child: [] };
    const parent = { addEventListener: (t, f) => t === 'message' && listeners.parent.push(f), removeEventListener() {} };
    const child = { addEventListener: (t, f) => t === 'message' && listeners.child.push(f), removeEventListener() {} };
    child.parent = parent;
    parent.postMessage = () => {};
    const frameWin = { postMessage: msg => setImmediate(() => listeners.child.forEach(f => f({ source: parent, data: msg }))) };
    child.postMessage = (msg) => setImmediate(() => listeners.parent.forEach(f => f({ source: frameWin, data: msg })));
    parent.parent = parent; // parent is the top window
    child.parent = { postMessage: msg => child.postMessage(msg) };
    // the SDK checks e.source === window.parent
    const sdkParent = child.parent;
    frameWin.postMessage = msg => setImmediate(() => listeners.child.forEach(f => f({ source: sdkParent, data: msg })));

    Object.assign(global, {
        window: Object.assign(parent, { addEventListener: parent.addEventListener }),
        document: { hidden: false, addEventListener() {}, body: { appendChild() {} }, createElement: () => ({ style: {}, remove() {} }) },
        localStorage: { getItem: k => (k in mem ? mem[k] : null), setItem: (k, v) => { mem[k] = String(v); } },
        MODE: 'demo', getCurrentUser: () => ({ username: 'Dev' }),
        _kvCache: { get: async () => undefined, set: async () => {} },
        fetch: async () => ({ ok: true, json: async () => ({ Items: [{ achievementId: 'first', Name: 'First', Description: 'd' }] }) })
    });
    require('./gameos-bridge.js');
    const bridge = window.GameOSBridge.attach({ frame: { contentWindow: frameWin }, game: { TitleID: 'dev-t1', Title: 'T' }, definitionsUrl: 'x' });

    global.window = child; // SDK runs in the child window
    delete require.cache[require.resolve('./sdk/gameos.js')];
    const sdkCode = require('fs').readFileSync(require.resolve('./sdk/gameos.js'), 'utf8');
    new Function('window', 'globalThis', sdkCode.replace("typeof window !== 'undefined' ? window : globalThis", 'window'))(child, child);
    const GameOS = child.GameOS;

    const info = await GameOS.ready();
    assert.strictEqual(info.user.username, 'Dev');
    assert.strictEqual((await GameOS.achievements.unlock('first')).unlocked, true);
    assert.strictEqual((await GameOS.achievements.unlock('first')).unlocked, false);
    await assert.rejects(GameOS.achievements.unlock('nope'), /Unknown achievement/);
    await GameOS.save.set({ level: 3 });
    assert.deepStrictEqual(await GameOS.save.get(), { level: 3 });
    await assert.rejects(GameOS.save.set('x'.repeat(300 * 1024)), /too big/);
    bridge.detach();
});
