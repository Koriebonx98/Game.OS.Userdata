const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, 'src/game.js'), 'utf8');

function player(name, relay, initialSave = null) {
    const handlers = {}, windowHandlers = {}, elements = {};
    let frame, now = 0;
    const element = id => elements[id] ||= {
        id, disabled: false, hidden: false, textContent: '', value: '', dataset: {},
        listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; },
        setAttribute() {}, replaceChildren(...children) { this.children = children; },
        setPointerCapture() {}
    };
    const ctx = new Proxy({}, { get: (_, key) => key === 'createLinearGradient'
        ? () => ({ addColorStop() {} }) : () => {} });
    const canvas = element('game');
    canvas.width = 960; canvas.height = 540; canvas.getContext = () => ctx;
    const document = {
        fullscreenEnabled: false, fullscreenElement: null,
        getElementById: element, querySelector: () => element('cabinet'),
        querySelectorAll: () => ['left', 'right', 'jump', 'power'].map(k => {
            const button = element('touch-' + k); button.dataset.control = k; return button;
        }), addEventListener() {},
        createElement: () => element('option-' + Math.random())
    };
    const unlocked = [], saves = [];
    const api = {
        ready: async () => ({ user: { username: name } }),
        on(type, fn) { handlers[type] = fn; return api; },
        save: { get: async () => initialSave, set: async data => { saves.push(data); } },
        achievements: { unlock: async id => { unlocked.push(id); } },
        multiplayer: {
            host: async opts => { relay.host = instance; relay.opts = opts; },
            players: async () => ['Guest'],
            listPublic: async () => [{ host: 'Host', roomId: 'room' }],
            join: async (host, id) => {
                assert.equal(host, 'Host'); assert.equal(id, 'room');
                relay.guest = instance;
                relay.host.emit('join', { username: name });
            },
            send: async data => {
                relay.messages.push({ from: name, data: JSON.parse(JSON.stringify(data)) });
                const other = name === 'Host' ? relay.guest : relay.host;
                if (other) other.emit('message', { from: name, data: JSON.parse(JSON.stringify(data)) });
            },
            invite: async () => {},
            leave: async () => {}
        }
    };
    const window = {
        parent: {}, GameOS: api,
        addEventListener(type, fn) { windowHandlers[type] = fn; }
    };
    const instance = {
        elements, unlocked, saves,
        emit(type, data) { if (handlers[type]) handlers[type](data); },
        click(id) { return element(id).listeners.click(); },
        key(code, type = 'keydown') { windowHandlers[type]({ code, preventDefault() {} }); },
        step(ms = 16) { now += ms; const next = frame; next(now); }
    };
    vm.runInNewContext(source, {
        window, document, navigator: { getGamepads: () => [] },
        performance: { now: () => now }, requestAnimationFrame: fn => { frame = fn; },
        console
    });
    return instance;
}

test('co-op uses the host simulation and syncs guest input, achievements and progress', async () => {
    const relay = { messages: [] };
    const host = player('Host', relay);
    const guest = player('Guest', relay);
    await new Promise(resolve => setImmediate(resolve));
    await host.click('host-button');
    await guest.click('join-button');
    assert.deepEqual(JSON.parse(JSON.stringify(relay.opts)), { maxPlayers: 2, public: true, mode: 'coop' });
    host.key('ArrowRight'); guest.key('ArrowRight');
    for (let i = 0; i < 120; i++) { guest.step(); host.step(); }
    await new Promise(resolve => setImmediate(resolve));
    const states = relay.messages.filter(m => m.from === 'Host' && m.data.t === 'state').map(m => m.data);
    assert.ok(states.some(s => s.q.active && s.q.x > 150), 'guest movement is simulated by host');
    assert.ok(states.some(s => s.coins.some(Boolean)), 'collected coins are included in snapshots');
    assert.ok(host.unlocked.includes('first-coin'));
    assert.ok(guest.unlocked.includes('first-coin'));
    assert.equal(guest.elements['pause-button'].disabled, true);
    guest.click('quit-button');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(guest.saves.at(-1).run.level, 1);
    assert.equal(guest.elements['pause-button'].disabled, false);
});

test('a saved level can be continued after Game OS connects', async () => {
    const relay = { messages: [] };
    const guest = player('Guest', relay, { bestScore: 800, run: { level: 4, lives: 3, totalCoins: 20, coinProgress: 0, score: 800 } });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(guest.elements['continue-button'].disabled, false);
    guest.click('continue-button');
    guest.step();
    assert.match(guest.elements.status.textContent, /LEVEL 4/);
});

test('a quick touch jump starts the game even between animation frames', async () => {
    const relay = { messages: [] };
    const guest = player('Guest', relay);
    await new Promise(resolve => setImmediate(resolve));
    const jump = guest.elements['touch-jump'];
    const event = { preventDefault() {}, pointerId: 1 };
    jump.listeners.pointerdown(event);
    jump.listeners.pointerup(event);
    guest.step();
    assert.match(guest.elements.status.textContent, /LEVEL 1/);
});

test('a guest touch jump is retained until the next network input update', async () => {
    const relay = { messages: [] };
    const host = player('Host', relay);
    const guest = player('Guest', relay);
    await new Promise(resolve => setImmediate(resolve));
    await host.click('host-button');
    await guest.click('join-button');
    const jump = guest.elements['touch-jump'];
    const event = { preventDefault() {}, pointerId: 1 };
    jump.listeners.pointerdown(event); jump.listeners.pointerup(event);
    for (let i = 0; i < 6; i++) guest.step();
    assert.ok(relay.messages.some(m => m.from === 'Guest' && m.data.t === 'input' && m.data.jump));
});
