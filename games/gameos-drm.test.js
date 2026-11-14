const test = require('node:test');
const assert = require('node:assert');
require('./gameos-drm.js');
const D = globalThis.GameOSDRM;

test('keys are bound to title and user, case-insensitively', async () => {
    const k = await D.makeKey('digital-abyss', 'Tester');
    assert.match(k, /^GOS(-[A-Z2-9]{4}){4}$/);
    assert.ok(await D.verify(k, 'digital-abyss', 'tester'));
    assert.ok(!(await D.verify(k, 'digital-abyss', 'other')));
    assert.ok(!(await D.verify(k, 'other-game', 'tester')));
    assert.ok(!(await D.verify(null, 'digital-abyss', 'tester')));
});
