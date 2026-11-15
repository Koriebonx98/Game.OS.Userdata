// Run: node --test community.test.js
const test = require('node:test');
const assert = require('node:assert');
global.window = {};
global.escapeHtml = s => String(s);
global.ADMIN_USERNAME_LOWER = 'admin.gameos';
global.MODE = 'demo';
global.getCurrentUser = () => ({ username: 'Dev' });
global.isAdminUser = () => false;
global.localStorage = { getItem: () => null, setItem() {} };
require('./community.js');
const C = window.Community;

test('repo links are parsed and bad ones rejected', () => {
    assert.deepStrictEqual(C.parseRepo('https://github.com/me/my-game/'), { owner: 'me', repo: 'my-game' });
    assert.strictEqual(C.parseRepo('https://evil.com/me/game'), null);
    assert.strictEqual(C.parseRepo('javascript:alert(1)'), null);
});
test('submission form validation', () => {
    const ok = { title: 'Cool Game', description: 'A really cool game for everyone.', repoUrl: 'https://github.com/a/b' };
    assert.strictEqual(C.cleanForm(ok).entry, 'index.html');
    assert.throws(() => C.cleanForm({ ...ok, entry: '../x.html' }));
    assert.throws(() => C.cleanForm({ ...ok, coverUrl: 'http://x/y.png' }));
    assert.throws(() => C.cleanForm({ ...ok, description: 'short' }));
});
test('scheduled games only go live after their publish time', () => {
    const past = new Date(Date.now() - 1000).toISOString(), future = new Date(Date.now() + 1e6).toISOString();
    assert.ok(C.isLive({ status: 'approved', publishAt: past }));
    assert.ok(!C.isLive({ status: 'approved', publishAt: future }));
    assert.ok(!C.isLive({ status: 'pending' }));
});
