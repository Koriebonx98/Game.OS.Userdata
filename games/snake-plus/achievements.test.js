const test = require('node:test');
const assert = require('node:assert');
const A = require('./achievements.js');

const fresh = () => ({ achievements: {}, stats: { games: 0, foodEaten: 0, items: [] } });

test('start and first food unlock their achievements once', () => {
    assert.deepStrictEqual(A.evaluate('start', {}, fresh()), ['first_game']);
    assert.deepStrictEqual(A.evaluate('item', { item: 'food' }, fresh()), ['first_bite']);
    const s = fresh();
    s.achievements.first_bite = 'x';
    assert.deepStrictEqual(A.evaluate('item', { item: 'food' }, s), []);
});

test('online start earns better_together', () => {
    assert.ok(A.evaluate('start', { online: true }, fresh()).includes('better_together'));
    assert.ok(!A.evaluate('start', { online: false }, fresh()).includes('better_together'));
});

test('power_user needs every power-up type', () => {
    const s = fresh();
    s.stats.items = ['speed', 'lockdown', 'colour', 'tp'];
    assert.ok(!A.evaluate('item', { item: 'speed' }, s).includes('power_user'));
    assert.ok(A.evaluate('item', { item: 'destruction' }, s).includes('power_user'));
});

test('score thresholds and mode-specific scores', () => {
    const ids = A.evaluate('end', { mode: 'classic', score: 250, rivals: [] }, fresh());
    assert.deepStrictEqual(ids.sort(), ['classic_200', 'growing_up', 'long_boi']);
    assert.ok(A.evaluate('end', { mode: 'rush', score: 150, rivals: [] }, fresh()).includes('rush_hour'));
});

test('winning needs rivals; hard bot and online variants', () => {
    assert.ok(!A.evaluate('end', { mode: 'classic', score: 5, won: true, rivals: [] }, fresh()).includes('winner'));
    const vsHard = A.evaluate('end', { mode: 'survival', score: 5, won: true, rivals: ['hard'] }, fresh());
    assert.ok(vsHard.includes('winner') && vsHard.includes('bot_buster'));
    const online = A.evaluate('end', { mode: 'firstTo', score: 50, won: true, online: true, rivals: ['remote'] }, fresh());
    assert.ok(online.includes('online_champion') && online.includes('first_to'));
});

test('marathon counts the game being finished; hidden ones only fire on their trigger', () => {
    const s = fresh();
    s.stats.games = 9;
    assert.ok(A.evaluate('end', { mode: 'survival', score: 0, rivals: [] }, s).includes('marathon'));
    assert.deepStrictEqual(A.evaluate('item', { item: 'bomb' }, fresh()), ['kaboom']);
    assert.ok(A.evaluate('end', { mode: 'survival', score: 0, died: true, ticks: 10, rivals: [] }, fresh()).includes('perfect_start'));
});

test('hidden achievements are masked until unlocked', () => {
    const def = A.byId.kaboom;
    assert.strictEqual(A.present(def, '').name, 'Hidden achievement');
    assert.strictEqual(A.present(def, 't').name, 'Kaboom');
});
