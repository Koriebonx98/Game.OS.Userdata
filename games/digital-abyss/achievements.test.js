const test = require('node:test');
const assert = require('node:assert');
const A = require('./achievements.js');

const fresh = () => ({ achievements: {}, stats: { solved: [], perfectCases: [] } });
const solved = (over) => Object.assign({ scenarioId: 1, wrongAttempts: 0, lives: 3, elapsedMs: 30 * 60000, remainingMs: 30 * 60000, allViewed: false }, over);

test('perfect solve earns case_closed and perfect_run', () => {
    const ids = A.evaluate('solved', solved(), fresh());
    assert.deepStrictEqual(ids.sort(), ['case_closed', 'perfect_run']);
});

test('mistakes block perfect_run; one life left earns on_the_edge', () => {
    const ids = A.evaluate('solved', solved({ wrongAttempts: 2, lives: 1 }), fresh());
    assert.ok(ids.includes('on_the_edge'));
    assert.ok(!ids.includes('perfect_run'));
});

test('losing earns outta_luck, already-earned ids are not repeated', () => {
    assert.deepStrictEqual(A.evaluate('lost', { reason: 'timeout' }, fresh()), ['outta_luck']);
    const state = fresh();
    state.achievements.outta_luck = 'x';
    assert.deepStrictEqual(A.evaluate('lost', {}, state), []);
});

test('hidden level traps only fire for that level\'s decoy location', () => {
    assert.deepStrictEqual(A.evaluate('wrong', { scenarioId: 4, location: 'server room alpha' }, fresh()), ['trap_4']);
    assert.deepStrictEqual(A.evaluate('wrong', { scenarioId: 4, location: 'basement' }, fresh()), []);
    assert.deepStrictEqual(A.evaluate('wrong', { scenarioId: 1, location: 'server room alpha' }, fresh()), []);
});

test('last_gasp and speed_sleuth depend on the clock', () => {
    const ids = A.evaluate('solved', solved({ elapsedMs: 59 * 60000 + 30000, remainingMs: 30000 }), fresh());
    assert.ok(ids.includes('last_gasp'));
    assert.ok(!ids.includes('speed_sleuth'));
    assert.ok(A.evaluate('solved', solved({ elapsedMs: 10 * 60000 }), fresh()).includes('speed_sleuth'));
});

test('streak and master detective use cumulative stats', () => {
    const state = fresh();
    state.stats.solved = [1, 2, 3, 4];
    state.stats.perfectCases = [1, 2];
    const ids = A.evaluate('solved', solved({ scenarioId: 5 }), state);
    assert.ok(ids.includes('all_cases'));
    assert.ok(ids.includes('perfect_trio'));
});

test('locked hidden achievements reveal neither name nor description', () => {
    const def = A.byId.last_gasp;
    const locked = A.present(def, '');
    assert.ok(!locked.name.includes('Last Gasp'));
    assert.ok(!locked.description.includes('minute'));
    assert.strictEqual(A.present(def, '2026-01-01T00:00:00Z').name, 'Last Gasp');
});

test('published template contains no hidden achievements', () => {
    const published = require('./achievements.json').Items.map(i => i.achievementId);
    for (const d of A.DEFS) assert.strictEqual(published.includes(d.id), !d.hidden, d.id);
});
