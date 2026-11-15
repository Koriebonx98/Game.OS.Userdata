const test = require('node:test');
const assert = require('node:assert');
const A = require('./achievements.js');
const { upsert, rank } = require('./leaderboard');
const published = require('./achievements.json');

const fresh = () => ({ achievements: {}, stats: { games: 0, subjects: [] } });
const end = (ctx, state) => A.evaluate('end', Object.assign({ total: 26, correct: 10, subjects: ['nature', 'music', 'maths'], allSubjects: ['nature', 'music', 'maths', 'sport'] }, ctx), state || fresh());

test('start earns first_game once; online start earns better_together', () => {
    assert.deepStrictEqual(A.evaluate('start', {}, fresh()), ['first_game']);
    assert.ok(A.evaluate('start', { online: true }, fresh()).includes('better_together'));
    const s = fresh(); s.achievements.first_game = 'x';
    assert.deepStrictEqual(A.evaluate('start', {}, s), []);
});

test('streak, score and correct-answer thresholds', () => {
    assert.ok(end({ bestStreak: 5 }).includes('warm_up') && !end({ bestStreak: 5 }).includes('on_fire'));
    assert.ok(end({ bestStreak: 10 }).includes('on_fire'));
    assert.ok(end({ correct: 20 }).includes('brainiac'));
    assert.ok(end({ score: 2000 }).includes('high_scorer') && !end({ score: 1999 }).includes('high_scorer'));
});

test('round specific achievements', () => {
    assert.ok(end({ spelled: 3 }).includes('spelling_bee'));
    assert.ok(end({ picTotal: 6, picCorrect: 6 }).includes('picture_perfect'));
    assert.ok(!end({ picTotal: 6, picCorrect: 5 }).includes('picture_perfect'));
    assert.ok(!end({ picTotal: 0, picCorrect: 0 }).includes('picture_perfect'));
    assert.ok(end({ quickCorrect: 8 }).includes('quick_draw'));
});

test('winning needs rivals; online adds online_champion', () => {
    assert.ok(!end({ won: true, rivals: 0 }).includes('winner'));
    const ids = end({ won: true, rivals: 2, online: true });
    assert.ok(ids.includes('winner') && ids.includes('online_champion'));
});

test('polymath collects subjects across games; marathon counts the finished game', () => {
    const s = fresh(); s.stats.subjects = ['sport']; s.stats.games = 9;
    const ids = end({}, s);
    assert.ok(ids.includes('polymath') && ids.includes('marathon'));
    assert.ok(!end({}).includes('polymath'));
    assert.ok(end({ subjects: ['a', 'b', 'c', 'd', 'e'] }).includes('well_rounded'));
});

test('hidden achievements only fire on their trigger and are masked until unlocked', () => {
    assert.ok(end({ total: 26, correct: 26 }).includes('flawless'));
    assert.ok(end({ total: 26, correct: 0 }).includes('better_luck'));
    assert.ok(!end({ correct: 10 }).includes('better_luck'));
    assert.strictEqual(A.present(A.byId.flawless, '').name, 'Hidden achievement');
    assert.strictEqual(A.present(A.byId.flawless, 't').name, 'Flawless');
});

test('mode and matchmaking achievements', () => {
    assert.ok(end({ escaped: true }).includes('escaped'));
    assert.ok(end({ finalWon: true }).includes('chase_champ'));
    assert.ok(end({ mode: 'millionaire', money: 32000 }).includes('big_money'));
    assert.ok(!end({ mode: 'millionaire', money: 16000 }).includes('big_money'));
    assert.ok(!end({ mode: 'chase', money: 64000 }).includes('big_money'));
    assert.ok(end({ millionaire: true }).includes('millionaire'));
    const s = fresh(); s.stats.modes = ['pub', 'chase'];
    assert.ok(end({ mode: 'millionaire' }, s).includes('all_modes'));
    assert.ok(!end({ mode: 'pub' }, s).includes('all_modes'));
    assert.ok(end({ publicMatch: true, online: true }).includes('meet_world'));
    assert.ok(!end({ publicMatch: true, online: false }).includes('meet_world'));
});

test('published achievements.json lists every non-hidden achievement', () => {
    const ids = published.Items.map(i => i.achievementId).sort();
    assert.deepStrictEqual(ids, A.DEFS.filter(d => !d.hidden).map(d => d.id).sort());
});

test('leaderboard keeps best numbers, skips no-op writes, ranks with shared places and filters to friends', () => {
    let board = upsert(null, 'Alice', { wins: 3, bestScore: 40, correct: 10 }, 't1');
    assert.strictEqual(upsert(board, 'Alice', { wins: 1, bestScore: 5 }, 't2'), undefined);
    board = upsert(board, 'Alice', { wins: 4, bestScore: 20 }, 't3');
    assert.deepStrictEqual([board.players.alice.wins, board.players.alice.bestScore], [4, 40]);
    board = upsert(board, 'Bob', { wins: 4 }, 't');
    board = upsert(board, 'Cara', { wins: 2 }, 't');
    assert.deepStrictEqual(rank(board, 'wins').map(r => [r.name, r.place]), [['Alice', 1], ['Bob', 1], ['Cara', 3]]);
    assert.deepStrictEqual(rank(board, 'wins', new Set(['bob', 'cara'])).map(r => r.name), ['Bob', 'Cara']);
    assert.deepStrictEqual(rank(board, 'correct').map(r => r.name), ['Alice']);
});

test('board is capped to the top players without dropping the writer', () => {
    let board = null;
    for (let i = 0; i < 501; i++) board = upsert(board, 'p' + i, { wins: i + 1 }, 't');
    assert.strictEqual(Object.keys(board.players).length, 500);
    board = upsert(board, 'newbie', { correct: 1 }, 't');
    assert.ok(board.players.newbie);
});
