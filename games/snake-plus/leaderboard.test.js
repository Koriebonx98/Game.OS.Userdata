const test = require('node:test');
const assert = require('node:assert');
const { upsert, rank } = require('./leaderboard');

test('upsert adds a player, keeps their best numbers and skips no-op writes', () => {
    let board = upsert(null, 'Alice', { wins: 3, bestScore: 40, foodEaten: 10 }, 't1');
    assert.strictEqual(board.players.alice.wins, 3);
    assert.strictEqual(upsert(board, 'Alice', { wins: 3, bestScore: 40, foodEaten: 10 }, 't2'), undefined);
    assert.strictEqual(upsert(board, 'Alice', { wins: 1, bestScore: 5 }, 't2'), undefined);
    board = upsert(board, 'Alice', { wins: 4, bestScore: 20, foodEaten: 12 }, 't3');
    assert.deepStrictEqual([board.players.alice.wins, board.players.alice.bestScore, board.players.alice.at], [4, 40, 't3']);
});

test('rank orders by metric, shares places on ties, hides zeros and can be limited to friends', () => {
    let board = null;
    board = upsert(board, 'Bob', { wins: 5 }, 't');
    board = upsert(board, 'Alice', { wins: 5, bestScore: 9 }, 't');
    board = upsert(board, 'Cara', { wins: 2 }, 't');
    assert.deepStrictEqual(rank(board, 'wins').map(r => [r.name, r.place]), [['Alice', 1], ['Bob', 1], ['Cara', 3]]);
    assert.deepStrictEqual(rank(board, 'bestScore').map(r => r.name), ['Alice']);
    assert.deepStrictEqual(rank(board, 'wins', new Set(['bob', 'cara'])).map(r => r.name), ['Bob', 'Cara']);
});

test('board is capped to the top players without dropping the writer', () => {
    let board = null;
    for (let i = 0; i < 501; i++) board = upsert(board, 'p' + i, { wins: i + 1 }, 't');
    assert.strictEqual(Object.keys(board.players).length, 500);
    board = upsert(board, 'newbie', { wins: 0, foodEaten: 1 }, 't');
    assert.ok(board.players.newbie);
});
