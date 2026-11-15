const test = require('node:test');
const assert = require('node:assert');
const E = require('./engine');
require('./questions-1');
require('./questions-2');

const bank = globalThis.QuizyBank;
const pool = () => E.buildPool(bank, null, new Date('2026-11-14T12:00:00Z'));

test('every subject has 20+ questions, each with four distinct options', () => {
    const p = pool();
    for (const s of E.SUBJECTS) {
        if (s.id === 'spelling') { assert.ok(p.weekWords.length >= 20); continue; }
        assert.ok(p.subjects[s.id].length >= 20, s.id);
        const prompts = new Set();
        for (const q of p.subjects[s.id]) {
            assert.strictEqual(q.length, 5, q[0]);
            assert.strictEqual(new Set(q.slice(1)).size, 4, 'duplicate options: ' + q[0]);
            assert.ok(!prompts.has(q[0]), 'duplicate question: ' + q[0]);
            prompts.add(q[0]);
        }
    }
    for (const group of ['places', 'celebs']) {
        assert.ok(p.pictures[group].length >= 20);
        for (const q of p.pictures[group]) assert.strictEqual(new Set(q.slice(1)).size, 4, q[0]);
    }
});

test('maths questions are right and the weekly set is the same for everyone', () => {
    const a = pool(), b = pool();
    assert.deepStrictEqual(a.subjects.maths, b.subjects.maths);
    assert.deepStrictEqual(a.weekWords, b.weekWords);
    const next = E.buildPool(bank, null, new Date('2026-11-23T12:00:00Z'));
    assert.notDeepStrictEqual(next.subjects.maths, a.subjects.maths);
    const sq = a.subjects.maths.find(q => /squared/.test(q[0]));
    if (sq) { const n = Number(sq[0].match(/\d+/)[0]); assert.strictEqual(Number(sq[1]), n * n); }
});

test('weekId rolls over on Monday (UTC)', () => {
    assert.strictEqual(E.weekId(new Date('2026-11-15T23:59:00Z')), '2026-W46');
    assert.strictEqual(E.weekId(new Date('2026-11-16T00:00:00Z')), '2026-W47');
    assert.strictEqual(E.weekId(new Date('2021-01-03T00:00:00Z')), '2020-W53');
});

test('weekly questions are merged, and malformed ones are ignored', () => {
    const weekly = { subjects: { nature: [['Q?', 'a', 'b', 'c', 'd'], ['bad', 'a', 'a', 'b', 'c'], ['short', 'a']], nope: [['x', 'a', 'b', 'c', 'd']] } };
    const p = E.buildPool(bank, weekly, new Date('2026-11-14T12:00:00Z'));
    assert.strictEqual(p.subjects.nature.length, 21);
    assert.ok(p.weeklyIds.has('Q?'));
});

test('spelling needs the exact letters but ignores case and surrounding spaces', () => {
    assert.ok(E.checkSpelling('  Necessary ', 'necessary'));
    assert.ok(!E.checkSpelling('neccessary', 'necessary'));
    assert.ok(!E.checkSpelling('', 'necessary'));
});

test('buildQuiz makes three rounds without repeats and hides answers from players', () => {
    const p = pool();
    const rounds = E.buildQuiz(p, [['nature', 'spelling', 'maths'], ['music', 'sport', 'spelling', 'general']]);
    assert.deepStrictEqual(rounds.map(r => r.kind), ['standard', 'picture', 'quickfire']);
    assert.deepStrictEqual(rounds.map(r => r.questions.length), [10, 6, 10]);
    const keys = rounds.flatMap(r => r.questions).map(q => q.prompt + (q.word || q.wiki || ''));
    assert.strictEqual(new Set(keys).size, keys.length);
    assert.ok(rounds[2].questions.every(q => q.type === 'mc' && q.secs === 6));
    for (const q of rounds.flatMap(r => r.questions)) {
        const pub = E.publicQuestion(q);
        assert.ok(!('answer' in pub));
        if (q.type !== 'spell') assert.ok(q.answer >= 0 && q.answer < 4);
    }
    assert.ok(rounds[0].questions.some(q => q.type === 'spell'));
    assert.strictEqual(E.buildQuiz(p, [['nature', 'music', 'sport']], { picture: false }).length, 2);
});

test('only chosen subjects are used', () => {
    const p = pool();
    const rounds = E.buildQuiz(p, [['science', 'history', 'food']], { picture: false });
    for (const q of rounds.flatMap(r => r.questions)) assert.ok(['science', 'history', 'food'].includes(q.subject));
});

test('scoring rewards speed and streaks; wrong answers score nothing', () => {
    const std = { type: 'mc', kind: 'standard' }, quick = { type: 'mc', kind: 'quickfire' };
    assert.strictEqual(E.points(std, false, 1, 3), 0);
    assert.strictEqual(E.points(std, true, 1, 0), 150);
    assert.strictEqual(E.points(std, true, 0, 0), 100);
    assert.strictEqual(E.points(std, true, 0, 9), 150);
    assert.strictEqual(E.points(quick, true, 0, 20), 100);
    assert.strictEqual(E.points({ type: 'spell', kind: 'standard' }, true, 0, 0), 150);
    assert.ok(E.isCorrect({ type: 'mc', answer: 2 }, 2) && !E.isCorrect({ type: 'mc', answer: 2 }, '2'));
});

test('validPicks needs 3-5 distinct known subjects', () => {
    assert.ok(E.validPicks(['nature', 'music', 'sport']));
    assert.ok(!E.validPicks(['nature', 'music']));
    assert.ok(!E.validPicks(['nature', 'music', 'music']));
    assert.ok(!E.validPicks(['nature', 'music', 'sport', 'food', 'tech', 'gaming']));
    assert.ok(!E.validPicks(['nature', 'music', 'bogus']));
});

test('ranking shares places on ties', () => {
    const r = E.ranking([{ name: 'B', score: 100, correct: 3 }, { name: 'A', score: 100, correct: 3 }, { name: 'C', score: 50, correct: 1 }]);
    assert.deepStrictEqual(r.map(x => [x.name, x.place]), [['A', 1], ['B', 1], ['C', 3]]);
});

test('chase offers trade risk for money and head-to-head ends home or caught', () => {
    const [high, mid, low] = E.chaseOffers(6000);
    assert.deepStrictEqual([high.money, mid.money, low.money], [18000, 6000, 2000]);
    assert.ok(high.start < mid.start && mid.start < low.start);
    const board = { pos: 2, chaser: 0, steps: E.CHASE.steps };
    assert.strictEqual(E.chaseStep(board, true, true).outcome, 'on');
    assert.strictEqual(E.chaseStep({ pos: 3, chaser: 2, steps: 7 }, false, true).outcome, 'caught');
    assert.strictEqual(E.chaseStep({ pos: 6, chaser: 5, steps: 7 }, true, true).outcome, 'home');
    assert.ok(E.finalChaseWon(7, 6) && !E.finalChaseWon(6, 6));
});

test('chase is beatable but not easy for an average player', () => {
    const rng = E.mulberry32(7);
    let home = 0;
    const runs = 4000;
    for (let i = 0; i < runs; i++) {
        let st = { pos: E.chaseOffers(0)[1].start, chaser: 0, steps: E.CHASE.steps };
        while (st.outcome !== 'home' && st.outcome !== 'caught') st = Object.assign(E.chaseStep(st, rng() < 0.65, rng() < E.CHASE.chaserAccuracy), {});
        if (st.outcome === 'home') home++;
    }
    assert.ok(home / runs > 0.3 && home / runs < 0.7, `escape rate ${home / runs}`);
});

test('millionaire winnings keep the safe havens', () => {
    assert.strictEqual(E.LADDER.length, 15);
    assert.strictEqual(E.LADDER[14], 1000000);
    assert.strictEqual(E.winnings(0, true), 0);
    assert.strictEqual(E.winnings(4, true), 0);
    assert.strictEqual(E.winnings(7, true), 1000);
    assert.strictEqual(E.winnings(12, true), 32000);
    assert.strictEqual(E.winnings(7, false), 4000);
    assert.strictEqual(E.winnings(15, false), 1000000);
});

test('lifelines never hide or contradict the right answer', () => {
    const rng = E.mulberry32(3);
    for (let i = 0; i < 200; i++) {
        const answer = i % 4;
        const hidden = E.fiftyFifty(answer, 4, rng);
        assert.strictEqual(hidden.length, 2);
        assert.ok(!hidden.includes(answer));
        const votes = E.audienceVote(answer, 4, i % 15, hidden, rng);
        assert.strictEqual(votes.reduce((a, b) => a + b, 0), 100);
        assert.ok(hidden.every(h => votes[h] === 0));
        const call = E.phoneFriend(answer, 4, i % 15, hidden, rng);
        assert.ok(!hidden.includes(call.guess));
    }
});

test('the deck draws easier questions early and never repeats until it runs out', () => {
    const p = pool();
    const deck = E.makeDeck(p, [['science', 'history']], E.mulberry32(5));
    const early = Array.from({ length: 5 }, () => deck.draw({ frac: 0 }));
    const late = Array.from({ length: 5 }, () => deck.draw({ frac: 1 }));
    const idx = q => { const list = p.subjects[q.subject]; return list.findIndex(r => r[0] === q.prompt) / (list.length - 1); };
    const avg = a => a.reduce((x, y) => x + y, 0) / a.length;
    assert.ok(avg(early.map(idx)) < avg(late.map(idx)));
    const seen = new Set();
    for (let i = 0; i < 30; i++) { const q = deck.draw({}); assert.ok(!seen.has(q.prompt)); seen.add(q.prompt); }
    assert.ok(Array.from({ length: 100 }, () => deck.draw({})).every(q => q.type === 'mc' && q.subject !== 'spelling'));
});
