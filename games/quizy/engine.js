/* Quizy game logic: subjects, weekly question rotation, quiz building, spelling checks and scoring.
 * Pure (no DOM, no network) so the game and its tests share it. */
(function (root) {
    'use strict';

    const SUBJECTS = [
        { id: 'nature', name: 'Nature', icon: '🌿' },
        { id: 'music', name: 'Music', icon: '🎵' },
        { id: 'entertainment', name: 'Entertainment', icon: '🎭' },
        { id: 'culture', name: 'Culture', icon: '🏛️' },
        { id: 'movies', name: 'Movies & TV', icon: '🎬' },
        { id: 'places', name: 'Places', icon: '🌍' },
        { id: 'general', name: 'General Knowledge', icon: '💡' },
        { id: 'spelling', name: 'Spelling', icon: '🔤', kind: 'spelling' },
        { id: 'maths', name: 'Maths', icon: '➗' },
        { id: 'science', name: 'Science', icon: '🔬' },
        { id: 'history', name: 'History', icon: '📜' },
        { id: 'sport', name: 'Sport', icon: '⚽' },
        { id: 'food', name: 'Food & Drink', icon: '🍕' },
        { id: 'tech', name: 'Technology', icon: '💻' },
        { id: 'gaming', name: 'Gaming', icon: '🎮' }
    ];
    const subjectById = Object.fromEntries(SUBJECTS.map(s => [s.id, s]));
    const MIN_SUBJECTS = 3, MAX_SUBJECTS = 5, MAX_PLAYERS = 4;
    const QUESTIONS_PER_SUBJECT = 20;

    const ROUNDS = [
        { kind: 'standard', name: 'Round 1: Mixed Subjects', blurb: 'Questions from everyone\'s chosen subjects. Spelling words are read out loud: type them exactly.', secs: 15, count: 10 },
        { kind: 'picture', name: 'Round 2: Picture Round', blurb: 'Name the place or the celebrity from the photo.', secs: 20, count: 6 },
        { kind: 'quickfire', name: 'Round 3: Quick Fire', blurb: 'Six seconds a question. Streaks score bonus points!', secs: 6, count: 10 }
    ];
    const SPELLING_SECS = 30;

    const MODES = [
        { id: 'pub', name: 'Pub Quiz', icon: '🍺', blurb: 'The classic: three rounds of mixed subjects, pictures and quick fire. Most points wins. About 8 minutes.' },
        { id: 'chase', name: 'The Chase', icon: '🕵️', blurb: 'Build your cash, pick your offer, then outrun the Chaser down the board. Survivors team up for a final chase. About 10 minutes.' },
        { id: 'millionaire', name: 'Millionaire', icon: '💰', blurb: 'Fifteen questions to £1,000,000 with 50:50, Ask the Audience and Phone a Friend. Everyone climbs their own ladder at once.' }
    ];
    const modeById = Object.fromEntries(MODES.map(m => [m.id, m]));
    const DEFAULT_MODE = 'pub';

    // The Chase: a cash builder, a head-to-head down a board with the Chaser, then a team final chase.
    const CHASE = {
        cashQuestions: 5, cashSecs: 10, cashPerAnswer: 1000,
        steps: 7, offerSecs: 15, headSecs: 12, chaserAccuracy: 0.85,
        finalQuestions: 10, finalSecs: 8, finalChaserAccuracy: 0.7
    };
    // Millionaire: the prize for answering question N, and the question numbers (1-based) that bank their prize.
    const LADDER = [100, 200, 300, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 125000, 250000, 500000, 1000000];
    const SAFE_AFTER = [5, 10];
    const LIFELINES = ['fifty', 'audience', 'phone'];
    const BASE_POINTS = { standard: 100, picture: 150, quickfire: 50, spell: 150 };

    // ── Seeded randomness (so the weekly rotation is the same for everybody, offline too) ──────────────
    function hashSeed(text) {
        let h = 2166136261;
        for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 16777619); }
        return h >>> 0;
    }
    function mulberry32(seed) {
        let a = seed >>> 0;
        return function () {
            a = (a + 0x6D2B79F5) >>> 0;
            let t = a;
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
    }
    function shuffle(list, rng) {
        const a = list.slice();
        for (let i = a.length - 1; i > 0; i--) { const j = Math.floor((rng || Math.random)() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
        return a;
    }

    /** ISO week id like "2026-W46"; the weekly question set rolls over every Monday (UTC). */
    function weekId(date) {
        const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
        const day = d.getUTCDay() || 7;
        d.setUTCDate(d.getUTCDate() + 4 - day);
        const yearStart = Date.UTC(d.getUTCFullYear(), 0, 1);
        const week = Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
        return d.getUTCFullYear() + '-W' + String(week).padStart(2, '0');
    }

    // ── Question pool ───────────────────────────────────────────────────────────────────────────────────
    /** Maths questions are generated, seeded by the week, so there are always fresh ones (works offline). */
    function mathsQuestions(rng, count) {
        const out = [], seen = new Set();
        const ri = (lo, hi) => lo + Math.floor(rng() * (hi - lo + 1));
        const make = [
            () => { const a = ri(12, 99), b = ri(12, 99); return [`${a} + ${b} = ?`, a + b]; },
            () => { const a = ri(50, 150), b = ri(11, 49); return [`${a} − ${b} = ?`, a - b]; },
            () => { const a = ri(3, 12), b = ri(3, 12); return [`${a} × ${b} = ?`, a * b]; },
            () => { const b = ri(3, 12), r = ri(3, 12); return [`${b * r} ÷ ${b} = ?`, r]; },
            () => { const p = [10, 20, 25, 50][ri(0, 3)], n = ri(2, 20) * 20; return [`What is ${p}% of ${n}?`, n * p / 100]; },
            () => { const a = ri(2, 9); return [`What is ${a} squared?`, a * a]; },
            () => { const a = ri(2, 6), b = ri(2, 9), c = ri(2, 9); return [`${a} × ${b} + ${c} = ?`, a * b + c]; },
            () => { const r = ri(4, 15); return [`What is the square root of ${r * r}?`, r]; }
        ];
        let guard = 0;
        while (out.length < count && guard++ < 500) {
            const [q, answer] = make[ri(0, make.length - 1)]();
            if (seen.has(q)) continue;
            seen.add(q);
            const wrong = new Set();
            let spread = Math.max(2, Math.round(Math.abs(answer) * 0.15));
            let tries = 0;
            while (wrong.size < 3 && tries++ < 100) {
                const w = answer + (ri(1, spread) * (rng() < 0.5 ? -1 : 1));
                if (w !== answer && w >= 0) wrong.add(w);
                if (tries % 10 === 0) spread += 2;
            }
            out.push([q, String(answer), ...Array.from(wrong).map(String)]);
        }
        return out;
    }

    /**
     * Merges every source into one pool.
     *   bank   { parts: [{subjects, pictures, words}] }   the questions shipped with the game
     *   weekly { week, subjects, ... } | null              the auto-generated weekly set (weekly.json)
     * Weekly questions are marked so they get picked more often.
     */
    function buildPool(bank, weekly, now) {
        const week = weekId(now || new Date());
        const pool = { week, subjects: {}, pictures: { places: [], celebs: [] }, words: [], weeklyIds: new Set() };
        for (const s of SUBJECTS) pool.subjects[s.id] = [];
        for (const part of (bank && bank.parts) || []) {
            for (const [id, list] of Object.entries(part.subjects || {})) if (pool.subjects[id]) pool.subjects[id].push(...list);
            for (const [id, list] of Object.entries(part.pictures || {})) if (pool.pictures[id]) pool.pictures[id].push(...list);
            if (part.words) pool.words.push(...part.words);
        }
        if (weekly && weekly.subjects) {
            for (const [id, list] of Object.entries(weekly.subjects)) {
                if (!pool.subjects[id] || !Array.isArray(list)) continue;
                for (const q of list) {
                    if (Array.isArray(q) && q.length === 5 && q.every(x => typeof x === 'string' && x) && new Set(q.slice(1)).size === 4) {
                        pool.subjects[id].push(q);
                        pool.weeklyIds.add(q[0]);
                    }
                }
            }
        }
        const rng = mulberry32(hashSeed('quizy-' + week));
        pool.subjects.maths = mathsQuestions(rng, QUESTIONS_PER_SUBJECT);
        // This week's 20 spelling words rotate through the whole word list.
        pool.weekWords = shuffle(pool.words, rng).slice(0, QUESTIONS_PER_SUBJECT);
        return pool;
    }

    // ── Quiz building ───────────────────────────────────────────────────────────────────────────────────
    function mcQuestion(raw, subject, kind, secs, rng) {
        const options = shuffle(raw.slice(1), rng);
        return { type: 'mc', kind, subject, prompt: raw[0], options, answer: options.indexOf(raw[1]), secs };
    }
    function spellQuestion(raw) {
        return { type: 'spell', kind: 'standard', subject: 'spelling', prompt: 'Listen carefully, then spell the word.', word: raw[0], clue: raw[1] || '', secs: SPELLING_SECS };
    }
    function pictureQuestion(raw, group, rng) {
        const options = shuffle(raw.slice(1), rng);
        return {
            type: 'pic', kind: 'picture', subject: group, wiki: raw[0], secs: ROUNDS[1].secs,
            prompt: group === 'places' ? 'Which place is this?' : 'Who is this?', options, answer: options.indexOf(raw[1])
        };
    }

    /** Round-robins through the chosen subjects (more popular ones come up more) without repeating a question. */
    function drawSubjects(pool, subjectIds, count, rng, used, allowSpelling, build) {
        const decks = {};
        const out = [];
        const order = shuffle(subjectIds, rng);
        let i = 0, misses = 0;
        while (out.length < count && misses < order.length * 2) {
            const id = order[i++ % order.length];
            if (id === 'spelling' && !allowSpelling) { misses++; continue; }
            if (!decks[id]) {
                const src = id === 'spelling' ? pool.weekWords : pool.subjects[id];
                const weekly = id === 'spelling' ? [] : src.filter(q => pool.weeklyIds.has(q[0]));
                decks[id] = shuffle(src.concat(weekly), rng);
            }
            let raw = null;
            while (decks[id].length) {
                const next = decks[id].pop();
                if (!used.has(next[0])) { raw = next; break; }
            }
            if (!raw) { misses++; continue; }
            used.add(raw[0]);
            misses = 0;
            out.push(build(raw, id));
        }
        return out;
    }

    /**
     * @param picks  array of subject-id arrays, one per player
     * @param opts   { rng, picture: include the picture round (needs a connection for the photos) }
     * @returns [{ ...round, questions: [...] }]
     */
    function buildQuiz(pool, picks, opts) {
        opts = opts || {};
        const rng = opts.rng || Math.random;
        const subjectIds = [].concat(...picks).filter(id => subjectById[id]);
        const used = new Set();
        const rounds = [];

        const mixed = drawSubjects(pool, subjectIds, ROUNDS[0].count, rng, used, true,
            (raw, id) => id === 'spelling' ? spellQuestion(raw) : mcQuestion(raw, id, 'standard', ROUNDS[0].secs, rng));
        rounds.push(Object.assign({}, ROUNDS[0], { questions: mixed }));

        if (opts.picture !== false) {
            const places = shuffle(pool.pictures.places, rng).slice(0, ROUNDS[1].count / 2).map(r => pictureQuestion(r, 'places', rng));
            const celebs = shuffle(pool.pictures.celebs, rng).slice(0, ROUNDS[1].count / 2).map(r => pictureQuestion(r, 'celebs', rng));
            const pics = shuffle(places.concat(celebs), rng);
            if (pics.length) rounds.push(Object.assign({}, ROUNDS[1], { questions: pics }));
        }

        const quickIds = subjectIds.filter(id => id !== 'spelling');
        const quick = drawSubjects(pool, quickIds.length ? quickIds : ['general'], ROUNDS[2].count, rng, used, false,
            (raw, id) => mcQuestion(raw, id, 'quickfire', ROUNDS[2].secs, rng));
        rounds.push(Object.assign({}, ROUNDS[2], { questions: quick }));
        return rounds;
    }

    // ── Modes: endless draws ────────────────────────────────────────────────────────────────────────────
    /**
     * Multiple choice questions from the players' subjects, drawn one at a time (Chase and Millionaire don't know up
     * front how many they need). `frac` 0..1 asks for an easier or harder question: each subject lists its questions
     * roughly easiest first, so the position in the list stands in for difficulty. Spelling is never drawn.
     */
    function makeDeck(pool, picks, rng) {
        rng = rng || Math.random;
        const ids = Array.from(new Set([].concat(...picks).filter(id => subjectById[id] && id !== 'spelling')));
        const items = [];
        for (const id of ids.length ? ids : ['general']) {
            const list = pool.subjects[id] || [];
            list.forEach((raw, i) => items.push({ raw, id, frac: id === 'maths' || pool.weeklyIds.has(raw[0]) ? rng() : i / Math.max(1, list.length - 1) }));
        }
        let used = new Set();
        return {
            draw(o) {
                o = o || {};
                let cand = items.filter(x => !used.has(x.raw[0]));
                if (!cand.length) { used = new Set(); cand = items; }
                if (typeof o.frac === 'number') {
                    const near = cand.filter(x => Math.abs(x.frac - o.frac) <= 0.2);
                    cand = near.length >= 3 ? near : cand.slice().sort((a, b) => Math.abs(a.frac - o.frac) - Math.abs(b.frac - o.frac)).slice(0, 5);
                }
                const x = cand[Math.floor(rng() * cand.length)];
                used.add(x.raw[0]);
                return mcQuestion(x.raw, x.id, o.kind || 'standard', o.secs || ROUNDS[0].secs, rng);
            }
        };
    }

    // ── The Chase ───────────────────────────────────────────────────────────────────────────────────────
    const roundTo = (n, unit) => Math.round(n / unit) * unit;

    /** The three offers after the cash builder: a bigger prize starting nearer the Chaser, your cash, or a smaller safer one. */
    function chaseOffers(cash) {
        return [
            { id: 'high', label: 'Higher offer', money: roundTo(cash * 3, 100), start: 1 },
            { id: 'mid', label: 'Your cash', money: cash, start: 2 },
            { id: 'low', label: 'Lower offer', money: roundTo(cash / 3, 100), start: 3 }
        ];
    }

    /** One question of the head-to-head. Home is reached by getting `steps` down the board; the Chaser starts at the top. */
    function chaseStep(state, playerRight, chaserRight) {
        const pos = state.pos + (playerRight ? 1 : 0);
        const chaser = state.chaser + (chaserRight ? 1 : 0);
        const outcome = pos >= state.steps ? 'home' : chaser >= pos ? 'caught' : 'on';
        return { pos, chaser, steps: state.steps, outcome };
    }

    /** The team wins the final chase only if it holds more correct answers than the Chaser. */
    function finalChaseWon(team, chaser) { return team > chaser; }

    // ── Millionaire ─────────────────────────────────────────────────────────────────────────────────────
    /** What a player takes home: the prize of their last correct answer, or the last safe haven if they got one wrong. */
    function winnings(correct, wrong) {
        const n = Math.max(0, Math.min(correct, LADDER.length));
        if (!wrong) return n ? LADDER[n - 1] : 0;
        const safe = SAFE_AFTER.filter(q => n >= q).pop();
        return safe ? LADDER[safe - 1] : 0;
    }

    /** How likely a friend or the audience is to know the answer at question `level` (0-based). */
    const lifelineAccuracy = level => Math.max(0.4, 0.95 - level * 0.04);

    function fiftyFifty(answer, count, rng) {
        const wrong = shuffle(Array.from({ length: count }, (_, i) => i).filter(i => i !== answer), rng);
        return wrong.slice(0, 2).sort((a, b) => a - b);
    }

    /** Percentages per option (adding up to 100); options in `hidden` get 0. */
    function audienceVote(answer, count, level, hidden, rng) {
        rng = rng || Math.random;
        const open = Array.from({ length: count }, (_, i) => i).filter(i => !(hidden || []).includes(i));
        const weights = open.map(i => i === answer ? lifelineAccuracy(level) * 100 + rng() * 15 : rng() * 30 + 2);
        const total = weights.reduce((a, b) => a + b, 0);
        const out = new Array(count).fill(0);
        let given = 0;
        open.forEach((i, k) => { out[i] = k === open.length - 1 ? 0 : Math.round(weights[k] / total * 100); given += out[i]; });
        out[open[open.length - 1]] = Math.max(0, 100 - given);
        return out;
    }

    function phoneFriend(answer, count, level, hidden, rng) {
        rng = rng || Math.random;
        const open = Array.from({ length: count }, (_, i) => i).filter(i => !(hidden || []).includes(i));
        const knows = rng() < lifelineAccuracy(level);
        const wrong = open.filter(i => i !== answer);
        const guess = knows || !wrong.length ? answer : wrong[Math.floor(rng() * wrong.length)];
        return { guess, confidence: knows ? 70 + Math.floor(rng() * 30) : 35 + Math.floor(rng() * 25) };
    }

    /** What a player's screen needs for a question: never the answer index (spelling words are read aloud, so they are included). */
    function publicQuestion(q) {
        const out = { type: q.type, kind: q.kind, subject: q.subject, prompt: q.prompt, secs: q.secs };
        if (q.options) out.options = q.options;
        if (q.wiki) out.wiki = q.wiki;
        if (q.type === 'spell') { out.word = q.word; out.clue = q.clue; out.letters = q.word.length; }
        return out;
    }

    // ── Answers and scoring ─────────────────────────────────────────────────────────────────────────────
    /** Spelling must be exact apart from capital letters and surrounding spaces. */
    function checkSpelling(input, word) {
        return String(input == null ? '' : input).trim().toLowerCase() === String(word).trim().toLowerCase();
    }

    function isCorrect(q, answer) {
        if (q.type === 'spell') return checkSpelling(answer, q.word);
        return Number.isInteger(answer) && answer === q.answer;
    }

    /** `remaining` is 0..1: how much of the time was left when the player answered. Wrong answers score nothing. */
    function points(q, ok, remaining, streak) {
        if (!ok) return 0;
        const base = BASE_POINTS[q.type === 'spell' ? 'spell' : q.kind];
        const speed = Math.round(base * 0.5 * Math.max(0, Math.min(1, remaining)));
        const streakBonus = q.kind === 'quickfire' ? Math.min(streak, 10) * 5 : Math.min(streak, 5) * 10;
        return base + speed + streakBonus;
    }

    /** Shared places for ties; sorted best first. */
    function ranking(players) {
        const rows = players.slice().sort((a, b) => b.score - a.score || b.correct - a.correct || a.name.localeCompare(b.name));
        let place = 0, last = null;
        rows.forEach((r, i) => { const key = r.score + ':' + r.correct; if (key !== last) { place = i + 1; last = key; } r.place = place; });
        return rows;
    }

    function validPicks(list) {
        return Array.isArray(list) && list.length >= MIN_SUBJECTS && list.length <= MAX_SUBJECTS &&
            new Set(list).size === list.length && list.every(id => !!subjectById[id]);
    }

    const api = {
        MODES, modeById, DEFAULT_MODE, CHASE, LADDER, SAFE_AFTER, LIFELINES,
        makeDeck, chaseOffers, chaseStep, finalChaseWon, winnings, lifelineAccuracy, fiftyFifty, audienceVote, phoneFriend,
        SUBJECTS, subjectById, ROUNDS, MIN_SUBJECTS, MAX_SUBJECTS, MAX_PLAYERS, QUESTIONS_PER_SUBJECT,
        hashSeed, mulberry32, shuffle, weekId, mathsQuestions, buildPool, buildQuiz, publicQuestion,
        checkSpelling, isCorrect, points, ranking, validPicks
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.QuizyEngine = api;
})(typeof window !== 'undefined' ? window : globalThis);
