/* Quizy leaderboard logic (pure, shared by the game and its tests).
 * One shared file holds every player's best numbers: { players: { <usernameLower>: { name, wins, bestScore, ... } } }. */
(function (root) {
    'use strict';
    const METRICS = [
        { key: 'wins', label: 'Most wins' },
        { key: 'bestScore', label: 'Best score' },
        { key: 'onlineWins', label: 'Online wins' },
        { key: 'correct', label: 'Correct answers' },
        { key: 'bestStreak', label: 'Longest streak' },
        { key: 'spelled', label: 'Words spelled' },
        { key: 'chaseWins', label: 'Chase finals won' },
        { key: 'bestWinnings', label: 'Best Millionaire winnings' }
    ];
    const MAX_PLAYERS = 500;

    /** Folds one player's stats into the shared board. Returns the new board, or undefined when nothing changed. */
    function upsert(board, username, stats, now) {
        const players = Object.assign({}, board && board.players);
        const key = String(username).toLowerCase();
        const prev = players[key] || {};
        const next = { name: username };
        let changed = !players[key] || prev.name !== username;
        for (const m of METRICS) {
            next[m.key] = Math.max(prev[m.key] || 0, stats[m.key] || 0);
            if (next[m.key] !== (prev[m.key] || 0)) changed = true;
        }
        if (!changed) return undefined;
        next.at = now;
        players[key] = next;
        const keys = Object.keys(players);
        if (keys.length > MAX_PLAYERS) {
            keys.sort((a, b) => (players[b].wins || 0) - (players[a].wins || 0) || String(players[b].at).localeCompare(String(players[a].at)));
            for (const drop of keys.slice(MAX_PLAYERS)) if (drop !== key) delete players[drop];
        }
        return { v: 1, players };
    }

    /** Ranked rows for one metric; `only` (a Set of lowercase names) limits the board, e.g. to friends. */
    function rank(board, metric, only) {
        const rows = Object.entries((board && board.players) || {})
            .filter(([key, p]) => (!only || only.has(key)) && (p[metric] || 0) > 0)
            .map(([key, p]) => ({ key, name: p.name || key, value: p[metric] || 0 }));
        rows.sort((a, b) => b.value - a.value || a.name.localeCompare(b.name));
        let place = 0, last = null;
        rows.forEach((r, i) => { if (r.value !== last) { place = i + 1; last = r.value; } r.place = place; });
        return rows;
    }

    const api = { METRICS, upsert, rank };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.QZLeaderboard = api;
})(typeof window !== 'undefined' ? window : globalThis);
