/* Quizy achievements: definitions + pure evaluation (no DOM, no network).
 * Hidden achievements keep their name/description out of every list shown to the player
 * (game UI, Game OS app, published template) until they are unlocked. */
(function (root) {
    const DEFS = [
        { id: 'first_game', name: 'Quiz Time', description: 'Play your first game of Quizy.' },
        { id: 'warm_up', name: 'Warming Up', description: 'Answer 5 questions correctly in a row.' },
        { id: 'on_fire', name: 'On Fire', description: 'Answer 10 questions correctly in a row.' },
        { id: 'brainiac', name: 'Brainiac', description: 'Answer 20 questions correctly in one game.' },
        { id: 'high_scorer', name: 'High Scorer', description: 'Score 2000 points in a single game.' },
        { id: 'winner', name: 'Quiz Champion', description: 'Win a game against other players or bots.' },
        { id: 'spelling_bee', name: 'Spelling Bee', description: 'Spell 3 words correctly in one game.' },
        { id: 'picture_perfect', name: 'Picture Perfect', description: 'Get every picture round question right.' },
        { id: 'quick_draw', name: 'Quick Draw', description: 'Get 8 or more Quick Fire questions right in one game.' },
        { id: 'well_rounded', name: 'Well Rounded', description: 'Play a game with 5 subjects.' },
        { id: 'polymath', name: 'Polymath', description: 'Play every subject at least once.' },
        { id: 'marathon', name: 'Quiz Addict', description: 'Play 10 games.' },
        { id: 'better_together', name: 'Better Together', description: 'Play a game online with a Game OS friend.' },
        { id: 'online_champion', name: 'Online Champion', description: 'Win a game online against a Game OS friend.' },
        { id: 'escaped', name: 'Outrun the Chaser', description: 'Escape the Chaser in Chase mode.' },
        { id: 'chase_champ', name: 'Chase Champion', description: 'Win a final chase.' },
        { id: 'big_money', name: 'Big Money', description: 'Take home £32,000 or more in Millionaire.' },
        { id: 'millionaire', name: 'Millionaire!', description: 'Win £1,000,000 in Millionaire.' },
        { id: 'all_modes', name: 'Mode Master', description: 'Play Pub, Chase and Millionaire.' },
        { id: 'meet_world', name: 'Meet the World', description: 'Play a public online match with players who are not your friends.' },
        { id: 'flawless', name: 'Flawless', description: 'Answer every single question correctly.', hidden: true },
        { id: 'better_luck', name: 'Better Luck Next Time', description: 'Finish a game without a single correct answer.', hidden: true }
    ];

    const byId = Object.fromEntries(DEFS.map(d => [d.id, d]));

    /**
     * Events:
     *   start {online}
     *   end   {score, correct, total, bestStreak, spelled, picCorrect, picTotal, quickCorrect, subjects:[ids], allSubjects:[ids],
     *          won, online, rivals}
     * Returns newly earned ids (already-earned ids are never repeated).
     */
    function evaluate(type, ctx, state) {
        ctx = ctx || {};
        const have = state.achievements || {};
        const stats = state.stats || {};
        const out = [];
        const add = id => { if (!have[id] && !out.includes(id)) out.push(id); };

        if (type === 'start') {
            add('first_game');
            if (ctx.online) add('better_together');
        }
        if (type === 'end') {
            if ((ctx.bestStreak || 0) >= 5) add('warm_up');
            if ((ctx.bestStreak || 0) >= 10) add('on_fire');
            if ((ctx.correct || 0) >= 20) add('brainiac');
            if ((ctx.score || 0) >= 2000) add('high_scorer');
            if ((ctx.spelled || 0) >= 3) add('spelling_bee');
            if ((ctx.picTotal || 0) > 0 && ctx.picCorrect === ctx.picTotal) add('picture_perfect');
            if ((ctx.quickCorrect || 0) >= 8) add('quick_draw');
            if ((ctx.subjects || []).length >= 5) add('well_rounded');
            if ((stats.games || 0) + 1 >= 10) add('marathon');
            const seen = new Set((stats.subjects || []).concat(ctx.subjects || []));
            if ((ctx.allSubjects || []).length && ctx.allSubjects.every(id => seen.has(id))) add('polymath');
            if (ctx.won && (ctx.rivals || 0) > 0) {
                add('winner');
                if (ctx.online) add('online_champion');
            }
            if (ctx.escaped) add('escaped');
            if (ctx.finalWon) add('chase_champ');
            if (ctx.mode === 'millionaire' && (ctx.money || 0) >= 32000) add('big_money');
            if (ctx.millionaire) add('millionaire');
            const modes = new Set((stats.modes || []).concat(ctx.mode ? [ctx.mode] : []));
            if (['pub', 'chase', 'millionaire'].every(m => modes.has(m))) add('all_modes');
            if (ctx.publicMatch && ctx.online) add('meet_world');
            if ((ctx.total || 0) > 0 && ctx.correct === ctx.total) add('flawless');
            if ((ctx.total || 0) > 0 && !ctx.correct) add('better_luck');
        }
        return out;
    }

    /** What the player may see for an achievement right now. */
    function present(def, unlockedAt) {
        if (def.hidden && !unlockedAt) return { id: def.id, name: 'Hidden achievement', description: 'Keep quizzing to discover this one.', hidden: true, unlockedAt: '' };
        return { id: def.id, name: def.name, description: def.description, hidden: !!def.hidden, unlockedAt: unlockedAt || '' };
    }

    const api = { DEFS, byId, evaluate, present };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.QZAchievements = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
