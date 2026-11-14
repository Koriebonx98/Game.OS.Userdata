/* Digital Abyss achievements: definitions + pure evaluation (no DOM, no network).
 * Hidden achievements keep their name/description out of every list shown to the player
 * (game UI, Game OS app, published template) until they are unlocked. */
(function (root) {
    const TRAPS = { 1: 'gallery', 2: 'mainlab', 3: 'building 3', 4: 'server room alpha', 5: 'vault room 1' };

    const DEFS = [
        { id: 'first_steps', name: 'First Steps', description: 'Start your first investigation.' },
        { id: 'case_closed', name: 'Case Closed', description: 'Solve a case.' },
        { id: 'perfect_run', name: 'Perfect Run', description: 'Solve a case without a single mistake.' },
        { id: 'outta_luck', name: 'Outta Luck', description: 'Run out of time or lose all your lives.' },
        { id: 'thorough', name: 'Leave No Stone Unturned', description: 'Read every message, email, note and voicemail in a case, then solve it.' },
        { id: 'on_the_edge', name: 'On the Edge', description: 'Solve a case with only one life left.' },
        { id: 'speed_sleuth', name: 'Speed Sleuth', description: 'Solve a case in under 20 minutes.' },
        { id: 'perfect_trio', name: 'Flawless Streak', description: 'Earn a perfect run on three different cases.' },
        { id: 'all_cases', name: 'Master Detective', description: 'Solve all five cases.' },
        { id: 'last_gasp', name: 'Last Gasp', description: 'Solve a case with less than a minute on the clock.', hidden: true },
        { id: 'trap_1', name: 'Framed by the Gallery', description: 'You trusted the gallery\'s glittering lie.', hidden: true },
        { id: 'trap_2', name: 'Contaminated Judgement', description: 'The main lab was never where the truth lay.', hidden: true },
        { id: 'trap_3', name: 'Temporal Echo', description: 'Building 3 was only a memory of a place.', hidden: true },
        { id: 'trap_4', name: 'Honeypot', description: 'You walked straight into Server Room Alpha.', hidden: true },
        { id: 'trap_5', name: 'Vault Vanity', description: 'Vault 1 was only ever a diversion.', hidden: true }
    ];

    const byId = Object.fromEntries(DEFS.map(d => [d.id, d]));

    /** Events: start | wrong {scenarioId, location} | solved {...} | lost {reason}. Returns newly earned ids. */
    function evaluate(type, ctx, state) {
        ctx = ctx || {};
        const have = state.achievements || {};
        const stats = state.stats || {};
        const out = [];
        const add = id => { if (!have[id] && !out.includes(id)) out.push(id); };

        if (type === 'start') add('first_steps');
        if (type === 'wrong' && TRAPS[ctx.scenarioId] && String(ctx.location || '').toLowerCase() === TRAPS[ctx.scenarioId]) {
            add('trap_' + ctx.scenarioId);
        }
        if (type === 'lost') add('outta_luck');
        if (type === 'solved') {
            const solved = new Set((stats.solved || []).concat(ctx.scenarioId));
            const perfect = new Set((stats.perfectCases || []).concat(ctx.wrongAttempts === 0 ? [ctx.scenarioId] : []));
            add('case_closed');
            if (ctx.wrongAttempts === 0) add('perfect_run');
            if (ctx.allViewed) add('thorough');
            if (ctx.lives === 1) add('on_the_edge');
            if (ctx.elapsedMs < 20 * 60 * 1000) add('speed_sleuth');
            if (ctx.remainingMs < 60 * 1000) add('last_gasp');
            if (perfect.size >= 3) add('perfect_trio');
            if (solved.size >= 5) add('all_cases');
        }
        return out;
    }

    /** What the player may see for an achievement right now. */
    function present(def, unlockedAt) {
        if (def.hidden && !unlockedAt) return { id: def.id, name: 'Hidden achievement', description: 'Keep investigating to discover this one.', hidden: true, unlockedAt: '' };
        return { id: def.id, name: def.name, description: def.description, hidden: !!def.hidden, unlockedAt: unlockedAt || '' };
    }

    const api = { DEFS, TRAPS, byId, evaluate, present };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.DAAchievements = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
