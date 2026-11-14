/* Snake Plus achievements: definitions + pure evaluation (no DOM, no network).
 * Hidden achievements keep their name/description out of every list shown to the player
 * (game UI, Game OS app, published template) until they are unlocked. */
(function (root) {
    const POWERUPS = ['speed', 'lockdown', 'colour', 'tp', 'destruction'];

    const DEFS = [
        { id: 'first_game', name: 'Slither In', description: 'Start your first game.' },
        { id: 'first_bite', name: 'First Bite', description: 'Eat your first food.' },
        { id: 'growing_up', name: 'Growing Up', description: 'Reach 100 points in a single game.' },
        { id: 'long_boi', name: 'Long Boi', description: 'Reach 250 points in a single game.' },
        { id: 'winner', name: 'Last Snake Standing', description: 'Win a game against other snakes.' },
        { id: 'classic_200', name: 'Classic Cruiser', description: 'Score 200 points in Classic 1P.' },
        { id: 'rush_hour', name: 'Rush Hour', description: 'Score 150 points in Rush.' },
        { id: 'first_to', name: 'First To The Finish', description: 'Win a First To game.' },
        { id: 'speed_demon', name: 'Speed Demon', description: 'Grab a speed power-up.' },
        { id: 'lockdown', name: 'Locked Down', description: 'Trigger a lockdown.' },
        { id: 'chop_chop', name: 'Chop Chop', description: 'Chop a rival\'s tail with a destruction power-up.' },
        { id: 'power_user', name: 'Power User', description: 'Collect every kind of power-up.' },
        { id: 'sweet_tooth', name: 'Sweet Tooth', description: 'Eat 100 food in total.' },
        { id: 'marathon', name: 'Marathon Slitherer', description: 'Play 10 games.' },
        { id: 'bot_buster', name: 'Bot Buster', description: 'Beat a HARD bot in a head-to-head game.' },
        { id: 'better_together', name: 'Better Together', description: 'Play a game online with a Game OS friend.' },
        { id: 'online_champion', name: 'Online Champion', description: 'Win a game online against a Game OS friend.' },
        { id: 'kaboom', name: 'Kaboom', description: 'You ate the bomb. Of course you did.', hidden: true },
        { id: 'perfect_start', name: 'Instant Regret', description: 'Crash within a second of starting.', hidden: true }
    ];

    const byId = Object.fromEntries(DEFS.map(d => [d.id, d]));

    /**
     * Events:
     *   start {online}
     *   item  {item}                      – a power-up / food was collected
     *   chop                              – a destruction chop landed
     *   end   {mode, score, won, online, rivals:[type], ticks, died}
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
        if (type === 'item') {
            if (ctx.item === 'food') {
                add('first_bite');
                if ((stats.foodEaten || 0) + 1 >= 100) add('sweet_tooth');
            }
            if (ctx.item === 'speed') add('speed_demon');
            if (ctx.item === 'lockdown') add('lockdown');
            if (ctx.item === 'bomb') add('kaboom');
            if (POWERUPS.includes(ctx.item)) {
                const seen = new Set((stats.items || []).concat(ctx.item));
                if (POWERUPS.every(p => seen.has(p))) add('power_user');
            }
        }
        if (type === 'chop') add('chop_chop');
        if (type === 'end') {
            const score = ctx.score || 0;
            const rivals = ctx.rivals || [];
            if (score >= 100) add('growing_up');
            if (score >= 250) add('long_boi');
            if (ctx.mode === 'classic' && score >= 200) add('classic_200');
            if (ctx.mode === 'rush' && score >= 150) add('rush_hour');
            if ((stats.games || 0) + 1 >= 10) add('marathon');
            if (ctx.died && ctx.ticks < 60) add('perfect_start');
            if (ctx.won && rivals.length) {
                add('winner');
                if (ctx.mode === 'firstTo') add('first_to');
                if (rivals.length === 1 && rivals[0] === 'hard') add('bot_buster');
                if (ctx.online) add('online_champion');
            }
        }
        return out;
    }

    /** What the player may see for an achievement right now. */
    function present(def, unlockedAt) {
        if (def.hidden && !unlockedAt) return { id: def.id, name: 'Hidden achievement', description: 'Keep slithering to discover this one.', hidden: true, unlockedAt: '' };
        return { id: def.id, name: def.name, description: def.description, hidden: !!def.hidden, unlockedAt: unlockedAt || '' };
    }

    const api = { DEFS, POWERUPS, byId, evaluate, present };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    else root.SPAchievements = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
