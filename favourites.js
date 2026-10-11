// Favourites – stored per user in localStorage (works in demo and GitHub mode).
function _favKey(username) { return `gameOS_favourites_${username.toLowerCase()}`; }
function getFavourites(username) {
    try { return JSON.parse(localStorage.getItem(_favKey(username))) || []; } catch (_) { return []; }
}
function _sameGame(a, platform, title) {
    return a.platform === platform && (a.title || '').toLowerCase() === (title || '').toLowerCase();
}
function isFavourite(username, platform, title) {
    return getFavourites(username).some(f => _sameGame(f, platform, title));
}
/** Toggle a favourite; returns true if the game is now a favourite. */
function toggleFavourite(username, game, platform) {
    const title = game.Title || game.game_name || game.title || '';
    let favs = getFavourites(username);
    const now = !favs.some(f => _sameGame(f, platform, title));
    if (now) {
        favs.push({
            platform, title,
            titleId: game.TitleID || game.title_id || game.titleid || game.titleId || game.id || null,
            coverUrl: game.coverUrl || (typeof getGameCoverUrl === 'function' ? getGameCoverUrl(game) : null) || undefined,
            addedAt: new Date().toISOString()
        });
    } else {
        favs = favs.filter(f => !_sameGame(f, platform, title));
    }
    localStorage.setItem(_favKey(username), JSON.stringify(favs));
    return now;
}
