(async function () {
    'use strict';
    const game = { Title: 'Starfall Trail', TitleID: 'starfall-trail' };
    const stage = document.getElementById('stage');
    const message = text => {
        stage.replaceChildren();
        const gate = document.createElement('div');
        gate.id = 'gate'; gate.setAttribute('role', 'status'); gate.textContent = text;
        stage.appendChild(gate);
        return gate;
    };
    try {
        modeReady = initializeMode();
        await modeReady;
        const user = getCurrentUser();
        if (!user) {
            const gate = message('Sign in to play Starfall Trail and save your progress. ');
            const link = document.createElement('a');
            link.textContent = 'Sign in';
            link.href = 'login.html?next=' + encodeURIComponent('starfall-trail.html' + location.search);
            gate.appendChild(link);
            return;
        }
        const find = lib => (lib || []).find(g => g.platform === 'PC' && String(g.title || '').toLowerCase() === 'starfall trail');
        const load = () => MODE === 'demo' ? getDemoGameLibrary(user.username) : getGameLibraryGitHub(user.username);
        const entry = async () => {
            const lib = await load();
            return find(lib);
        };
        async function claim() {
            const licenseKey = await GameOSDRM.makeKey(game.TitleID, user.username);
            const gameEntry = { platform:'PC', title:game.Title, titleId:game.TitleID,
                coverUrl:new URL('games/starfall-trail/cover.svg', location.href).href,
                achievementsUrl:new URL('games/starfall-trail/achievements.json', location.href).href,
                licenseKey, addedAt:new Date().toISOString() };
            if (MODE === 'demo') {
                const lib = await load();
                if (!find(lib)) { lib.push(gameEntry); saveDemoGameLibrary(user.username, lib); }
            } else {
                const path = `accounts/${user.username.toLowerCase()}/games.json`;
                for (let attempt = 0; ; attempt++) {
                    const file = await githubRead(path);
                    const lib = file && Array.isArray(file.content) ? file.content : [];
                    if (find(lib)) break;
                    try {
                        await githubWrite(path, lib.concat(gameEntry), 'Add game: Starfall Trail (PC)', file ? file.sha : undefined);
                        _libCacheSet(user.username, lib.concat(gameEntry));
                        break;
                    } catch (e) { if (attempt >= 2) throw e; }
                }
            }
            GameOSDRM.setLocal(game.TitleID, user.username, licenseKey);
        }
        async function launch() {
            if (window.GameOSLAN) await GameOSLAN.ready;
            const frame = document.createElement('iframe');
            frame.id = 'frame'; frame.title = game.Title;
            frame.setAttribute('sandbox', 'allow-scripts allow-forms allow-pointer-lock allow-popups allow-modals');
            frame.setAttribute('allow', 'fullscreen; gamepad; autoplay');
            frame.setAttribute('allowfullscreen', '');
            stage.replaceChildren(frame);
            const q = new URLSearchParams(location.search);
            window._gosBridge = GameOSBridge.attach({ frame, game,
                definitionsUrl:'games/starfall-trail/achievements.json',
                launch:q.get('join') && q.get('room') ? { join:q.get('join'), room:q.get('room') } : null });
            frame.src = 'games/starfall-trail/index.html';
        }
        let owned, gameEntry;
        try {
            gameEntry = await entry();
        } catch (e) {
            const key = GameOSDRM.getLocal(game.TitleID, user.username);
            if (key && await GameOSDRM.verify(key, game.TitleID, user.username)) owned = true;
            else throw e;
        }
        if (gameEntry) {
            const key = gameEntry.licenseKey || await GameOSDRM.makeKey(game.TitleID, user.username);
            if (!await GameOSDRM.verify(key, game.TitleID, user.username)) throw new Error('Invalid game licence.');
            GameOSDRM.setLocal(game.TitleID, user.username, key);
            owned = true;
        }
        if (owned) { await launch(); return; }
        const gate = message('Claim Starfall Trail for free to add it to your Game OS library. ');
        const button = document.createElement('button');
        button.textContent = 'Claim and play';
        gate.appendChild(button);
        button.addEventListener('click', async () => {
            button.disabled = true;
            try { await claim(); await launch(); }
            catch (e) { message('Could not claim Starfall Trail: ' + e.message); }
        });
    } catch (e) { message('Could not start Starfall Trail: ' + e.message); }
})();
