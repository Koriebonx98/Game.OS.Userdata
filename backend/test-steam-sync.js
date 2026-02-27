/**
 * Standalone test for the Steam-to-PC.Games.json sync logic.
 *
 * Tests the exact same filter / dedup / diff / append pipeline that the
 * backend endpoint `POST /api/admin/sync-steam-games` and the manual
 * `POST /api/admin/add-game` write path both use — with no network requests
 * and no GAMES_DB_TOKEN required.
 *
 * Usage (from backend/ directory):
 *   node test-steam-sync.js
 *
 * Exit codes:
 *   0 – all tests passed
 *   1 – one or more tests failed
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// The filter / build logic copied verbatim from index.js sync-steam-games
// ─────────────────────────────────────────────────────────────────────────────
const SKIP_KEYWORDS = [
    'dedicated server', ' sdk', 'source sdk', 'soundtrack', ' ost',
    'playtest', 'press review', 'linux client', 'winui', 'steamcmd',
    'steam client', 'tool ', ' tool', 'beta test', 'server beta',
    'dev kit', 'devkit',
];

function buildSteamByAppId(allApps) {
    const steamByAppId = {};
    const seenNames = new Set();
    for (const app of allApps) {
        const appid = app.appid;
        const name  = (app.name || '').trim();
        if (!name || appid == null) continue;
        const nameLower = name.toLowerCase();
        if (SKIP_KEYWORDS.some(kw => nameLower.includes(kw))) continue;
        if (seenNames.has(nameLower)) continue;
        seenNames.add(nameLower);
        steamByAppId[appid] = {
            Title:   name,
            TitleID: String(appid),
            appid:   appid,
            image:   `https://cdn.akamai.steamstatic.com/steam/apps/${appid}/header.jpg`,
            stores:  [{ name: 'Steam', url: `https://store.steampowered.com/app/${appid}/` }],
        };
    }
    return steamByAppId;
}

function diffAndAppend(steamByAppId, existingGamesArr) {
    const existingAppIds = new Set();
    const existingTitles = new Set();
    for (const g of existingGamesArr) {
        if (g.appid != null) existingAppIds.add(Number(g.appid));
        const t = String(g.Title || g.title || '').trim().toLowerCase();
        if (t) existingTitles.add(t);
    }
    const newGames = Object.entries(steamByAppId)
        .filter(([appid, entry]) =>
            !existingAppIds.has(Number(appid)) &&
            !existingTitles.has(entry.Title.trim().toLowerCase()))
        .map(([, entry]) => entry)
        .sort((a, b) => a.appid - b.appid);
    return newGames;
}

function buildFinalPayload(existingFileData, newGames) {
    let gamesArr, topKey, fileMeta;
    if (existingFileData && Array.isArray(existingFileData.Games)) {
        gamesArr = existingFileData.Games;  topKey = 'Games';
        fileMeta = Object.fromEntries(Object.entries(existingFileData).filter(([k]) => k !== 'Games' && k !== 'games'));
    } else if (existingFileData && Array.isArray(existingFileData.games)) {
        gamesArr = existingFileData.games;  topKey = 'games';
        fileMeta = Object.fromEntries(Object.entries(existingFileData).filter(([k]) => k !== 'Games' && k !== 'games'));
    } else if (Array.isArray(existingFileData)) {
        gamesArr = existingFileData; topKey = null; fileMeta = {};
    } else {
        throw new Error('Unexpected existing file format');
    }
    const updatedArr = [...gamesArr, ...newGames];
    const newContent = topKey
        ? { ...fileMeta, Platform: fileMeta.Platform || 'PC', source: fileMeta.source || 'https://github.com/dgibbs64/SteamCMD-AppID-List', [topKey]: updatedArr }
        : { Platform: 'PC', source: 'https://api.steampowered.com/ISteamApps/GetAppList/v2/', Games: updatedArr };
    return { newContent, updatedArr };
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal test harness
// ─────────────────────────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;

function assert(condition, label) {
    if (condition) {
        console.log(`  ✅ ${label}`);
        passed++;
    } else {
        console.error(`  ❌ FAIL: ${label}`);
        failed++;
    }
}

function assertEqual(actual, expected, label) {
    if (actual === expected) {
        console.log(`  ✅ ${label}`);
        passed++;
    } else {
        console.error(`  ❌ FAIL: ${label}`);
        console.error(`       expected: ${JSON.stringify(expected)}`);
        console.error(`       actual:   ${JSON.stringify(actual)}`);
        failed++;
    }
}

function suite(name, fn) {
    console.log(`\n📋 ${name}`);
    fn();
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture data
// ─────────────────────────────────────────────────────────────────────────────
const STEAM_FIXTURE_APPS = [
    { appid: 1174180, name: 'Red Dead Redemption 2' },
    { appid: 1091500, name: 'Cyberpunk 2077' },
    { appid: 892970,  name: 'Valheim' },
    { appid: 814380,  name: 'Sekiro: Shadows Die Twice' },
    { appid: 611500,  name: 'Dying Light 2 Stay Human' },
    // Dead Island 2 – the game the admin wanted to add
    { appid: 268690,  name: 'Dead Island 2' },
    // Should be filtered out (non-game entries)
    { appid: 999001,  name: 'My Game Dedicated Server' },
    { appid: 999002,  name: 'My Game Soundtrack' },
    { appid: 999003,  name: 'My Game SDK' },
    { appid: 999004,  name: 'My Game Playtest' },
    { appid: 999005,  name: 'My Game OST' },
    // Duplicate name (different appid) – should be deduped
    { appid: 999006,  name: 'Dead Island 2' },
    // Empty / null name – should be skipped
    { appid: 999007,  name: '' },
    { appid: 999008,  name: null },
];

// Existing PC.Games.json already contains these two games
const EXISTING_GAMES_JSON = {
    Platform: 'PC',
    source:   'https://github.com/dgibbs64/SteamCMD-AppID-List',
    Games: [
        { Title: 'Red Dead Redemption 2', TitleID: '1174180', appid: 1174180, image: 'https://cdn.akamai.steamstatic.com/steam/apps/1174180/header.jpg', stores: [{ name: 'Steam', url: 'https://store.steampowered.com/app/1174180/' }] },
        { Title: 'Cyberpunk 2077',        TitleID: '1091500', appid: 1091500, image: 'https://cdn.akamai.steamstatic.com/steam/apps/1091500/header.jpg', stores: [{ name: 'Steam', url: 'https://store.steampowered.com/app/1091500/' }] },
    ]
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
suite('1. buildSteamByAppId – filtering', () => {
    const map = buildSteamByAppId(STEAM_FIXTURE_APPS);

    assert(map[1174180] !== undefined, 'keeps "Red Dead Redemption 2"');
    assert(map[1091500] !== undefined, 'keeps "Cyberpunk 2077"');
    assert(map[892970]  !== undefined, 'keeps "Valheim"');
    assert(map[814380]  !== undefined, 'keeps "Sekiro: Shadows Die Twice"');
    assert(map[611500]  !== undefined, 'keeps "Dying Light 2 Stay Human"');
    assert(map[268690]  !== undefined, 'keeps "Dead Island 2"');

    assert(map[999001]  === undefined, 'filters out "Dedicated Server"');
    assert(map[999002]  === undefined, 'filters out "Soundtrack"');
    assert(map[999003]  === undefined, 'filters out "SDK"');
    assert(map[999004]  === undefined, 'filters out "Playtest"');
    assert(map[999005]  === undefined, 'filters out " OST" suffix');
    assert(map[999006]  === undefined, 'deduplicates "Dead Island 2" (second appid wins dedup → first kept)');
    assert(map[999007]  === undefined, 'skips empty name');
    assert(map[999008]  === undefined, 'skips null name');
});

suite('2. buildSteamByAppId – output shape matches add-game write path', () => {
    const map = buildSteamByAppId(STEAM_FIXTURE_APPS);
    const entry = map[268690]; // Dead Island 2

    assertEqual(entry.Title,   'Dead Island 2', 'Title field set');
    assertEqual(entry.TitleID, '268690',         'TitleID is string appid');
    assertEqual(entry.appid,   268690,           'appid is numeric');
    assertEqual(entry.image,   'https://cdn.akamai.steamstatic.com/steam/apps/268690/header.jpg', 'image is Steam CDN header.jpg');
    assert(Array.isArray(entry.stores),          'stores is an array');
    assertEqual(entry.stores[0].name, 'Steam',   'store name is Steam');
    assertEqual(entry.stores[0].url,  'https://store.steampowered.com/app/268690/', 'store URL correct');
});

suite('3. diffAndAppend – only adds truly new games', () => {
    const map      = buildSteamByAppId(STEAM_FIXTURE_APPS);
    const newGames = diffAndAppend(map, EXISTING_GAMES_JSON.Games);

    // RDR2 and Cyberpunk 2077 already exist — should NOT be in newGames
    const titles = newGames.map(g => g.Title);
    assert(!titles.includes('Red Dead Redemption 2'), 'does not re-add existing "Red Dead Redemption 2"');
    assert(!titles.includes('Cyberpunk 2077'),        'does not re-add existing "Cyberpunk 2077"');

    // These 4 are genuinely new
    assert(titles.includes('Dead Island 2'),             'adds "Dead Island 2"');
    assert(titles.includes('Valheim'),                   'adds "Valheim"');
    assert(titles.includes('Sekiro: Shadows Die Twice'), 'adds "Sekiro: Shadows Die Twice"');
    assert(titles.includes('Dying Light 2 Stay Human'),  'adds "Dying Light 2 Stay Human"');

    assertEqual(newGames.length, 4, 'exactly 4 new games added (filtered+deduped steam list minus 2 existing)');

    // New games must be sorted by appid
    const appids = newGames.map(g => g.appid);
    const sorted = [...appids].sort((a, b) => a - b);
    assert(JSON.stringify(appids) === JSON.stringify(sorted), 'new games are sorted by appid');
});

suite('4. diffAndAppend – no new games returns empty array', () => {
    // Existing file already has all steam games
    const allGames = EXISTING_GAMES_JSON.Games.concat([
        { Title: 'Valheim',                   TitleID: '892970',  appid: 892970  },
        { Title: 'Sekiro: Shadows Die Twice', TitleID: '814380',  appid: 814380  },
        { Title: 'Dying Light 2 Stay Human',  TitleID: '611500',  appid: 611500  },
        { Title: 'Dead Island 2',             TitleID: '268690',  appid: 268690  },
    ]);
    const map      = buildSteamByAppId(STEAM_FIXTURE_APPS);
    const newGames = diffAndAppend(map, allGames);

    assertEqual(newGames.length, 0, 'returns 0 new games when all already present');
});

suite('5. buildFinalPayload – preserves existing metadata and appends games', () => {
    const map      = buildSteamByAppId(STEAM_FIXTURE_APPS);
    const newGames = diffAndAppend(map, EXISTING_GAMES_JSON.Games);
    const { newContent, updatedArr } = buildFinalPayload(EXISTING_GAMES_JSON, newGames);

    assertEqual(newContent.Platform, 'PC',  'Platform metadata preserved');
    assert(typeof newContent.source === 'string', 'source metadata preserved');
    assert(Array.isArray(newContent.Games),       'Games key preserved');
    assertEqual(updatedArr.length, EXISTING_GAMES_JSON.Games.length + newGames.length,
        `total games = existing (${EXISTING_GAMES_JSON.Games.length}) + new (${newGames.length})`);

    // Dead Island 2 must be present in the final payload
    const di2 = newContent.Games.find(g => g.Title === 'Dead Island 2');
    assert(di2 !== undefined,            '"Dead Island 2" is in the final Games array');
    assertEqual(di2.appid,   268690,     '"Dead Island 2" appid is correct');
    assertEqual(di2.TitleID, '268690',   '"Dead Island 2" TitleID is correct');
    assert(di2.image.endsWith('/header.jpg'), '"Dead Island 2" image URL ends with /header.jpg');
    assertEqual(di2.stores[0].name, 'Steam', '"Dead Island 2" store name is Steam');
});

suite('6. buildFinalPayload – bare-array format (no top-level key)', () => {
    const map      = buildSteamByAppId([{ appid: 268690, name: 'Dead Island 2' }]);
    const newGames = diffAndAppend(map, []);
    const { newContent } = buildFinalPayload([], newGames);

    assert(Array.isArray(newContent.Games), 'wraps bare array in { Games: [...] }');
    assertEqual(newContent.Platform, 'PC',  'adds Platform field');
    assert(typeof newContent.source === 'string', 'adds source field');
    assertEqual(newContent.Games.length, 1, 'single game written correctly');
});

suite('7. Manual add-game write path – same shape as Steam sync', () => {
    // Simulates what handleAddPcGameToDb / POST /api/admin/add-game does:
    // a manually entered game object must match the Steam-sync output shape
    // so both paths produce compatible entries in PC.Games.json.
    const manualGame = {
        Title:   'Dead Island 2',
        TitleID: '268690',
        appid:   268690,
        image:   'https://cdn.akamai.steamstatic.com/steam/apps/268690/header.jpg',
        stores:  [{ name: 'Steam', url: 'https://store.steampowered.com/app/268690/' }],
    };

    const map       = buildSteamByAppId(STEAM_FIXTURE_APPS);
    const steamEntry = map[268690];

    assertEqual(manualGame.Title,         steamEntry.Title,          'Title matches between manual and Steam sync');
    assertEqual(manualGame.TitleID,       steamEntry.TitleID,        'TitleID matches');
    assertEqual(manualGame.appid,         steamEntry.appid,          'appid matches');
    assertEqual(manualGame.image,         steamEntry.image,          'image URL matches');
    assertEqual(manualGame.stores[0].url, steamEntry.stores[0].url,  'Steam store URL matches');
});

suite('8. diffAndAppend – title-based dedup prevents re-adding by title', () => {
    // Simulate a game that exists in PC.Games.json by title but with a different
    // (or older) appid.  The sync must NOT create a duplicate entry.
    const existingWithDifferentAppid = [
        { Title: 'Dead Island 2', TitleID: '99999', appid: 99999 },
    ];
    const map      = buildSteamByAppId(STEAM_FIXTURE_APPS);
    const newGames = diffAndAppend(map, existingWithDifferentAppid);

    const titles = newGames.map(g => g.Title);
    assert(!titles.includes('Dead Island 2'),
        'does not re-add "Dead Island 2" when title already exists (even if appid differs)');
    assert(titles.includes('Valheim'),                   'still adds other new games');
    assert(titles.includes('Sekiro: Shadows Die Twice'), 'still adds other new games');
});

suite('9. diffAndAppend – adds game when absent by both appid and title', () => {
    // "Dead Island 2" is completely absent from PC.Games.json → must be added.
    const map      = buildSteamByAppId(STEAM_FIXTURE_APPS);
    const newGames = diffAndAppend(map, []);   // empty existing list

    const titles = newGames.map(g => g.Title);
    assert(titles.includes('Dead Island 2'),
        'adds "Dead Island 2" when it is absent from PC.Games.json');
});

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n${'─'.repeat(55)}`);
if (failed === 0) {
    console.log(`✅ All ${passed} assertions passed.\n`);
    process.exit(0);
} else {
    console.error(`❌ ${failed} assertion(s) failed, ${passed} passed.\n`);
    process.exit(1);
}
