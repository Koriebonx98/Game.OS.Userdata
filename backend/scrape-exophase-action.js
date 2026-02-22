/**
 * scrape-exophase-action.js
 *
 * GitHub Actions entrypoint: fetch an Exophase achievements page server-side
 * (no CORS restriction), parse the achievement list with cheerio, then write
 * achievements.json to the Games.Database repository via the GitHub API.
 *
 * Environment variables (all required unless noted):
 *   GAMES_DB_TOKEN       – Fine-grained PAT with Contents: R/W on Games.Database
 *   EXOPHASE_URL         – https://www.exophase.com/game/…/achievements/
 *   PLATFORM             – PS4 | PS3 | Switch | Xbox 360 | PS5 | Xbox One | PC
 *   GAME_TITLE           – Human-readable game name (used in the commit message)
 *   TITLE_ID             – Folder name inside Data/{platform}/Games/ (alnum/_/-)
 *   GAMES_DB_REPO_OWNER  – (optional) Games.Database owner, default: Koriebonx98
 *   GAMES_DB_REPO_NAME   – (optional) Games.Database repo name, default: Games.Database
 */

'use strict';

const cheerio = require('cheerio');
const { Octokit } = require('@octokit/rest');

// ── Read and validate environment variables ───────────────────────────────────

const GAMES_DB_TOKEN      = process.env.GAMES_DB_TOKEN || '';
const EXOPHASE_URL        = (process.env.EXOPHASE_URL || '').trim();
const PLATFORM            = (process.env.PLATFORM || '').trim();
const GAME_TITLE          = (process.env.GAME_TITLE || '').trim();
const TITLE_ID            = (process.env.TITLE_ID || '').trim();
const GAMES_DB_REPO_OWNER = (process.env.GAMES_DB_REPO_OWNER || 'Koriebonx98').trim();
const GAMES_DB_REPO_NAME  = (process.env.GAMES_DB_REPO_NAME  || 'Games.Database').trim();

function fail(msg) {
    console.error(`❌ ${msg}`);
    process.exit(1);
}

if (!GAMES_DB_TOKEN) fail('GAMES_DB_TOKEN is not set. Add it as a repository secret.');
if (!EXOPHASE_URL)   fail('EXOPHASE_URL is required.');
if (!PLATFORM)       fail('PLATFORM is required.');
if (!GAME_TITLE)     fail('GAME_TITLE is required.');
if (!TITLE_ID)       fail('TITLE_ID is required.');

// Validate URL: must be https://exophase.com
let parsedUrl;
try { parsedUrl = new URL(EXOPHASE_URL); } catch { fail(`Invalid EXOPHASE_URL: ${EXOPHASE_URL}`); }
if (parsedUrl.protocol !== 'https:' ||
    (parsedUrl.hostname !== 'exophase.com' && !parsedUrl.hostname.endsWith('.exophase.com'))) {
    fail('Only https://exophase.com URLs are allowed (SSRF protection).');
}

// Validate TITLE_ID
if (!/^[a-zA-Z0-9_-]+$/.test(TITLE_ID)) {
    fail('TITLE_ID may only contain alphanumeric characters, underscores, and hyphens.');
}

// Map platform → Games.Database folder name
const PLATFORM_FOLDER_MAP = {
    'Switch':   'Nintendo - Switch',
    'Xbox 360': 'Microsoft - Xbox 360',
    'PS3':      'Sony - PlayStation 3',
    'PS4':      'Sony - PlayStation 4',
    'PS5':      'Sony - PlayStation 5',
    'Xbox One': 'Microsoft - Xbox One',
    'PC':       'PC'
};
const platformFolder = PLATFORM_FOLDER_MAP[PLATFORM];
if (!platformFolder) fail(`Unknown platform "${PLATFORM}". Valid values: ${Object.keys(PLATFORM_FOLDER_MAP).join(', ')}`);

(async () => {

// ── Fetch Exophase page ───────────────────────────────────────────────────────

console.log(`\nFetching: ${EXOPHASE_URL}`);

const controller = new AbortController();
const fetchTimeout = setTimeout(() => controller.abort(), 20000);
let html;
try {
    const resp = await fetch(EXOPHASE_URL, {
        signal: controller.signal,
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9'
        }
    });
    if (!resp.ok) fail(`HTTP ${resp.status} ${resp.statusText} from Exophase.`);
    html = await resp.text();
    console.log(`✅ Fetched ${html.length.toLocaleString()} bytes`);
} catch (err) {
    if (err.name === 'AbortError') fail('Request to Exophase timed out after 20 seconds.');
    fail(`Fetch error: ${err.message}`);
} finally {
    clearTimeout(fetchTimeout);
}

// ── Parse achievements ────────────────────────────────────────────────────────

const $ = cheerio.load(html);
const scraped = [];

// Exophase structure:
//   <ul class="achievement|trophy|challenge">
//     <li data-average="45.2" class="[secret]">
//       <img src="...icon...">
//       <a>Achievement Name</a>
//       <div class="award-description"><p>Description</p></div>
//     </li>
//   </ul>
$('ul.achievement > li, ul.trophy > li, ul.challenge > li').each((i, el) => {
    const $el = $(el);
    const name = ($el.find('a').first().text() || '').trim();
    if (!name) return;

    const description = ($el.find('div.award-description p').first().text() || '').trim();
    const rawIconUrl  = $el.find('img').first().attr('src') || undefined;

    // Only accept icon URLs served over HTTPS from exophase.com
    let iconUrl;
    if (rawIconUrl) {
        try {
            const iconParsed = new URL(rawIconUrl);
            if (iconParsed.protocol === 'https:' &&
                (iconParsed.hostname === 'exophase.com' || iconParsed.hostname.endsWith('.exophase.com'))) {
                iconUrl = rawIconUrl;
            }
        } catch { /* ignore malformed icon URLs */ }
    }

    const isHidden = ($el.attr('class') || '').split(/\s+/).includes('secret');
    const avgRaw   = $el.attr('data-average');
    const percent  = avgRaw !== undefined ? parseFloat(avgRaw) : undefined;

    const entry = {
        achievementId: String(i + 1),
        name,
        description,
        unlockedAt: null,
        source: 'exophase'
    };
    if (iconUrl)                                  entry.iconUrl = iconUrl;
    if (isHidden)                                 entry.hidden  = true;
    if (percent !== undefined && !isNaN(percent)) entry.percent = percent;
    scraped.push(entry);
});

if (!scraped.length) {
    console.warn('⚠️  No achievements found. Diagnostics:');
    console.warn(`   Page title       : ${$('title').text().trim()}`);
    console.warn(`   ul.achievement   : ${$('ul.achievement').length}`);
    console.warn(`   ul.trophy        : ${$('ul.trophy').length}`);
    console.warn(`   ul.challenge     : ${$('ul.challenge').length}`);
    fail('No achievements found on the Exophase page. Verify the URL points to an achievement/trophy list.');
}

console.log(`✅ Scraped ${scraped.length} achievements`);

// ── Write achievements.json to Games.Database ─────────────────────────────────

const octokit = new Octokit({ auth: GAMES_DB_TOKEN });
const gamesDbPath  = `Data/${platformFolder}/Games/${TITLE_ID}/achievements.json`;
const safeTitle    = String(GAME_TITLE).replace(/[\r\n]/g, ' ').slice(0, 80);
const safePlatform = String(PLATFORM).replace(/[\r\n]/g, ' ').slice(0, 20);
const commitMsg    = `Add achievements for ${safeTitle} (${safePlatform}) from Exophase`;

console.log(`\nWriting to ${GAMES_DB_REPO_OWNER}/${GAMES_DB_REPO_NAME}/${gamesDbPath}`);

// Check if file already exists (to get the SHA for update)
let existingSha;
try {
    const { data } = await octokit.repos.getContent({
        owner: GAMES_DB_REPO_OWNER,
        repo:  GAMES_DB_REPO_NAME,
        path:  gamesDbPath
    });
    existingSha = data.sha;
    console.log('   (updating existing file)');
} catch (err) {
    if (err.status !== 404) throw err;
    console.log('   (creating new file)');
}

const params = {
    owner:   GAMES_DB_REPO_OWNER,
    repo:    GAMES_DB_REPO_NAME,
    path:    gamesDbPath,
    message: commitMsg,
    content: Buffer.from(JSON.stringify(scraped, null, 2)).toString('base64'),
    committer: { name: 'Game OS Bot', email: 'bot@gameos.com' }
};
if (existingSha) params.sha = existingSha;

await octokit.repos.createOrUpdateFileContents(params);

console.log(`✅ achievements.json written (${scraped.length} entries)`);
console.log(`   Path   : ${gamesDbPath}`);
console.log(`   Commit : ${commitMsg}`);

})();
