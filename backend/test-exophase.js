/**
 * Standalone Exophase scraper test script.
 *
 * Run this from the backend/ directory to validate the scraper against a real
 * Exophase achievements page without needing the full server running.
 *
 * Usage:
 *   node test-exophase.js [url]          – fetch live page and scrape
 *   node test-exophase.js --fixture      – use built-in sample HTML (no network needed)
 *
 * Examples:
 *   node test-exophase.js --fixture
 *   node test-exophase.js https://www.exophase.com/game/skate-3-xbox-360/achievements/
 *
 * Output:
 *   - Summary of scraped achievements printed to stdout
 *   - Full JSON written to /tmp/exophase-test-output.json
 *   - HTML results page written to /tmp/exophase-test-results.html
 */

'use strict';

const cheerio = require('cheerio');

// ---------------------------------------------------------------------------
// Built-in fixture: full Skate 3 (Xbox 360) achievement list matching the
// real Exophase HTML structure (ul.achievement > li).  Used when --fixture is
// passed so the scraper can be validated without any network access.
// ---------------------------------------------------------------------------
const FIXTURE_ACHIEVEMENTS = [
    { name: 'Welcome to Port Carverton',  pct: 93.4, desc: 'Complete the tutorial.' },
    { name: 'Ramp It Up',                 pct: 72.1, desc: 'Build a skate spot using the spot creator.' },
    { name: 'Own the City',               pct: 11.2, desc: 'Own every spot in Port Carverton.' },
    { name: 'Team Player',                pct: 68.5, desc: 'Create a skate team and recruit two skaters.' },
    { name: 'Spreading the Stoke',        pct: 55.3, desc: 'Film and upload a skate video.' },
    { name: 'Board Breaking',             pct: 41.7, desc: 'Destroy 100 boards.' },
    { name: 'Hall of Meat Gold',          pct: 18.9, desc: 'Earn a gold medal in any Hall of Meat competition.', hidden: true },
    { name: 'Monster Mash',               pct: 33.6, desc: 'Win a team event with your skate team.' },
    { name: 'Campus Life',                pct: 61.0, desc: 'Find and skate all the on-campus gaps.' },
    { name: 'Port Carverton Locals Only', pct: 28.4, desc: 'Play a game of S.K.A.T.E. against a local skater.' },
    { name: 'Beastly',                    pct:  9.7, desc: 'Land a manual combo over 500,000 points.' },
    { name: 'Film Director',              pct: 44.2, desc: 'Upload 10 videos to the Skate.Reel.' },
    { name: 'Best In Show',               pct: 22.8, desc: 'Win any best trick competition.' },
    { name: 'Road to Nowhere',            pct: 82.5, desc: 'Skate 5 miles total.' },
    { name: 'Big Air',                    pct: 61.0, desc: 'Land a jump of at least 50 feet.' },
    { name: 'Hall of Meat',               pct: 12.3, desc: 'Wreck yourself for 1,000,000 points of pain.', hidden: true },
    { name: 'Spot Wrecker',               pct: 36.9, desc: 'Destroy every destructible object in the school.' },
    { name: 'Filmbot',                    pct: 53.1, desc: 'Earn a photo sponsorship.' },
    { name: 'Skate Nation',               pct: 15.4, desc: 'Have 20 people join your skate team.' },
    { name: 'Hometown Hero',              pct: 48.7, desc: 'Complete all amateur events in your hometown.' },
    { name: 'Go Big or Go Home',          pct: 31.2, desc: 'Pull off a mega grab over 75 feet.' },
    { name: 'Photogenic',                 pct: 57.8, desc: 'Get your photo taken for a magazine cover.' },
    { name: 'Street Credible',            pct: 39.4, desc: 'Own 10 street spots.' },
    { name: 'Style Points',               pct: 25.6, desc: 'Score over 750,000 points in a best trick event.' },
    { name: "Team Build",                 pct: 62.3, desc: "Fully upgrade your team's skate park." },
    { name: 'Mogul',                      pct:  7.8, desc: 'Earn $1,000,000 in the in-game economy.' },
    { name: 'Transition King',            pct: 20.1, desc: 'Win every vert competition in Port Carverton.' },
    { name: 'Sick Lines',                 pct: 17.6, desc: 'Link 10 grinds in a single combo.' },
    { name: 'Wrecking Crew',              pct: 43.5, desc: 'Team-destroy 500 objects.' },
    { name: 'Community Service',          pct: 66.9, desc: 'Complete 20 community missions.' },
    { name: 'Drop In',                    pct: 78.4, desc: 'Successfully drop in from the highest point in each district.' },
    { name: 'Legendary',                  pct:  4.2, desc: 'Complete the entire pro career.', hidden: true },
    { name: 'Backyard Bliss',             pct: 50.0, desc: 'Complete all challenges in the school skate park.' },
    { name: 'Gapped',                     pct: 35.8, desc: 'Find and land 50 unique gaps.' },
    { name: 'Night Rider',                pct: 29.3, desc: 'Skate for one full in-game night without stopping.' },
    { name: 'Popped Off',                 pct: 46.1, desc: 'Get kicked out of 10 locations.' },
    { name: 'Viral',                      pct: 14.7, desc: 'Have your video viewed 10,000 times in the game.', hidden: true },
    { name: "Slappy's Legacy",           pct: 58.2, desc: "Grind the rail at the Slappy's memorial." },
    { name: 'Concrete Jungle',            pct: 23.5, desc: 'Own all spots in the downtown district.' },
    { name: 'Half Pipe Hero',             pct: 19.0, desc: 'Score over 200,000 points on any half-pipe.' },
    { name: 'Bail Artist',                pct: 37.6, desc: 'Rack up 50 bails in Hall of Meat mode.' },
    { name: 'Spot Builder',               pct: 54.4, desc: 'Build 5 custom skate spots.' },
    { name: 'Grind King',                 pct: 48.9, desc: 'Grind a total of 10 miles.' },
    { name: 'The Ripper',                 pct: 32.1, desc: 'Complete all the demo crew challenges.' },
    { name: 'Old School Cool',            pct: 27.8, desc: 'Land an old-school combo worth 500,000 points.' },
    { name: 'Sponsor Me',                 pct: 71.3, desc: 'Earn your first skateboard sponsorship.' },
    { name: 'Frequent Flyer',             pct: 42.6, desc: 'Complete 30 airline challenges.' },
    { name: 'Top of the World',           pct:  6.5, desc: 'Reach the highest accessible point in every district.', hidden: true },
    { name: 'Photo Op',                   pct: 64.7, desc: 'Take 25 screenshots of your skater in action.' },
    { name: 'Legend',                     pct:  2.3, desc: 'Achieve 100% game completion.', hidden: true },
];

const FIXTURE_HTML = (() => {
    const items = FIXTURE_ACHIEVEMENTS.map(a => {
        const cls = a.hidden ? ' class="secret"' : '';
        return `  <li data-average="${a.pct}"${cls}>\n` +
               // Synthetic icon URL – only the HTML structure matters for scraper tests
               `    <img src="https://media.exophase.com/achievements/skate3/${a.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}.png">\n` +
               `    <a>${a.name}</a>\n` +
               `    <div class="award-description"><p>${a.desc}</p></div>\n` +
               `  </li>`;
    }).join('\n');
    return `<!DOCTYPE html>\n<html>\n<head><title>Skate 3 (Xbox 360) Achievements - Exophase.com</title></head>\n<body>\n<ul class="achievement">\n${items}\n</ul>\n</body>\n</html>`;
})();

// ---------------------------------------------------------------------------
// PS3 fixture – uses <ul class="trophy"> (the class Exophase uses for PS3).
// A small representative subset of Skate 3 PS3 trophies is enough to verify
// the selector handles the trophy variant correctly.
// ---------------------------------------------------------------------------
const FIXTURE_PS3_TROPHIES = [
    { name: 'Skate 3',                    pct:  4.1,  desc: 'Earn all Skate 3 Trophies.', hidden: false },
    { name: 'Welcome to Port Carverton',  pct: 91.3,  desc: 'Complete the tutorial.', hidden: false },
    { name: 'Hall of Meat',               pct: 12.5,  desc: 'Wreck yourself for 1,000,000 points of pain.', hidden: true },
    { name: 'Road to Nowhere',            pct: 79.8,  desc: 'Skate 5 miles total.', hidden: false },
    { name: 'Legendary',                  pct:  3.8,  desc: 'Complete the entire pro career.', hidden: true },
];

const FIXTURE_PS3_HTML = (() => {
    const items = FIXTURE_PS3_TROPHIES.map(a => {
        const cls = a.hidden ? ' class="secret"' : '';
        return `  <li data-average="${a.pct}"${cls}>\n` +
               `    <img src="https://media.exophase.com/trophies/skate3_ps3/${a.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}.png">\n` +
               `    <a>${a.name}</a>\n` +
               `    <div class="award-description"><p>${a.desc}</p></div>\n` +
               `  </li>`;
    }).join('\n');
    return `<!DOCTYPE html>\n<html>\n<head><title>Skate 3 Trophies - PS3 - Exophase.com</title></head>\n<body>\n<ul class="trophy">\n${items}\n</ul>\n</body>\n</html>`;
})();

// Fixture for the plural-class variant (ul.trophies) used on some Exophase pages.
const FIXTURE_TROPHIES_PLURAL_HTML = FIXTURE_PS3_HTML.replace('<ul class="trophy">', '<ul class="trophies">');

// ---------------------------------------------------------------------------
// PS3 Skate 2 fixture – uses <ul class="trophies"> (plural).
// Represents a game different from Skate 3 to verify the scraper handles
// PS3 games beyond the one that was fixed in PR #144.
// ---------------------------------------------------------------------------
const FIXTURE_PS3_SKATE2_TROPHIES = [
    { name: 'Skate 2',                   pct:  3.9,  desc: 'Earn all Skate 2 Trophies.', hidden: false },
    { name: 'Back in Black',             pct: 88.7,  desc: 'Complete the first chapter.', hidden: false },
    { name: 'Hall of Meat',              pct: 10.2,  desc: 'Sustain 1,000,000 points of damage in Hall of Meat.', hidden: true },
    { name: 'City Planner',              pct: 25.4,  desc: 'Move 50 objects in one session.', hidden: false },
    { name: 'Skate 2 Legend',            pct:  2.1,  desc: 'Complete everything in the game.', hidden: true },
];

const FIXTURE_PS3_SKATE2_HTML = (() => {
    const items = FIXTURE_PS3_SKATE2_TROPHIES.map(a => {
        const cls = a.hidden ? ' class="secret"' : '';
        return `  <li data-average="${a.pct}"${cls}>\n` +
               `    <img src="https://media.exophase.com/trophies/skate2_ps3/${a.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}.png">\n` +
               `    <a>${a.name}</a>\n` +
               `    <div class="award-description"><p>${a.desc}</p></div>\n` +
               `  </li>`;
    }).join('\n');
    return `<!DOCTYPE html>\n<html>\n<head><title>Skate 2 Trophies - PS3 - Exophase.com</title></head>\n<body>\n<ul class="trophies">\n${items}\n</ul>\n</body>\n</html>`;
})();

// ---------------------------------------------------------------------------
// Xbox 360 Skate 3 fixture – uses <ul class="achievements"> (plural) with
// <div class="title"> and <div class="description"> for name/desc rather than
// <a> and <div class="award-description">.  This reflects the HTML structure
// Exophase uses for some Xbox 360 achievement pages.
// ---------------------------------------------------------------------------
const FIXTURE_XBOX360_SKATE3_ACHIEVEMENTS = [
    { name: 'Welcome to Port Carverton',  pct: 93.4, desc: 'Complete the tutorial.' },
    { name: 'Ramp It Up',                 pct: 72.1, desc: 'Build a skate spot using the spot creator.' },
    { name: 'Own the City',               pct: 11.2, desc: 'Own every spot in Port Carverton.' },
    { name: 'Team Player',                pct: 68.5, desc: 'Create a skate team and recruit two skaters.' },
    { name: 'Legend',                     pct:  2.3, desc: 'Achieve 100% game completion.', hidden: true },
];

const FIXTURE_XBOX360_SKATE3_HTML = (() => {
    const items = FIXTURE_XBOX360_SKATE3_ACHIEVEMENTS.map(a => {
        const cls = a.hidden ? ' class="achievement secret"' : ' class="achievement"';
        return `  <li${cls} data-average="${a.pct}">\n` +
               `    <img src="https://media.exophase.com/achievements/skate3xbox/${a.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}.png">\n` +
               `    <div class="info">\n` +
               `      <div class="title">${a.name}</div>\n` +
               `      <div class="description">${a.desc}</div>\n` +
               `    </div>\n` +
               `  </li>`;
    }).join('\n');
    return `<!DOCTYPE html>\n<html>\n<head><title>Skate 3 Achievements - Xbox 360 - Exophase.com</title></head>\n<body>\n<ul class="achievements">\n${items}\n</ul>\n</body>\n</html>`;
})();

// ---------------------------------------------------------------------------
// Shared scraping function – same selector cascade as the server-side implementation.
// ---------------------------------------------------------------------------
function scrapeAchievements(html) {
    const $ = cheerio.load(html);

    // Selector cascade: primary → plural fallback → data-average last resort.
    let items = $('ul.achievement > li, ul.trophy > li, ul.challenge > li');
    if (!items.length) items = $('ul.achievements > li, ul.trophies > li, ul.challenges > li');
    if (!items.length) items = $('li[data-average]').filter((_, el) =>
        $(el).find('a, h4, h5, .title, .award-title').length > 0);

    const scraped = [];

    items.each((i, el) => {
        const $el = $(el);
        const name = ($el.find('a').first().text() ||
                      $el.find('h4, h5, .title, .award-title').first().text() || '').trim();
        if (!name) return;

        const description = ($el.find('div.award-description p, .award-description, .description').first().text() || '').trim();
        const iconUrl     = $el.find('img').first().attr('src') || undefined;
        const isHidden    = ($el.attr('class') || '').split(/\s+/).includes('secret');
        const avgRaw      = $el.attr('data-average');
        const percent     = avgRaw !== undefined ? parseFloat(avgRaw) : undefined;

        const entry = {
            achievementId: String(i + 1),
            name,
            description,
            unlockedAt: null,
            source: 'exophase'
        };
        if (iconUrl)                                  entry.iconUrl  = iconUrl;
        if (isHidden)                                 entry.hidden   = true;
        if (percent !== undefined && !isNaN(percent)) entry.percent  = percent;
        scraped.push(entry);
    });

    return { scraped, $ };
}

// ---------------------------------------------------------------------------
// Self-test: validate the scraper against all fixtures when --fixture is passed.
// ---------------------------------------------------------------------------
function runFixtureTests() {
    const tests = [
        { label: 'Xbox 360 (ul.achievement)',         html: FIXTURE_HTML,                  expected: FIXTURE_ACHIEVEMENTS },
        { label: 'PS3     (ul.trophy)',               html: FIXTURE_PS3_HTML,              expected: FIXTURE_PS3_TROPHIES },
        { label: 'plural  (ul.trophies)',             html: FIXTURE_TROPHIES_PLURAL_HTML,  expected: FIXTURE_PS3_TROPHIES },
        { label: 'PS3 Skate 2 (ul.trophies)',         html: FIXTURE_PS3_SKATE2_HTML,       expected: FIXTURE_PS3_SKATE2_TROPHIES },
        { label: 'Xbox 360 Skate 3 (ul.achievements + div.title)', html: FIXTURE_XBOX360_SKATE3_HTML, expected: FIXTURE_XBOX360_SKATE3_ACHIEVEMENTS },
    ];

    let allPassed = true;
    for (const t of tests) {
        const { scraped } = scrapeAchievements(t.html);
        const pass = scraped.length === t.expected.length &&
            scraped.every((a, i) => a.name === t.expected[i].name &&
                (!!a.hidden === !!t.expected[i].hidden) &&
                (t.expected[i].pct === undefined || a.percent === t.expected[i].pct));
        if (pass) {
            console.log(`  ✅  ${t.label}: ${scraped.length} entries OK`);
        } else {
            console.error(`  ❌  ${t.label}: expected ${t.expected.length} entries, got ${scraped.length}`);
            allPassed = false;
        }
    }
    if (!allPassed) process.exit(1);
    console.log('\n✅  All fixture tests passed.\n');
}

const useFixture = process.argv.includes('--fixture');
const DEFAULT_URL = 'https://www.exophase.com/game/skate-3-xbox-360/achievements/';
const urlArg = process.argv.slice(2).find(a => a !== '--fixture');
const url = (!useFixture && urlArg) ? urlArg : DEFAULT_URL;

(async () => {
    let html;

    if (useFixture) {
        // Run all fixture tests first (Xbox 360 + PS3 trophy + plural-class variants)
        console.log('🔧 Running fixture tests (no network request)\n');
        runFixtureTests();
        // Use the Xbox 360 fixture for the visual HTML report
        html = FIXTURE_HTML;
    } else {
        console.log(`Fetching: ${url}\n`);

        // Validate URL
        let parsed;
        try {
            parsed = new URL(url);
        } catch {
            console.error('❌ Invalid URL');
            process.exit(1);
        }
        if (parsed.protocol !== 'https:' ||
            (parsed.hostname !== 'exophase.com' && !parsed.hostname.endsWith('.exophase.com'))) {
            console.error('❌ Only https://exophase.com URLs are allowed');
            process.exit(1);
        }

        // Fetch
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        try {
            const resp = await fetch(url, {
                signal: controller.signal,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9'
                }
            });
            if (!resp.ok) {
                console.error(`❌ HTTP ${resp.status} ${resp.statusText}`);
                process.exit(1);
            }
            html = await resp.text();
            console.log(`✅ Fetched ${html.length.toLocaleString()} bytes\n`);
        } catch (err) {
            if (err.name === 'AbortError') {
                console.error('❌ Request timed out');
            } else {
                console.error('❌ Fetch error:', err.message);
            }
            process.exit(1);
        } finally {
            clearTimeout(timeout);
        }
    }

    const { scraped, $ } = scrapeAchievements(html);

    if (!scraped.length) {
        console.warn('⚠️  No achievements found. The page structure may have changed, or the URL may not be an achievements list page.');
        console.log('\nPage title:', $('title').text().trim());
        console.log('ul.achievement count:', $('ul.achievement').length);
        console.log('ul.trophy count:', $('ul.trophy').length);
        console.log('ul.challenge count:', $('ul.challenge').length);
        console.log('ul.trophies count:', $('ul.trophies').length);
        console.log('ul.achievements count:', $('ul.achievements').length);
        process.exit(1);
    }

    console.log(`✅ Scraped ${scraped.length} achievements:\n`);
    scraped.forEach((a, i) => {
        const hidden = a.hidden ? ' [HIDDEN]' : '';
        const pct    = a.percent !== undefined ? ` (${a.percent}% earned)` : '';
        console.log(`  ${String(i + 1).padStart(3)}. ${a.name}${hidden}${pct}`);
        if (a.description) console.log(`       ${a.description.slice(0, 80)}${a.description.length > 80 ? '…' : ''}`);
    });

    // Write full output
    const fs = require('fs');
    const outPath = '/tmp/exophase-test-output.json';
    fs.writeFileSync(outPath, JSON.stringify(scraped, null, 2), 'utf8');
    console.log(`\n📄 Full JSON written to: ${outPath}`);

    // Write HTML results page for visual inspection
    const sourceLabel = useFixture ? 'Fixture (Skate 3 Xbox 360)' : url;
    const rows = scraped.map((a, i) => {
        const hiddenBadge = a.hidden
            ? '<span style="background:#dc2626;color:#fff;font-size:10px;padding:1px 5px;border-radius:3px;margin-left:6px">HIDDEN</span>'
            : '';
        const pctBar = a.percent !== undefined
            ? `<div style="background:#e2e8f0;border-radius:4px;height:6px;margin-top:4px"><div style="background:#3b82f6;height:6px;border-radius:4px;width:${Math.min(a.percent, 100)}%"></div></div><span style="font-size:11px;color:#64748b">${a.percent}% of players earned this</span>`
            : '';
        return `<tr style="border-bottom:1px solid #e2e8f0">
  <td style="padding:10px 8px;color:#94a3b8;font-size:12px;white-space:nowrap">${i + 1}</td>
  <td style="padding:10px 8px">
    <div style="font-weight:600;color:#1e293b">${a.name}${hiddenBadge}</div>
    <div style="color:#475569;font-size:13px;margin-top:2px">${a.description || ''}</div>
    ${pctBar}
  </td>
</tr>`;
    }).join('\n');

    const htmlReport = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Exophase Scraper — ${scraped.length} Achievements</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#f8fafc; margin:0; padding:24px; }
  .card { background:#fff; border-radius:12px; box-shadow:0 1px 4px rgba(0,0,0,.08); max-width:860px; margin:0 auto; overflow:hidden; }
  .header { background:linear-gradient(135deg,#1e3a5f 0%,#2563eb 100%); color:#fff; padding:24px 28px; }
  .header h1 { margin:0 0 4px; font-size:22px; }
  .header p  { margin:0; opacity:.8; font-size:14px; }
  .badge { display:inline-block; background:rgba(255,255,255,.2); border-radius:20px; padding:3px 12px; font-size:13px; margin-top:10px; }
  table { width:100%; border-collapse:collapse; }
  tr:hover td { background:#f1f5f9; }
  .footer { padding:14px 28px; background:#f1f5f9; font-size:12px; color:#64748b; text-align:right; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <h1>🎮 Exophase Achievement Scraper</h1>
    <p>Source: ${sourceLabel}</p>
    <div class="badge">✅ ${scraped.length} achievements scraped</div>
  </div>
  <table>
    <thead><tr style="background:#f8fafc">
      <th style="padding:10px 8px;text-align:left;font-size:12px;color:#64748b;font-weight:600">#</th>
      <th style="padding:10px 8px;text-align:left;font-size:12px;color:#64748b;font-weight:600">Achievement</th>
    </tr></thead>
    <tbody>
${rows}
    </tbody>
  </table>
  <div class="footer">scraped ${new Date().toISOString()} · source: exophase</div>
</div>
</body>
</html>`;

    const htmlPath = '/tmp/exophase-test-results.html';
    fs.writeFileSync(htmlPath, htmlReport, 'utf8');
    console.log(`📊 HTML results page written to: ${htmlPath}`);
})();
