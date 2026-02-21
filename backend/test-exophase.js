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
 */

'use strict';

const cheerio = require('cheerio');

// ---------------------------------------------------------------------------
// Built-in fixture: a minimal HTML page that mirrors the real Exophase
// achievements page structure, used when --fixture is passed (no network).
// ---------------------------------------------------------------------------
const FIXTURE_HTML = `<!DOCTYPE html>
<html>
<head><title>Skate 3 (Xbox 360) Achievements - Exophase.com</title></head>
<body>
<ul class="achievement">
  <li data-average="82.5">
    <img src="https://media.exophase.com/achievements/skate3/icon1.png">
    <a>Road to Nowhere</a>
    <div class="award-description"><p>Skate 5 miles total.</p></div>
  </li>
  <li data-average="61.0">
    <img src="https://media.exophase.com/achievements/skate3/icon2.png">
    <a>Big Air</a>
    <div class="award-description"><p>Land a jump of at least 50 feet.</p></div>
  </li>
  <li data-average="12.3" class="secret">
    <img src="https://media.exophase.com/achievements/skate3/icon3.png">
    <a>Hall of Meat</a>
    <div class="award-description"><p>Wreck yourself for 1,000,000 points of pain.</p></div>
  </li>
</ul>
<ul class="trophy">
  <li data-average="95.1">
    <img src="https://media.exophase.com/achievements/skate3/icon4.png">
    <a>Welcome to San Vanelona</a>
    <div class="award-description"><p>Complete the tutorial.</p></div>
  </li>
</ul>
<ul class="challenge">
  <li data-average="5.0">
    <img src="https://media.exophase.com/achievements/skate3/icon5.png">
    <a>Own the City</a>
    <div class="award-description"><p>Own every spot in the city.</p></div>
  </li>
</ul>
</body>
</html>`;

// ---------------------------------------------------------------------------
// Shared scraping function – same logic as the server-side implementation.
// ---------------------------------------------------------------------------
function scrapeAchievements(html) {
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

const useFixture = process.argv.includes('--fixture');
const DEFAULT_URL = 'https://www.exophase.com/game/skate-3-xbox-360/achievements/';
const urlArg = process.argv.slice(2).find(a => a !== '--fixture');
const url = (!useFixture && urlArg) ? urlArg : DEFAULT_URL;

(async () => {
    let html;

    if (useFixture) {
        console.log('🔧 Using built-in fixture HTML (no network request)\n');
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
})();
