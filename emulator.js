/* Game OS web emulator: ROMs are stored on-device (IndexedDB), emulator core comes from EmulatorJS (cached by sw.js).
 * Suggested ROM folder layout (copy ROMs into these folders before picking them):
 *   Roms/GBA/  Roms/GB/  Roms/GBC/  Roms/NES/  Roms/SNES/   (file name = game title, e.g. "Pokemon Emerald.gba")
 */
(function () {
    const EJS_CDN = 'https://cdn.emulatorjs.org/stable/data/';
    const CORES = { gba: 'gba', gb: 'gb', gbc: 'gb', nes: 'nes', snes: 'snes', sfc: 'snes', smc: 'snes',
        n64: 'n64', z64: 'n64', v64: 'n64', nds: 'nds', md: 'segaMD', gen: 'segaMD', smd: 'segaMD', sms: 'segaMS', gg: 'segaGG',
        pce: 'pce', a26: 'atari2600', lnx: 'lynx', ngp: 'ngp', ws: 'ws', wsc: 'ws', pbp: 'psx', chd: 'psx', bin: null, cue: null, iso: null };
    const ACCEPT = '.gba,.gb,.gbc,.nes,.sfc,.smc,.n64,.z64,.v64,.nds,.md,.gen,.smd,.sms,.gg,.pce,.a26,.lnx,.ngp,.ws,.wsc,.pbp,.chd,.iso,.zip';
    const DB = 'gameos-roms';

    function db() {
        return new Promise((res, rej) => {
            const r = indexedDB.open(DB, 1);
            r.onupgradeneeded = () => r.result.createObjectStore('roms');
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
        });
    }
    async function tx(mode, fn) {
        const d = await db();
        return new Promise((res, rej) => {
            const req = fn(d.transaction('roms', mode).objectStore('roms'));
            req.onsuccess = () => res(req.result);
            req.onerror = () => rej(req.error);
        });
    }
    const key = (platform, title) => (platform + '|' + title).toLowerCase();

    function coreFor(platform, fileName) {
        const ext = (fileName.split('.').pop() || '').toLowerCase();
        if (CORES[ext] && ext !== 'zip') return CORES[ext];
        const p = (platform || '').toLowerCase();
        if (/^(sony )?(playstation( 1| one)?|ps1|psx|psone)$/.test(p)) return 'psx';
        if (/^(sony )?(playstation portable|psp)$/.test(p)) return 'psp';
        if (/nintendo 64|\bn64\b/.test(p)) return 'n64';
        if (/\bds\b|nds/.test(p) && !/3ds/.test(p)) return 'nds';
        if (/genesis|mega ?drive/.test(p)) return 'segaMD';
        if (/master system/.test(p)) return 'segaMS';
        if (/game gear/.test(p)) return 'segaGG';
        if (/turbografx|pc engine/.test(p)) return 'pce';
        if (/atari 2600/.test(p)) return 'atari2600';
        if (/lynx/.test(p)) return 'lynx';
        if (/neo geo pocket/.test(p)) return 'ngp';
        if (/wonderswan/.test(p)) return 'ws';
        if (/advance|gba/.test(p)) return 'gba';
        if (/color|gbc|game ?boy|\bgb\b/.test(p)) return 'gb';
        if (/super|snes/.test(p)) return 'snes';
        if (/\bnes\b|nintendo entertainment|famicom/.test(p)) return 'nes';
        return null;
    }
    function isRetro(platform) { return !!coreFor(platform, ''); }

    function pickFile() {
        return new Promise(resolve => {
            const i = document.createElement('input');
            i.type = 'file'; i.accept = ACCEPT;
            i.onchange = () => resolve(i.files[0] || null);
            i.click();
        });
    }

    async function install(platform, title) {
        const f = await pickFile();
        if (!f) return false;
        if (!coreFor(platform, f.name)) { alert('Unsupported ROM type. Use a ROM for a platform supported by the emulator.'); return false; }
        await tx('readwrite', s => s.put({ name: f.name, blob: f }, key(platform, title)));
        return true;
    }
    const isInstalled = async (platform, title) => !!(await tx('readonly', s => s.get(key(platform, title))));
    const uninstall = (platform, title) => tx('readwrite', s => s.delete(key(platform, title)));

    async function play(platform, title) {
        if (!isRetro(platform)) { alert('No in-browser emulator is available for ' + (platform || 'this platform') + ' yet.'); return; }
        let rec = await tx('readonly', s => s.get(key(platform, title)));
        if (!rec) { if (!(await install(platform, title))) return; rec = await tx('readonly', s => s.get(key(platform, title))); }
        const core = coreFor(platform, rec.name);
        // Pass a File (not a blob: URL) so EmulatorJS keeps the file extension needed to detect the ROM type
        const rom = new File([rec.blob], rec.name, { type: 'application/octet-stream' });
        const wrap = document.createElement('div');
        wrap.style.cssText = 'position:fixed;inset:0;height:100vh;height:100dvh;touch-action:manipulation;z-index:99999;background:#000;';
        const close = document.createElement('button');
        close.textContent = '✕ Close';
        close.style.cssText = 'position:absolute;top:env(safe-area-inset-top,8px);right:8px;z-index:2;padding:8px 12px;';
        const stage = document.createElement('div');
        stage.style.cssText = 'width:100%;height:100%;';
        const holder = document.createElement('div');
        holder.id = 'game';
        stage.appendChild(holder);
        // Run EmulatorJS in the page itself: iOS WebKit fails to load it from a srcdoc iframe
        Object.assign(window, { EJS_player: '#game', EJS_core: core, EJS_gameUrl: rom, EJS_gameName: title,
            EJS_pathtodata: EJS_CDN, EJS_startOnLoaded: true,
            EJS_threads: false }); // touch controls are shown automatically on phones/tablets; keyboard/gamepad on desktop
        const loader = document.createElement('script');
        loader.src = EJS_CDN + 'loader.js';
        loader.onerror = () => alert('Could not load the emulator. Check your connection and try again.');
        close.onclick = () => location.reload(); // EmulatorJS cannot be torn down cleanly
        document.addEventListener('keydown', e => { if (e.key === 'Escape' && e.shiftKey) location.reload(); });
        wrap.append(stage, close);
        document.body.appendChild(wrap);
        document.body.appendChild(loader);
    }

    // ── Offline emulator: pre-download EmulatorJS and its cores; sw.js stores everything from the CDN in the 'gameos-emu' cache ──
    const EJS_BASE_FILES = ['loader.js', 'emulator.min.js', 'emulator.min.css', 'compression/extract7z.js', 'compression/extractzip.js',
        'compression/libunrar.js', 'compression/libunrar.js.mem', 'localization/en-US.json'];
    // EmulatorJS core name (as used by CORES above) -> files that make up the core
    const CORE_FILES = { gba: 'mgba', gb: 'gambatte', nes: 'fceumm', snes: 'snes9x', n64: 'mupen64plus_next', nds: 'melonds',
        segaMD: 'genesis_plus_gx', segaMS: 'genesis_plus_gx', segaGG: 'genesis_plus_gx', pce: 'mednafen_pce', atari2600: 'stella2014',
        lynx: 'handy', ngp: 'mednafen_ngp', ws: 'mednafen_wswan', psx: 'pcsx_rearmed', psp: 'ppsspp' };
    const DEFAULT_OFFLINE = ['gba', 'gb', 'nes', 'snes', 'segaMD', 'psx'];
    const OFFLINE_FLAG = 'gameOS_emuOffline';

    function offlineStatus() {
        try { return JSON.parse(localStorage.getItem(OFFLINE_FLAG)) || null; } catch (_) { return null; }
    }
    async function downloadOffline(onProgress, cores) {
        if (!('caches' in window)) throw new Error('Offline storage is not supported in this browser.');
        const wanted = (cores || DEFAULT_OFFLINE).filter(c => CORE_FILES[c]);
        const urls = EJS_BASE_FILES.map(f => EJS_CDN + f);
        wanted.forEach(c => ['-wasm.data', '-legacy-wasm.data'].forEach(x => urls.push(EJS_CDN + 'cores/' + CORE_FILES[c] + x)));
        wanted.forEach(c => urls.push(EJS_CDN + 'cores/reports/' + CORE_FILES[c] + '.json'));
        if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
        const cache = await caches.open('gameos-emu');
        let done = 0, ok = 0;
        for (const url of urls) {
            try {
                if (!(await cache.match(url))) {
                    const r = await fetch(url);
                    if (r.ok) { await cache.put(url, r); ok++; }
                } else ok++;
            } catch (_) {}
            done++;
            if (onProgress) onProgress(done, urls.length);
        }
        // the page needs at least the loader and one core to run offline
        const ready = !!(await cache.match(EJS_CDN + 'loader.js')) && ok > EJS_BASE_FILES.length;
        if (ready) localStorage.setItem(OFFLINE_FLAG, JSON.stringify({ at: Date.now(), cores: wanted }));
        return { ready, cached: ok, total: urls.length };
    }

    window.GameOSEmu = { isRetro, install, play, uninstall, isInstalled, downloadOffline, offlineStatus };
})();
