/* Game OS web emulator: ROMs are stored on-device (IndexedDB), emulator core comes from EmulatorJS (cached by sw.js).
 * Suggested ROM folder layout (copy ROMs into these folders before picking them):
 *   Roms/GBA/  Roms/GB/  Roms/GBC/  Roms/NES/  Roms/SNES/   (file name = game title, e.g. "Pokemon Emerald.gba")
 */
(function () {
    const EJS_CDN = 'https://cdn.emulatorjs.org/stable/data/';
    const CORES = { gba: 'gba', gb: 'gb', gbc: 'gb', nes: 'nes', snes: 'snes', sfc: 'snes', smc: 'snes',
        n64: 'n64', z64: 'n64', v64: 'n64', nds: 'nds', md: 'segaMD', gen: 'segaMD', smd: 'segaMD', sms: 'segaMS', gg: 'segaGG',
        pce: 'pce', a26: 'atari2600', lnx: 'lynx', ngp: 'ngp', ws: 'ws', wsc: 'ws', bin: null, cue: null, iso: null };
    const ACCEPT = '.gba,.gb,.gbc,.nes,.sfc,.smc,.n64,.z64,.v64,.nds,.md,.gen,.smd,.sms,.gg,.pce,.a26,.lnx,.ngp,.ws,.wsc,.zip';
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
        let rec = await tx('readonly', s => s.get(key(platform, title)));
        if (!rec) { if (!(await install(platform, title))) return; rec = await tx('readonly', s => s.get(key(platform, title))); }
        const core = coreFor(platform, rec.name);
        const url = URL.createObjectURL(rec.blob);
        const wrap = document.createElement('div');
        wrap.style.cssText = 'position:fixed;inset:0;z-index:99999;background:#000;';
        const close = document.createElement('button');
        close.textContent = '✕ Close';
        close.style.cssText = 'position:absolute;top:env(safe-area-inset-top,8px);right:8px;z-index:2;padding:8px 12px;';
        const stage = document.createElement('div');
        stage.style.cssText = 'width:100%;height:100%;';
        const holder = document.createElement('div');
        holder.id = 'game';
        stage.appendChild(holder);
        // Run EmulatorJS in the page itself: iOS WebKit fails to load it from a srcdoc iframe
        Object.assign(window, { EJS_player: '#game', EJS_core: core, EJS_gameUrl: url, EJS_gameName: title,
            EJS_pathtodata: EJS_CDN, EJS_startOnLoaded: true });
        const loader = document.createElement('script');
        loader.src = EJS_CDN + 'loader.js';
        loader.onerror = () => alert('Could not load the emulator. Check your connection and try again.');
        close.onclick = () => location.reload(); // EmulatorJS cannot be torn down cleanly
        wrap.append(stage, close);
        document.body.appendChild(wrap);
        document.body.appendChild(loader);
    }

    window.GameOSEmu = { isRetro, install, play, uninstall, isInstalled };
})();
