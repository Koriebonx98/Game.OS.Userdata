/* Game OS web emulator: ROMs are stored on-device (IndexedDB), emulator core comes from EmulatorJS (cached by sw.js).
 * Suggested ROM folder layout (copy ROMs into these folders before picking them):
 *   Roms/GBA/  Roms/GB/  Roms/GBC/  Roms/NES/  Roms/SNES/   (file name = game title, e.g. "Pokemon Emerald.gba")
 */
(function () {
    const EJS_CDN = 'https://cdn.emulatorjs.org/stable/data/';
    const CORES = { gba: 'gba', gb: 'gb', gbc: 'gb', nes: 'nes', snes: 'snes', sfc: 'snes', smc: 'snes' };
    const ACCEPT = '.gba,.gb,.gbc,.nes,.sfc,.smc,.zip';
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
        if (/advance|gba/.test(p)) return 'gba';
        if (/color|gbc|game ?boy|\bgb\b/.test(p)) return 'gb';
        if (/super|snes/.test(p)) return 'snes';
        if (/nes|famicom/.test(p)) return 'nes';
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
        if (!coreFor(platform, f.name)) { alert('Unsupported ROM type. Use GBA, GB, GBC, NES or SNES.'); return false; }
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
        const frame = document.createElement('iframe');
        frame.style.cssText = 'width:100%;height:100%;border:0;';
        frame.allow = 'autoplay; gamepad; fullscreen';
        const q = s => JSON.stringify(String(s)).replace(/</g, '\\u003c');
        frame.srcdoc = '<!doctype html><body style="margin:0;background:#000"><div style="width:100vw;height:100vh"><div id="game"></div></div><script>' +
            'EJS_player="#game";EJS_core=' + q(core) + ';EJS_gameUrl=' + q(url) + ';EJS_gameName=' + q(title) +
            ';EJS_pathtodata=' + q(EJS_CDN) + ';EJS_startOnLoaded=true;<\/script><script src="' + EJS_CDN + 'loader.js"><\/script>';
        close.onclick = () => { wrap.remove(); URL.revokeObjectURL(url); };
        wrap.append(frame, close);
        document.body.appendChild(wrap);
    }

    window.GameOSEmu = { isRetro, install, play, uninstall, isInstalled };
})();
