// Digital Abyss desktop shell. The game itself is served from the Game OS site so the PC, website and
// iOS versions share one build, one login, one DRM check and one cloud save.
const { app, BrowserWindow, shell, Menu, ipcMain } = require('electron');
const path = require('path');

const SITE = process.env.GAMEOS_SITE || 'https://koriebonx98.github.io/Game.OS.Userdata/';
const GAME_URL = new URL('games/digital-abyss/index.html?client=desktop', SITE).href;
const SITE_ORIGIN = new URL(SITE).origin;

if (!app.requestSingleInstanceLock()) app.quit();

ipcMain.on('gameos:quit', e => { if (e.senderFrame && new URL(e.senderFrame.url).origin === SITE_ORIGIN) app.quit(); });

function createWindow() {
    const win = new BrowserWindow({
        width: 480, height: 900, minWidth: 360, minHeight: 640,
        backgroundColor: '#000000', title: 'Digital Abyss',
        autoHideMenuBar: true,
        webPreferences: { contextIsolation: true, sandbox: true, preload: path.join(__dirname, 'preload.js'), backgroundThrottling: true, nodeIntegration: false, partition: 'persist:digital-abyss' }
    });
    win.webContents.setUserAgent(win.webContents.getUserAgent() + ' GameOSDesktop/' + app.getVersion());

    // Only the Game OS site (login, signup, the game) may load in-app; everything else opens in the browser.
    const allowed = url => { try { return new URL(url).origin === SITE_ORIGIN; } catch (_) { return false; } };
    win.webContents.setWindowOpenHandler(({ url }) => { if (!allowed(url)) shell.openExternal(url); return { action: 'deny' }; });
    win.webContents.on('will-navigate', (e, url) => {
        if (url.startsWith('file:')) return;
        if (!allowed(url)) { e.preventDefault(); shell.openExternal(url); }
    });
    win.webContents.on('did-fail-load', (_e, code, _desc, url, isMainFrame) => {
        if (isMainFrame && code !== -3 && !url.startsWith('file:')) win.loadFile(path.join(__dirname, 'offline.html'), { query: { retry: GAME_URL } });
    });

    win.webContents.on('before-input-event', (_e, input) => {
        if (input.type === 'keyDown' && input.key === 'F11') win.setFullScreen(!win.isFullScreen());
    });

    win.loadURL(GAME_URL);
    return win;
}

app.whenReady().then(() => {
    Menu.setApplicationMenu(null);
    let win = createWindow();
    app.on('second-instance', () => { if (win.isMinimized()) win.restore(); win.focus(); });
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) win = createWindow(); });
});
app.on('window-all-closed', () => app.quit());
