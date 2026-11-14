// Signs the player in with the Game OS launcher account (read by main.js) before any page script runs.
const { ipcRenderer } = require('electron');

try {
    const session = ipcRenderer.sendSync('gameos-session');
    if (session && session.username && !localStorage.getItem('gameOSUser') && !sessionStorage.getItem('gameOSUser')) {
        localStorage.setItem('gameOSUser', JSON.stringify({
            username: session.username,
            email: session.email || '',
            loginTime: new Date().toISOString()
        }));
    }
} catch (_) { /* fall back to the normal sign-in page */ }
