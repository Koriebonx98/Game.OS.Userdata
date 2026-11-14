const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('gameOSDesktop', { quit: () => ipcRenderer.send('gameos:quit') });
