// Run: node --test emulator.test.js
const test = require('node:test');
const assert = require('node:assert');
global.window = {}; global.document = {};
require('./emulator.js');
const Emu = window.GameOSEmu;

test('retro platforms show a play button', () => {
    for (const p of ['GBA', 'Game Boy Advance', 'NES', 'Nintendo Entertainment System', 'SNES',
        'Super Nintendo Entertainment System', 'Game Boy Color', 'Nintendo 64', 'Nintendo DS',
        'Sega Genesis', 'Mega Drive', 'Master System', 'Game Gear', 'Atari 2600', 'PlayStation', 'PS1', 'PSP'])
        assert.ok(Emu.isRetro(p), p);
});
test('unsupported platforms do not', () => {
    for (const p of ['PC', 'PS4', 'PlayStation 4', 'PlayStation 2', 'Xbox 360', 'Nintendo 3DS', 'Switch']) assert.ok(!Emu.isRetro(p), p);
});
