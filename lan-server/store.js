// Tiny JSON file store with the same getFile/putFile shape the backend uses, so backend/game-rooms.js runs unchanged.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function createStore(dir) {
    fs.mkdirSync(dir, { recursive: true });
    const root = path.resolve(dir);
    const resolve = p => {
        const full = path.resolve(root, p);
        if (full !== root && !full.startsWith(root + path.sep)) throw new Error('Invalid path');
        return full;
    };
    const shaOf = text => crypto.createHash('sha1').update(text).digest('hex');
    return {
        async getFile(p) {
            try { const text = fs.readFileSync(resolve(p), 'utf8'); return { content: JSON.parse(text), sha: shaOf(text) }; }
            catch (err) { if (err.code === 'ENOENT') return null; throw err; }
        },
        async putFile(p, content) {
            const full = resolve(p);
            fs.mkdirSync(path.dirname(full), { recursive: true });
            const tmp = full + '.tmp';
            fs.writeFileSync(tmp, JSON.stringify(content, null, 2));
            fs.renameSync(tmp, full);
        }
    };
}
module.exports = { createStore };
