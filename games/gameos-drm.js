/* Game OS DRM: per-user licence keys for Game OS exclusives. Reusable by any game (pass its titleId).
 * A key is bound to (titleId, username), is issued when the user claims the game (which adds it to their
 * library), is stored with the library entry and cached on the device so it verifies offline.
 * NOTE: verification is client-side (the salt is public); real enforcement needs a server-signed key. */
(function (root) {
    'use strict';
    const SALT = 'gameos-drm-v1';
    const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const subtle = (root.crypto || {}).subtle;

    async function makeKey(titleId, username) {
        const data = new TextEncoder().encode([SALT, String(titleId).toLowerCase(), String(username).toLowerCase()].join('|'));
        const bytes = new Uint8Array(await subtle.digest('SHA-256', data));
        let s = '';
        for (let i = 0; i < 16; i++) s += ALPHA[bytes[i] % ALPHA.length];
        return 'GOS-' + s.match(/.{4}/g).join('-');
    }
    async function verify(key, titleId, username) {
        return typeof key === 'string' && key === await makeKey(titleId, username);
    }

    const slot = (titleId, username) => 'gameOS_lic_' + String(titleId).toLowerCase() + '_' + String(username).toLowerCase();
    const getLocal = (t, u) => { try { return localStorage.getItem(slot(t, u)); } catch (_) { return null; } };
    const setLocal = (t, u, k) => { try { localStorage.setItem(slot(t, u), k); } catch (_) {} };
    const clearLocal = (t, u) => { try { localStorage.removeItem(slot(t, u)); } catch (_) {} };

    root.GameOSDRM = { makeKey, verify, getLocal, setLocal, clearLocal };
})(typeof window !== 'undefined' ? window : globalThis);
