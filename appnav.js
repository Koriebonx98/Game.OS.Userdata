/* Game OS app: controller / keyboard navigation with highlight (Xbox 360 guide / PS5 style).
   D-pad/arrows move, A/Enter opens (game rows -> info card), X/x plays, B/Esc goes back. */
(function () {
    'use strict';
    var SEL = '.app-row, .app-tabbar button, .app-detail button, .app-sheet button, .app-main button, .app-main select, .app-main input, .app-main a[href], .app-main [data-open-t], .app-header button, .app-chat button, .app-chat input, .game-modal-close, .game-modal button, .game-modal a[href]';
    var cur = null;

    function visible(el) {
        if (!el || el.disabled || el.closest('[hidden]')) return false;
        var r = el.getBoundingClientRect();
        if (r.width < 2 || r.height < 2) return false;
        var cs = getComputedStyle(el);
        return cs.visibility !== 'hidden' && cs.display !== 'none';
    }
    function layer() {
        var gm = document.getElementById('gameDetailModal');
        if (gm && gm.style.display && gm.style.display !== 'none') return gm;
        var ids = ['achSheet', 'chatPane', 'gameDetail'];
        for (var i = 0; i < ids.length; i++) {
            var e = document.getElementById(ids[i]);
            if (e && !e.hidden) return e;
        }
        return null;
    }
    function candidates() {
        var root = layer();
        var list = Array.prototype.slice.call(document.querySelectorAll(SEL));
        if (root) list = list.filter(function (e) { return root.contains(e); });
        else list = list.filter(function (e) { return !e.closest('.app-detail, .app-sheet, .app-chat, #gameDetailModal'); });
        return list.filter(visible);
    }
    function setFocus(el) {
        if (cur && cur !== el) cur.classList.remove('nav-focus');
        cur = el;
        if (!el) return;
        el.classList.add('nav-focus');
        try { el.focus({ preventScroll: true }); } catch (_) {}
        if (el.scrollIntoView) el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    }
    function center(r) { return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; }
    function move(dir) {
        var list = candidates();
        if (!list.length) return;
        if (!cur || list.indexOf(cur) < 0) { setFocus(list[0]); return; }
        var c = center(cur.getBoundingClientRect()), best = null, bs = Infinity;
        list.forEach(function (el) {
            if (el === cur) return;
            var p = center(el.getBoundingClientRect()), dx = p.x - c.x, dy = p.y - c.y, main, off;
            if (dir === 'left') { main = -dx; off = Math.abs(dy); }
            else if (dir === 'right') { main = dx; off = Math.abs(dy); }
            else if (dir === 'up') { main = -dy; off = Math.abs(dx); }
            else { main = dy; off = Math.abs(dx); }
            if (main <= 1) return;
            var s = main + off * 2.5;
            if (s < bs) { bs = s; best = el; }
        });
        if (best) setFocus(best);
    }
    function activate() {
        if (!cur || !visible(cur)) return;
        if (cur.tagName === 'INPUT' || cur.tagName === 'SELECT') { cur.focus(); return; }
        cur.click();
    }
    function back() {
        var gm = document.getElementById('gameDetailModal');
        if (gm && gm.style.display && gm.style.display !== 'none') { var x = gm.querySelector('.game-modal-close'); if (x) x.click(); else gm.style.display = 'none'; return; }
        var s = document.getElementById('achSheetClose'), sh = document.getElementById('achSheet');
        if (sh && !sh.hidden && s) { s.click(); return; }
        var cp = document.getElementById('chatPane'), cb = document.getElementById('chatBack');
        if (cp && !cp.hidden && cb) { cb.click(); return; }
        var d = document.getElementById('gameDetail'), db = document.getElementById('detailBack');
        if (d && !d.hidden && db) db.click();
    }
    function play() {
        var btn = document.getElementById('detailPlayBtn') || document.getElementById('detailPcPlay');
        var d = document.getElementById('gameDetail');
        if (d && !d.hidden) { if (btn) btn.click(); return; }
        if (!cur || !cur.matches('[data-open-t]')) return;
        cur.click();
        var tries = 0, t = setInterval(function () {
            var b = document.getElementById('detailPlayBtn') || document.getElementById('detailPcPlay');
            if (b || ++tries > 20) { clearInterval(t); if (b) b.click(); }
        }, 100);
    }
    function onOpen() {
        // after a layer opens/closes, make sure something visible is highlighted
        setTimeout(function () {
            var list = candidates();
            if (!cur || list.indexOf(cur) < 0) setFocus(list.length ? (layer() ? (list.filter(function (e) { return !e.closest('.app-detail-bar'); })[0] || list[0]) : list[0]) : null);
        }, 60);
    }

    document.addEventListener('keydown', function (e) {
        var t = e.target, typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
        if (e.ctrlKey || e.metaKey || e.altKey) return;
        var k = e.key;
        if (typing && k !== 'Escape' && k !== 'ArrowUp' && k !== 'ArrowDown') return;
        if (t && t.tagName === 'SELECT' && k !== 'Escape') return;
        var dirs = { ArrowLeft: 'left', ArrowRight: 'right', ArrowUp: 'up', ArrowDown: 'down' };
        if (dirs[k]) { e.preventDefault(); move(dirs[k]); }
        else if (k === 'Enter') { if (cur && t === cur && cur.tagName !== 'BUTTON' && cur.tagName !== 'A') { e.preventDefault(); activate(); } else if (cur && t !== cur) { e.preventDefault(); activate(); } }
        else if (k === 'x' || k === 'X') { e.preventDefault(); play(); }
        else if (k === 'Escape' || k === 'Backspace' || k === 'b' || k === 'B') { if (typing) { t.blur(); return; } e.preventDefault(); back(); onOpen(); }
    });
    document.addEventListener('click', function () { onOpen(); }, true);
    document.addEventListener('pointerdown', function () { if (cur) { cur.classList.remove('nav-focus'); } }, true);

    // Gamepad: 0=A 1=B 2=X, 12-15 d-pad, left stick
    var prev = {}, lastMove = 0, raf = 0;
    function poll() {
        var pads = navigator.getGamepads ? navigator.getGamepads() : [];
        var now = performance.now(), any = false;
        for (var i = 0; i < pads.length; i++) {
            var p = pads[i]; if (!p) continue; any = true;
            var b = function (n) { return p.buttons[n] && p.buttons[n].pressed; };
            var down = function (n, fn) { var key = i + ':' + n, v = b(n); if (v && !prev[key]) fn(); prev[key] = v; };
            down(0, function () { activate(); onOpen(); });
            down(1, function () { back(); onOpen(); });
            down(2, play);
            var dir = b(14) ? 'left' : b(15) ? 'right' : b(12) ? 'up' : b(13) ? 'down' : null;
            var ax = p.axes[0] || 0, ay = p.axes[1] || 0;
            if (!dir) { if (ax < -.6) dir = 'left'; else if (ax > .6) dir = 'right'; else if (ay < -.6) dir = 'up'; else if (ay > .6) dir = 'down'; }
            if (dir && now - lastMove > 180) { lastMove = now; move(dir); }
        }
        raf = any ? requestAnimationFrame(poll) : 0;
        if (!any) setTimeout(startPoll, 1000);
    }
    function startPoll() {
        if (raf) return;
        var pads = navigator.getGamepads ? navigator.getGamepads() : [];
        for (var i = 0; i < pads.length; i++) if (pads[i]) { raf = requestAnimationFrame(poll); return; }
    }
    window.addEventListener('gamepadconnected', function () { startPoll(); onOpen(); });
})();
