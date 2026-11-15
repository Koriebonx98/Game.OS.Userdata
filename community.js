/* Game OS community features: Game Developer role, store submissions (GitHub repo + release) and VIP.
 * Data lives in the private data repo (community/*.json); in demo mode it falls back to localStorage.
 * Depends on script.js (githubRead/githubWrite, MODE, getCurrentUser, escapeHtml, isAdminUser, addGameGitHub). */
(function () {
    'use strict';
    const ROLES = 'community/roles.json';
    const REQUESTS = 'community/role-requests.json';
    const SUBMISSIONS = 'community/store-submissions.json';
    const REPO_RE = /^https:\/\/github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100}?)(?:\.git)?\/?$/;
    const esc = s => escapeHtml(String(s == null ? '' : s));
    const me = () => { const u = getCurrentUser(); return u ? u.username : null; };
    const lower = s => String(s || '').toLowerCase();
    const newId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const cloud = () => MODE !== 'demo';

    // ── Storage ─────────────────────────────────────────────────────────────
    async function read(path, fallback) {
        if (!cloud()) { try { return JSON.parse(localStorage.getItem('gameOS_' + path)) || fallback; } catch (_) { return fallback; } }
        const f = await githubRead(path);
        return f ? f.content : fallback;
    }
    // Read-modify-write with retries so two people editing the same file don't overwrite each other.
    async function update(path, fallback, fn, message) {
        for (let attempt = 0; ; attempt++) {
            let file = null, data = fallback;
            if (cloud()) { file = await githubRead(path); data = file ? file.content : fallback; }
            else { try { data = JSON.parse(localStorage.getItem('gameOS_' + path)) || fallback; } catch (_) {} }
            const next = fn(data);
            if (next === undefined) return data;
            try {
                if (cloud()) await githubWrite(path, next, message, file ? file.sha : undefined);
                else localStorage.setItem('gameOS_' + path, JSON.stringify(next));
                return next;
            } catch (err) { if (attempt >= 2) throw err; }
        }
    }

    // ── Roles ───────────────────────────────────────────────────────────────
    async function getRoles(username) {
        const all = await read(ROLES, {});
        const r = all[lower(username)] || {};
        const admin = lower(username) === ADMIN_USERNAME_LOWER;
        return { admin, developer: admin || !!r.developer, vip: admin || !!r.vip };
    }
    async function setRole(username, role, value) {
        if (!isAdminUser()) throw new Error('Admin access required.');
        if (!/^[A-Za-z0-9._-]{1,40}$/.test(username || '')) throw new Error('Enter a valid username.');
        if (cloud() && !(await githubRead(`accounts/${lower(username)}/profile.json`))) throw new Error('User not found.');
        await update(ROLES, {}, all => {
            const r = Object.assign({}, all[lower(username)]);
            if (value) r[role] = true; else delete r[role];
            all[lower(username)] = r;
            return all;
        }, `${value ? 'Grant' : 'Revoke'} ${role}: ${username}`);
    }
    async function listRoleHolders() {
        const all = await read(ROLES, {});
        return Object.entries(all).filter(([, r]) => r.vip || r.developer).map(([u, r]) => ({ username: u, ...r }));
    }

    // ── Role requests (Game Developer) ──────────────────────────────────────
    async function requestDeveloper(note) {
        const user = me();
        if (!user) throw new Error('Please log in first.');
        if ((await getRoles(user)).developer) throw new Error('You already have the Game Developer role.');
        let dup = false;
        await update(REQUESTS, [], list => {
            if (list.some(r => lower(r.from) === lower(user) && r.status === 'pending')) { dup = true; return undefined; }
            return list.concat({ id: newId(), type: 'developer', from: user, note: String(note || '').slice(0, 500), status: 'pending', createdAt: new Date().toISOString() });
        }, `Game Developer request: ${user}`);
        if (dup) throw new Error('You already have a pending request.');
    }
    const listRequests = () => read(REQUESTS, []);
    async function decideRequest(id, accept) {
        if (!isAdminUser()) throw new Error('Admin access required.');
        let target = null;
        await update(REQUESTS, [], list => {
            const r = list.find(x => x.id === id);
            if (!r || r.status !== 'pending') return undefined;
            r.status = accept ? 'accepted' : 'declined'; r.decidedAt = new Date().toISOString(); target = r;
            return list;
        }, `${accept ? 'Accept' : 'Decline'} developer request`);
        if (target && accept) await setRole(target.from, 'developer', true);
    }

    // ── Store submissions ───────────────────────────────────────────────────
    function parseRepo(url) {
        const m = REPO_RE.exec(String(url || '').trim());
        return m ? { owner: m[1], repo: m[2] } : null;
    }
    // Checks that the repo is public, the entry file exists and (when given) the release tag exists.
    async function verifyRepo(form) {
        const r = parseRepo(form.repoUrl);
        if (!r) throw new Error('Repository link must look like https://github.com/owner/repo');
        const api = `https://api.github.com/repos/${r.owner}/${r.repo}`;
        const repo = await fetch(api);
        if (repo.status === 404) throw new Error('Repository not found or not public.');
        if (!repo.ok) return r; // rate limited etc.: admin reviews it anyway
        if (form.releaseTag) {
            const rel = await fetch(`${api}/releases/tags/${encodeURIComponent(form.releaseTag)}`);
            if (rel.status === 404) throw new Error(`Release "${form.releaseTag}" not found in that repository.`);
        }
        return r;
    }
    function cleanForm(f) {
        const entry = String(f.entry || 'index.html').trim().replace(/^\/+/, '');
        if (/\.\.|[<>"'\\]/.test(entry)) throw new Error('Entry file path is not valid.');
        const cover = String(f.coverUrl || '').trim();
        if (cover && !/^https:\/\//i.test(cover)) throw new Error('Cover image must be an https link.');
        const title = String(f.title || '').trim();
        if (title.length < 2 || title.length > 80) throw new Error('Title must be 2-80 characters.');
        const description = String(f.description || '').trim();
        if (description.length < 20) throw new Error('Please describe your game (at least 20 characters).');
        return {
            title, description: description.slice(0, 2000), entry,
            repoUrl: String(f.repoUrl || '').trim(), releaseTag: String(f.releaseTag || '').trim().slice(0, 100),
            coverUrl: cover, version: String(f.version || '').trim().slice(0, 30),
            genres: String(f.genres || '').split(',').map(x => x.trim()).filter(Boolean).slice(0, 6),
            multiplayer: !!f.multiplayer
        };
    }
    async function submitGame(form) {
        const user = me();
        if (!user) throw new Error('Please log in first.');
        if (!(await getRoles(user)).developer) throw new Error('Only Game Developers can submit games.');
        const clean = cleanForm(form);
        await verifyRepo(clean);
        let dup = false;
        await update(SUBMISSIONS, [], list => {
            if (list.some(s => s.status !== 'declined' && lower(s.title) === lower(clean.title))) { dup = true; return undefined; }
            return list.concat({ id: newId(), by: user, ...clean, status: 'pending', createdAt: new Date().toISOString() });
        }, `Store submission: ${clean.title}`);
        if (dup) throw new Error('A game with this title is already submitted.');
    }
    const listSubmissions = () => read(SUBMISSIONS, []);
    // publishAt: ISO string (scheduled), or '' to publish as soon as it is approved.
    async function decideSubmission(id, accept, publishAt, reason) {
        if (!isAdminUser()) throw new Error('Admin access required.');
        await update(SUBMISSIONS, [], list => {
            const s = list.find(x => x.id === id);
            if (!s) return undefined;
            s.status = accept ? 'approved' : 'declined';
            s.publishAt = accept && publishAt ? new Date(publishAt).toISOString() : (accept ? new Date().toISOString() : null);
            s.reason = reason ? String(reason).slice(0, 300) : undefined;
            s.decidedAt = new Date().toISOString();
            return list;
        }, `${accept ? 'Approve' : 'Decline'} store submission`);
        _swrMem.delete('devgames');
    }
    const isLive = s => s.status === 'approved' && (!s.publishAt || new Date(s.publishAt) <= new Date());

    // Store entry shape matches Games.Database entries, plus playUrl so it is playable like other exclusives.
    function toStoreGame(s) {
        const r = parseRepo(s.repoUrl) || {};
        return {
            platform: 'PC', Title: s.title, TitleID: 'dev-' + s.id, image: s.coverUrl || '',
            description: s.description, genres: s.genres || [], developer: s.by,
            categories: ['Community', 'Free'].concat(s.multiplayer ? ['Multiplayer'] : []), features: ['Community', 'Free'],
            gameOSExclusive: true, playUrl: 'dev-game.html?id=' + encodeURIComponent(s.id),
            downloadUrl: r.owner ? `https://github.com/${r.owner}/${r.repo}/releases/${s.releaseTag ? 'tag/' + encodeURIComponent(s.releaseTag) : 'latest'}` : ''
        };
    }
    async function fetchPublishedDevGames() {
        let list;
        try { list = await _swr('devgames', () => read(SUBMISSIONS, [])); } catch (_) { list = []; }
        const games = list.filter(isLive).map(toStoreGame);
        try { localStorage.setItem('gameOS_devPlay', JSON.stringify(games.map(g => [lower(g.Title), g.playUrl]))); } catch (_) {}
        return games;
    }
    function devGamePlayPath(title) {
        try { const e = JSON.parse(localStorage.getItem('gameOS_devPlay') || '[]').find(x => x[0] === lower(title)); return e ? e[1] : ''; } catch (_) { return ''; }
    }
    async function getPublishedDevGame(id) {
        const list = await fetchPublishedDevGames();
        const g = list.find(x => x.TitleID === 'dev-' + id);
        if (!g) return null;
        const s = (await _swr('devgames', () => read(SUBMISSIONS, []))).find(x => x.id === id);
        return { game: g, submission: s };
    }
    // Raw GitHub files are served as text/plain; jsDelivr serves them with correct types so html/js/css run.
    function cdnBase(s) {
        const r = parseRepo(s.repoUrl);
        return `https://cdn.jsdelivr.net/gh/${r.owner}/${r.repo}${s.releaseTag ? '@' + encodeURIComponent(s.releaseTag) : ''}/`;
    }

    // ── Inbox items (admin approvals + result notices) ──────────────────────
    const seenKey = () => 'gameOS_commSeen_' + lower(me());
    const seen = () => { try { return JSON.parse(localStorage.getItem(seenKey())) || []; } catch (_) { return []; } };
    async function inboxItems() {
        const user = me();
        if (!user) return { count: 0, html: [] };
        const html = [];
        const [requests, subs] = await Promise.all([listRequests().catch(() => []), listSubmissions().catch(() => [])]);
        if (isAdminUser()) {
            requests.filter(r => r.status === 'pending').forEach(r => html.push(`
            <div class="friend-item"><span class="friend-name">🛠️ ${esc(r.from)} <span style="color:#666;font-size:0.8em;font-weight:400;">requests the <strong>Game Developer</strong> role${r.note ? ' – “' + esc(r.note) + '”' : ''}</span></span>
                <div class="friend-actions">
                    <button class="btn-accept-friend" onclick="communityDecideRequest('${esc(r.id)}', true)">✅ Accept</button>
                    <button class="btn-decline-friend" onclick="communityDecideRequest('${esc(r.id)}', false)">❌ Decline</button>
                </div></div>`));
            subs.filter(s => s.status === 'pending').forEach(s => html.push(`
            <div class="friend-item" style="flex-wrap:wrap;"><span class="friend-name">🎮 ${esc(s.by)} <span style="color:#666;font-size:0.8em;font-weight:400;">submitted <strong>${esc(s.title)}</strong> to the store – <a href="${esc(s.repoUrl)}" target="_blank" rel="noopener">repo</a></span></span>
                <div class="friend-actions" style="flex-wrap:wrap;gap:6px;">
                    <label style="font-size:0.8em;">Go live <input type="datetime-local" id="pub-${esc(s.id)}" style="padding:3px;"></label>
                    <button class="btn-accept-friend" onclick="communityDecideSubmission('${esc(s.id)}', true)">✅ Approve</button>
                    <button class="btn-decline-friend" onclick="communityDecideSubmission('${esc(s.id)}', false)">❌ Decline</button>
                </div></div>`));
        }
        const done = seen();
        const mine = [];
        requests.filter(r => lower(r.from) === lower(user) && r.status !== 'pending').forEach(r =>
            mine.push({ id: r.id, text: r.status === 'accepted' ? '🎉 You are now a <strong>Game Developer</strong>! Open Settings to submit a game.' : 'Your Game Developer request was declined.' }));
        subs.filter(s => lower(s.by) === lower(user) && (s.status === 'approved' || s.status === 'declined')).forEach(s =>
            mine.push({ id: s.id, text: s.status === 'approved'
                ? `✅ <strong>${esc(s.title)}</strong> was approved${s.publishAt && new Date(s.publishAt) > new Date() ? ' and goes live ' + esc(new Date(s.publishAt).toLocaleString()) : ' and is live in the store'}.`
                : `❌ <strong>${esc(s.title)}</strong> was declined${s.reason ? ': ' + esc(s.reason) : '.'}` }));
        mine.filter(n => !done.includes(n.id)).forEach(n => html.push(`
            <div class="friend-item"><span class="friend-name">${n.text}</span>
                <div class="friend-actions"><button class="btn-decline-friend" onclick="communityDismiss('${esc(n.id)}')">✓ Dismiss</button></div></div>`));
        return { count: html.length, html };
    }
    window.communityDismiss = id => { localStorage.setItem(seenKey(), JSON.stringify(seen().concat(id))); if (typeof loadInbox === 'function') loadInbox(); };
    window.communityDecideRequest = async (id, ok) => { try { await decideRequest(id, ok); } catch (e) { alert(e.message); } loadInbox(); };
    window.communityDecideSubmission = async (id, ok) => {
        let reason = '';
        if (!ok) { reason = prompt('Reason for declining (optional):') || ''; }
        const at = document.getElementById('pub-' + id);
        try { await decideSubmission(id, ok, at && at.value ? at.value : '', reason); } catch (e) { alert(e.message); }
        loadInbox();
    };

    // ── Account settings UI ─────────────────────────────────────────────────
    const field = (id, label, extra) => `<label style="display:block;margin:8px 0 2px;font-size:0.85em;font-weight:600;">${label}</label>${extra || `<input id="${id}" style="width:100%;padding:8px;border:1px solid #cbd5e1;border-radius:6px;box-sizing:border-box;">`}`;
    async function renderSettings(el) {
        const user = me();
        if (!el || !user) return;
        el.innerHTML = '<p style="color:#666;">Loading…</p>';
        const [roles, requests, subs] = await Promise.all([getRoles(user), listRequests().catch(() => []), listSubmissions().catch(() => [])]);
        const badges = [roles.admin ? '🛡️ Admin' : '', roles.developer ? '🛠️ Game Developer' : '', roles.vip ? '💎 VIP' : '']
            .filter(Boolean).map(b => `<span class="store-card-ach" style="margin-right:6px;">${b}</span>`).join('') || '<span style="color:#666;">Standard account</span>';
        const pending = requests.some(r => lower(r.from) === lower(user) && r.status === 'pending');
        let h = `<p>${badges}</p>`;
        if (!roles.developer) {
            h += pending ? '<p style="color:#666;">⏳ Your Game Developer request is waiting for an admin to review it.</p>' : `
            <p style="font-size:0.9em;color:#475569;">Make your own games for Game OS and list them in the store. An admin reviews every request.</p>
            ${field('devNote', 'Tell us what you want to build (optional)')}
            <button class="btn btn-primary" id="devRequestBtn" style="margin-top:10px;">🛠️ Request Game Developer role</button>`;
        } else {
            const mine = subs.filter(s => lower(s.by) === lower(user));
            h += `<h4 style="margin:14px 0 6px;">Submit a game to the store <a href="DEVELOPER_API.md" target="_blank" rel="noopener" style="font-size:0.75em;font-weight:400;">📖 Developer API docs</a></h4>
            <p style="font-size:0.85em;color:#475569;">Host your game in a public GitHub repo (HTML/JS/CSS run in Game OS just like our own games). Tag a release and we use it as the version and download link. An admin approves it and schedules when it goes live.</p>
            ${field('subTitle', 'Game title')}${field('subDesc', 'Description', '<textarea id="subDesc" rows="3" style="width:100%;padding:8px;border:1px solid #cbd5e1;border-radius:6px;box-sizing:border-box;"></textarea>')}
            ${field('subRepo', 'GitHub repository link (https://github.com/you/game)')}${field('subTag', 'Release tag (e.g. v1.0.0 – leave empty for latest)')}
            ${field('subEntry', 'Start file in the repo (default index.html)')}${field('subCover', 'Cover image link (https, optional)')}
            ${field('subGenres', 'Genres (comma separated)')}${field('subVersion', 'Version')}
            <label style="display:block;margin-top:8px;font-size:0.9em;"><input type="checkbox" id="subMulti"> Online multiplayer</label>
            <button class="btn btn-primary" id="subSend" style="margin-top:10px;">📤 Submit for review</button>
            ${mine.length ? '<h4 style="margin:16px 0 6px;">Your submissions</h4>' + mine.map(s => `<div class="account-detail-row"><span class="detail-label">${esc(s.title)}</span><span class="detail-value">${
                s.status === 'pending' ? '⏳ In review' : s.status === 'declined' ? '❌ Declined' + (s.reason ? ' – ' + esc(s.reason) : '')
                : isLive(s) ? '✅ Live' : '🗓️ Goes live ' + esc(new Date(s.publishAt).toLocaleString())}</span></div>`).join('') : ''}`;
        }
        if (roles.admin) {
            const holders = await listRoleHolders();
            h += `<h4 style="margin:18px 0 6px;">Admin: grant roles</h4>
            ${field('roleUser', 'Username')}
            <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
                <button class="btn btn-primary" data-role="vip" data-val="1">💎 Grant VIP</button><button class="btn btn-secondary" data-role="vip" data-val="0">Revoke VIP</button>
                <button class="btn btn-primary" data-role="developer" data-val="1">🛠️ Grant Developer</button><button class="btn btn-secondary" data-role="developer" data-val="0">Revoke Developer</button>
            </div>
            ${holders.length ? '<p style="font-size:0.85em;margin-top:10px;color:#475569;">' + holders.map(x => `${esc(x.username)} ${x.vip ? '💎' : ''}${x.developer ? '🛠️' : ''}`).join(' · ') + '</p>' : ''}
            <p style="font-size:0.85em;color:#475569;">Pending requests and submissions appear in your <a href="inbox.html">Inbox</a> with Accept / Decline.</p>`;
        }
        h += '<div id="communityMsg" class="message" style="margin-top:10px;"></div>';
        el.innerHTML = h;
        const msg = el.querySelector('#communityMsg');
        const say = (t, ok) => showMessage(msg, t, ok ? 'success' : 'error');
        const val = id => (el.querySelector('#' + id) || {}).value || '';
        const run = async (btn, fn, okText) => {
            btn.disabled = true;
            try { await fn(); say(okText, true); setTimeout(() => renderSettings(el), 1200); }
            catch (e) { say(e.message || 'Something went wrong.', false); btn.disabled = false; }
        };
        const rq = el.querySelector('#devRequestBtn');
        if (rq) rq.onclick = () => run(rq, () => requestDeveloper(val('devNote')), '✅ Request sent to the Game OS admins.');
        const sb = el.querySelector('#subSend');
        if (sb) sb.onclick = () => run(sb, () => submitGame({
            title: val('subTitle'), description: val('subDesc'), repoUrl: val('subRepo'), releaseTag: val('subTag'), entry: val('subEntry'),
            coverUrl: val('subCover'), genres: val('subGenres'), version: val('subVersion'), multiplayer: el.querySelector('#subMulti').checked
        }), '✅ Submitted! An admin will review it.');
        el.querySelectorAll('[data-role]').forEach(b => b.onclick = () =>
            run(b, () => setRole(val('roleUser').trim(), b.dataset.role, b.dataset.val === '1'), '✅ Updated.'));
    }

    window.Community = { getRoles, setRole, requestDeveloper, listRequests, decideRequest, submitGame, listSubmissions, decideSubmission,
        fetchPublishedDevGames, getPublishedDevGame, devGamePlayPath, cdnBase, parseRepo, isLive, inboxItems, renderSettings, cleanForm };
    window.fetchPublishedDevGames = fetchPublishedDevGames;
    window.devGamePlayPath = devGamePlayPath;
    window.communityInboxItems = inboxItems;
})();
