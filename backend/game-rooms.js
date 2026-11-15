// Online play for Game OS exclusives, built into the backend so friends can invite each other and play together
// like a console game: the host opens a room, invites a Game OS friend, and the friend joins from their inbox.
//   host  --ws /game/:room--> relay <--ws /game/:room-- invited friends
// Every connection is authenticated with the player's Game OS account, only mutual friends can be invited, and the
// relay never exposes anyone's IP. The relay only forwards JSON between the host and the guests; the host runs the game.
//
// Credentials (Authorization: Bearer <value> for REST, ?auth=<value> for WebSocket):
//   gos_<user>.<hex>   the user's API token (launcher)
//   gost_<user>.<hex>  short-lived game ticket that the website writes to accounts/<user>/game-tickets.json
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const GAMES = { 'snake-plus': { name: 'Snake Plus', maxPlayers: 4 }, 'quizy': { name: 'Quizy', maxPlayers: 4 } };
const MAX_ROOMS = 300;
const MAX_PUBLIC_LISTED = 20;
const MAX_INVITES_PER_ROOM = 8;
const ROOM_NO_HOST_MS = 2 * 60 * 1000;
const MSGS_PER_SECOND = 200;
const INVITE_MARKER = '\u2063\u2063GOSINV1:';

const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');

/**
 * @param app   express app (routes are added under /api/game-rooms)
 * @param server the http.Server returned by app.listen (WebSocket upgrades are attached to it)
 * @param deps  { getFile, putFile, areFriends, sanitiseUsername, conversationPath, parseTokenUsername,
 *                verifyApiToken(raw) => {username,usernameLower}|null, checkRateLimit(ip) => boolean }
 */
function mountGameRooms(app, server, deps) {
    const rooms = new Map();
    const hostRoom = new Map(); // host usernameLower -> room id

    async function authenticate(raw) {
        raw = String(raw || '').trim();
        if (raw.startsWith('gost_')) {
            const rest = raw.slice(5), dot = rest.lastIndexOf('.');
            if (dot < 1) return null;
            const usernameLower = rest.slice(0, dot).toLowerCase();
            if (!deps.sanitiseUsername(usernameLower)) return null;
            const tickets = await deps.getFile(`accounts/${usernameLower}/game-tickets.json`);
            const h = sha256(raw), now = Date.now();
            if (!tickets || !Array.isArray(tickets.content) || !tickets.content.some(t => t && t.h === h && t.exp > now)) return null;
            const profile = await deps.getFile(`accounts/${usernameLower}/profile.json`);
            return profile ? { username: profile.content.username || usernameLower, usernameLower } : null;
        }
        return deps.verifyApiToken(raw);
    }

    async function restAuth(req, res, next) {
        const ip = req.ip || 'unknown';
        if (!deps.checkRateLimit(ip)) return res.status(429).json({ success: false, message: 'Too many requests – please slow down.' });
        const h = req.headers['authorization'] || '';
        try {
            const user = h.startsWith('Bearer ') ? await authenticate(h.slice(7)) : null;
            if (!user) return res.status(401).json({ success: false, message: 'Sign in to Game OS to play online.' });
            req.gameUser = user;
            next();
        } catch (err) {
            console.error('Game room auth error:', err);
            res.status(500).json({ success: false, message: 'Server error during authentication.' });
        }
    }

    const send = (ws, obj) => { try { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); } catch { } };

    function closeRoom(room, reason) {
        if (!rooms.delete(room.id)) return;
        if (hostRoom.get(room.hostLower) === room.id) hostRoom.delete(room.hostLower);
        for (const g of room.guests.values()) { send(g.ws, { t: 'ended', reason }); try { g.ws.close(1000, 'ended'); } catch { } }
        try { room.hostWs && room.hostWs.close(1000, 'ended'); } catch { }
    }

    const cleanMode = m => String(m || '').replace(/[^a-z0-9-]/gi, '').slice(0, 20).toLowerCase();
    const canJoinPublic = (room, userLower) => room.public && room.open && !room.banned.has(userLower);

    function roomOf(req, res) {
        const room = rooms.get(String(req.params.id));
        if (!room) { res.status(404).json({ success: false, message: 'This game session has ended.' }); return null; }
        return room;
    }

    // Public matchmaking: lists lobbies that anyone signed in to Game OS may join (not yet started, with a free seat).
    app.get('/api/game-rooms/public', restAuth, (req, res) => {
        const game = String(req.query.game || '');
        if (!GAMES[game]) return res.status(400).json({ success: false, message: 'Unknown game.' });
        const list = [];
        for (const room of rooms.values()) {
            if (room.game !== game || !room.public || !room.open || room.hostLower === req.gameUser.usernameLower) continue;
            if (!room.hostWs || room.hostWs.readyState !== 1 || room.guests.size + 1 >= GAMES[game].maxPlayers) continue;
            list.push({ roomId: room.id, host: room.host, mode: room.mode, players: room.guests.size + 1, maxPlayers: GAMES[game].maxPlayers });
        }
        list.sort((a, b) => b.players - a.players);
        res.json({ success: true, rooms: list.slice(0, MAX_PUBLIC_LISTED) });
    });

    app.post('/api/game-rooms', restAuth, (req, res) => {
        const game = String((req.body && req.body.game) || '');
        if (!GAMES[game]) return res.status(400).json({ success: false, message: 'Unknown game.' });
        const old = hostRoom.get(req.gameUser.usernameLower);
        if (old && rooms.has(old)) closeRoom(rooms.get(old), 'The host started a new session.');
        if (rooms.size >= MAX_ROOMS) return res.status(503).json({ success: false, message: 'Online play is busy. Try again soon.' });
        const id = crypto.randomBytes(6).toString('hex');
        rooms.set(id, {
            id, game, host: req.gameUser.username, hostLower: req.gameUser.usernameLower, hostWs: null,
            guests: new Map(), invited: new Set(), created: Date.now(),
            public: !!(req.body && req.body.public), mode: cleanMode(req.body && req.body.mode), open: true, banned: new Set()
        });
        hostRoom.set(req.gameUser.usernameLower, id);
        res.status(201).json({ success: true, roomId: id, maxPlayers: GAMES[game].maxPlayers });
    });

    app.get('/api/game-rooms/:id', restAuth, (req, res) => {
        const room = roomOf(req, res);
        if (!room) return;
        const me = req.gameUser.usernameLower;
        if (me !== room.hostLower && !room.invited.has(me) && !canJoinPublic(room, me)) return res.status(403).json({ success: false, message: 'You were not invited to this session.' });
        res.json({ success: true, game: room.game, host: room.host, players: room.guests.size + 1, maxPlayers: GAMES[room.game].maxPlayers });
    });

    // The host updates what the lobby list shows: whether it is public, its game mode, and whether it still takes players.
    app.post('/api/game-rooms/:id/info', restAuth, (req, res) => {
        const room = roomOf(req, res);
        if (!room) return;
        if (room.hostLower !== req.gameUser.usernameLower) return res.status(403).json({ success: false, message: 'Only the host can change the lobby.' });
        const b = req.body || {};
        if (typeof b.public === 'boolean') room.public = b.public;
        if (typeof b.open === 'boolean') room.open = b.open;
        if (typeof b.mode === 'string') room.mode = cleanMode(b.mode);
        res.json({ success: true });
    });

    app.delete('/api/game-rooms/:id', restAuth, (req, res) => {
        const room = rooms.get(String(req.params.id));
        if (room && room.hostLower === req.gameUser.usernameLower) closeRoom(room, 'The host closed the lobby.');
        res.json({ success: true });
    });

    // Invites a mutual friend: they get the same hidden chat invite the launcher uses, which opens a "Join" link.
    app.post('/api/game-rooms/:id/invite', restAuth, async (req, res) => {
        const room = roomOf(req, res);
        if (!room) return;
        try {
            if (room.hostLower !== req.gameUser.usernameLower) return res.status(403).json({ success: false, message: 'Only the host can invite players.' });
            const toLower = String((req.body && req.body.toUsername) || '').toLowerCase();
            if (!deps.sanitiseUsername(toLower) || toLower === room.hostLower) return res.status(400).json({ success: false, message: 'Invalid username.' });
            if (!(await deps.areFriends(room.hostLower, toLower))) return res.status(403).json({ success: false, message: 'You can only invite your Game OS friends.' });
            if (!room.invited.has(toLower) && room.invited.size >= MAX_INVITES_PER_ROOM) return res.status(429).json({ success: false, message: 'Too many invites for this session.' });

            const inviteId = 'msg-' + room.game + '-' + room.id + '-' + crypto.randomBytes(3).toString('hex');
            const envelope = { Invite: {
                inviteId, from: room.host, gameName: GAMES[room.game].name, platform: 'PC', connectionType: 'Game OS Online',
                game: room.game, kind: 'game', roomId: room.id, sentAt: new Date().toISOString()
            } };
            const path = deps.conversationPath(room.host, toLower);
            for (let attempt = 0; ; attempt++) {
                try {
                    const file = await deps.getFile(path);
                    const msgs = file ? [...file.content] : [];
                    msgs.push({ from: room.host, text: INVITE_MARKER + JSON.stringify(envelope), sentAt: envelope.Invite.sentAt });
                    await deps.putFile(path, msgs, `Game invite from ${room.host} to ${toLower}`, file ? file.sha : undefined);
                    break;
                } catch (err) {
                    if (attempt >= 3) throw err;
                    await new Promise(r => setTimeout(r, 400 * (attempt + 1)));
                }
            }
            room.invited.add(toLower);
            res.json({ success: true, inviteId });
        } catch (err) {
            console.error('Game invite error:', err);
            res.status(500).json({ success: false, message: 'Failed to send the invite. Please try again.' });
        }
    });

    const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });

    server.on('upgrade', async (req, socket, head) => {
        let url;
        try { url = new URL(req.url, 'http://x'); } catch { return; }
        const m = url.pathname.match(/^\/game\/([\w-]+)$/);
        if (!m) return;
        socket.on('error', () => { });
        let user = null;
        try { user = deps.checkRateLimit(req.socket.remoteAddress || 'unknown') ? await authenticate(url.searchParams.get('auth')) : null; } catch { }
        if (!user) { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); socket.destroy(); return; }
        wss.handleUpgrade(req, socket, head, ws => attach(ws, rooms.get(m[1]), user));
    });

    function attach(ws, room, user) {
        ws.isAlive = true;
        ws.on('pong', () => { ws.isAlive = true; });
        ws.on('error', () => { });
        const refuse = message => { send(ws, { t: 'error', message }); ws.close(4003, 'refused'); };
        if (!room) return refuse('This game session has ended.');

        const isHost = user.usernameLower === room.hostLower;
        const cap = GAMES[room.game].maxPlayers;
        if (isHost) {
            if (room.hostWs) { try { room.hostWs.close(4000, 'replaced'); } catch { } }
            room.hostWs = ws;
            send(ws, { t: 'hello', role: 'host', you: room.host, game: room.game });
        } else {
            if (!room.invited.has(user.usernameLower) && !canJoinPublic(room, user.usernameLower)) {
                return refuse(room.public && room.open === false ? 'This game has already started.' : 'You were not invited to this session.');
            }
            if (!room.hostWs || room.hostWs.readyState !== 1) return refuse(`${room.host} is not in the lobby any more.`);
            const existing = room.guests.get(user.usernameLower);
            if (!existing && room.guests.size >= cap - 1) return refuse('This game is full.');
            if (existing) { try { existing.ws.close(4000, 'replaced'); } catch { } }
            room.guests.set(user.usernameLower, { name: user.username, ws });
            send(ws, { t: 'hello', role: 'guest', you: user.username, host: room.host, game: room.game });
            send(room.hostWs, { t: 'join', who: user.username });
        }

        let windowStart = Date.now(), count = 0;
        ws.on('message', data => {
            const now = Date.now();
            if (now - windowStart >= 1000) { windowStart = now; count = 0; }
            if (++count > MSGS_PER_SECOND) return;
            let msg; try { msg = JSON.parse(data.toString()); } catch { return; }
            if (!msg || typeof msg !== 'object') return;
            if (isHost) {
                if (typeof msg.kick === 'string') {
                    const g = room.guests.get(msg.kick.toLowerCase());
                    if (room.public) room.banned.add(msg.kick.toLowerCase());
                    if (g) { room.guests.delete(msg.kick.toLowerCase()); try { g.ws.close(1000, 'kicked'); } catch { } }
                    return;
                }
                const out = { t: 'msg', from: room.host, d: msg.d };
                if (typeof msg.to === 'string') { const g = room.guests.get(msg.to.toLowerCase()); if (g) send(g.ws, out); }
                else for (const g of room.guests.values()) send(g.ws, out);
            } else {
                send(room.hostWs, { t: 'msg', from: user.username, d: msg.d });
            }
        });
        ws.on('close', () => {
            if (isHost) { if (room.hostWs === ws) closeRoom(room, 'The host left the lobby.'); return; }
            const g = room.guests.get(user.usernameLower);
            if (g && g.ws === ws) { room.guests.delete(user.usernameLower); send(room.hostWs, { t: 'leave', who: user.username }); }
        });
    }

    // Keeps connections alive through proxies, drops dead ones, and reaps rooms whose host never connected.
    setInterval(() => {
        for (const ws of wss.clients) {
            if (ws.isAlive === false) { ws.terminate(); continue; }
            ws.isAlive = false;
            try { ws.ping(); } catch { }
        }
        const now = Date.now();
        for (const room of rooms.values()) if (!room.hostWs && now - room.created > ROOM_NO_HOST_MS) closeRoom(room, 'The host never connected.');
    }, 25000).unref();

    return { rooms };
}

module.exports = { mountGameRooms };
