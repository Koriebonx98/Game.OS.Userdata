// Game.OS stream relay (HTTP + WebSocket).
// The launcher pushes JPEG frames + PCM audio to /ingest/:roomId?key=...;
// web viewers (incl. iOS Safari) receive them from /view/:roomId.
// Env: STREAM_PORT (default 26502), STREAM_ADMIN_KEY (optional; required to create rooms when set)
//
// Binary message types (first byte): 0x01 JPEG frame, 0x02 PCM audio chunk.
// Text messages are JSON: {type:'audio-format',...} / {type:'meta',title}.
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.STREAM_PORT || '26502', 10);
const ADMIN_KEY = process.env.STREAM_ADMIN_KEY || '';
const MAX_ROOMS = 200;
const MAX_VIEWERS = 500;

// roomId -> { ingestKey, title, live, ingest, viewers:Set, audioFormat, lastFrame, created }
const rooms = new Map();

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type,x-admin-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
}
function json(res, code, obj) {
  cors(res);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 4096) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); } });
  });
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function endRoom(id) {
  const r = rooms.get(id);
  if (!r) return;
  for (const v of r.viewers) { try { v.send(JSON.stringify({ type: 'ended' })); v.close(); } catch { } }
  try { r.ingest && r.ingest.close(); } catch { }
  rooms.delete(id);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); return res.end(); }

  if (req.method === 'POST' && url.pathname === '/api/rooms') {
    if (ADMIN_KEY && !safeEq(req.headers['x-admin-key'] || '', ADMIN_KEY)) return json(res, 401, { error: 'unauthorized' });
    if (rooms.size >= MAX_ROOMS) return json(res, 503, { error: 'too many rooms' });
    const body = await readBody(req);
    const roomId = crypto.randomBytes(9).toString('base64url');
    const ingestKey = crypto.randomBytes(24).toString('base64url');
    rooms.set(roomId, {
      ingestKey, title: String(body.title || '').slice(0, 120), live: false, ingest: null,
      viewers: new Set(), audioFormat: null, lastFrame: null, created: Date.now()
    });
    return json(res, 201, { roomId, ingestKey });
  }

  const m = url.pathname.match(/^\/api\/rooms\/([\w-]+)$/);
  if (m) {
    const r = rooms.get(m[1]);
    if (req.method === 'GET') {
      if (!r) return json(res, 404, { live: false });
      return json(res, 200, { live: r.live, viewers: r.viewers.size, title: r.title });
    }
    if (req.method === 'DELETE') {
      if (!r || !safeEq(url.searchParams.get('key') || '', r.ingestKey)) return json(res, 404, { error: 'not found' });
      endRoom(m[1]);
      return json(res, 200, { ok: true });
    }
  }
  if (url.pathname === '/health') return json(res, 200, { ok: true, rooms: rooms.size });
  json(res, 404, { error: 'not found' });
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 8 * 1024 * 1024 });

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://x');
  const ingest = url.pathname.match(/^\/ingest\/([\w-]+)$/);
  const view = url.pathname.match(/^\/view\/([\w-]+)$/);
  const r = rooms.get((ingest || view || [])[1]);
  if (!r) { socket.destroy(); return; }
  if (ingest && !safeEq(url.searchParams.get('key') || '', r.ingestKey)) { socket.destroy(); return; }
  if (view && r.viewers.size >= MAX_VIEWERS) { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => {
    if (ingest) attachIngest(ws, ingest[1], r); else attachViewer(ws, r);
  });
});

function attachIngest(ws, id, r) {
  if (r.ingest) { try { r.ingest.close(); } catch { } }
  r.ingest = ws; r.live = true;
  ws.on('message', (data, isBinary) => {
    if (!isBinary) {
      let msg; try { msg = JSON.parse(data.toString()); } catch { return; }
      if (msg.type === 'audio-format') r.audioFormat = msg;
      if (msg.type === 'meta' && typeof msg.title === 'string') r.title = msg.title.slice(0, 120);
      for (const v of r.viewers) if (v.readyState === 1) v.send(data.toString());
      return;
    }
    if (data[0] === 0x01) r.lastFrame = data;
    for (const v of r.viewers) {
      if (v.readyState !== 1) continue;
      // Drop video frames for slow viewers instead of buffering; always keep audio flowing.
      if (data[0] === 0x01 && v.bufferedAmount > 1_000_000) continue;
      if (data[0] === 0x02 && v.bufferedAmount > 2_000_000) continue;
      v.send(data, { binary: true });
    }
  });
  ws.on('close', () => { if (r.ingest === ws) endRoom(id); });
  ws.on('error', () => { });
}

function attachViewer(ws, r) {
  r.viewers.add(ws);
  ws.send(JSON.stringify({ type: 'hello', title: r.title, live: r.live }));
  if (r.audioFormat) ws.send(JSON.stringify(r.audioFormat));
  if (r.lastFrame) ws.send(r.lastFrame, { binary: true });
  ws.on('close', () => r.viewers.delete(ws));
  ws.on('error', () => { });
}

// Rooms whose publisher never connected (or went silent) are reaped.
setInterval(() => {
  const now = Date.now();
  for (const [id, r] of rooms) if (!r.live && now - r.created > 120000) endRoom(id);
}, 30000).unref();

if (require.main === module) {
  server.listen(PORT, () => console.log(`stream-relay listening on :${PORT}`));
}
module.exports = { server, rooms };
