// Game.OS virtual-network rendezvous + relay (UDP).
// Env: VPN_SECRET (must match backend), VPN_PORT (default 26501)
//
// Packet types (first byte):
//   0x01 REGISTER  [token utf8]            -> reply 0x02 [json {endpoint, peers:[{vip,ip,port}]}]
//   0x10 RELAY     [src4][dst4][payload]   -> forwarded as 0x11 [src4][payload]
const dgram = require('dgram');
const crypto = require('crypto');

const SECRET = process.env.VPN_SECRET || '';
const PORT = parseInt(process.env.VPN_PORT || '26501', 10);
const PEER_TTL_MS = 30000;

// rooms: roomId -> Map(vip -> {ip, port, seen})
const rooms = new Map();
// endpoint "ip:port" -> {roomId, vip}
const byEndpoint = new Map();

function verifyToken(token) {
  // token = roomId.vip.exp.sig  (sig = hex HMAC-SHA256 of "roomId.vip.exp")
  const parts = String(token).split('.');
  if (parts.length !== 4 || !SECRET) return null;
  const [roomId, vip, exp, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(`${roomId}.${vip}.${exp}`).digest('hex');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (Number(exp) < Date.now()) return null;
  return { roomId, vip: parseInt(vip, 10) };
}

const sock = dgram.createSocket('udp4');

sock.on('message', (msg, rinfo) => {
  if (msg.length < 1) return;
  const key = `${rinfo.address}:${rinfo.port}`;
  if (msg[0] === 0x01) {
    const t = verifyToken(msg.slice(1).toString('utf8'));
    if (!t) return;
    let room = rooms.get(t.roomId);
    if (!room) { room = new Map(); rooms.set(t.roomId, room); }
    const old = room.get(t.vip);
    if (old) byEndpoint.delete(`${old.ip}:${old.port}`);
    room.set(t.vip, { ip: rinfo.address, port: rinfo.port, seen: Date.now() });
    byEndpoint.set(key, { roomId: t.roomId, vip: t.vip });
    const peers = [];
    for (const [vip, p] of room) if (vip !== t.vip) peers.push({ vip, ip: p.ip, port: p.port });
    const body = Buffer.from(JSON.stringify({ endpoint: key, peers }));
    sock.send(Buffer.concat([Buffer.from([0x02]), body]), rinfo.port, rinfo.address);
  } else if (msg[0] === 0x10 && msg.length >= 9) {
    const owner = byEndpoint.get(key);
    if (!owner) return;
    const src = msg.readUInt32BE(1), dst = msg.readUInt32BE(5);
    if (src !== owner.vip) return; // anti-spoof
    const room = rooms.get(owner.roomId);
    const peer = room && room.get(dst);
    if (!peer) return;
    const out = Buffer.concat([Buffer.from([0x11]), msg.slice(1, 5), msg.slice(9)]);
    sock.send(out, peer.port, peer.ip);
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [roomId, room] of rooms) {
    for (const [vip, p] of room) {
      if (now - p.seen > PEER_TTL_MS) { room.delete(vip); byEndpoint.delete(`${p.ip}:${p.port}`); }
    }
    if (room.size === 0) rooms.delete(roomId);
  }
}, 10000).unref();

if (require.main === module) {
  if (!SECRET) console.warn('VPN_SECRET not set: all tokens will be rejected');
  sock.bind(PORT, () => console.log(`vpn-relay listening on udp/${PORT}`));
}
module.exports = { sock, verifyToken };
