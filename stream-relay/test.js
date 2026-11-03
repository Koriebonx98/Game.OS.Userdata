const { server } = require('./server');
const WebSocket = require('ws');
const assert = require('assert');

server.listen(0, async () => {
  const base = `127.0.0.1:${server.address().port}`;
  try {
    const room = await (await fetch(`http://${base}/api/rooms`, { method: 'POST', body: '{"title":"T"}' })).json();
    const ing = new WebSocket(`ws://${base}/ingest/${room.roomId}?key=${room.ingestKey}`);
    await new Promise(r => ing.on('open', r));
    const view = new WebSocket(`ws://${base}/view/${room.roomId}`);
    const got = [];
    view.on('message', (d, bin) => got.push(bin ? d : d.toString()));
    await new Promise(r => view.on('open', r));
    ing.send(Buffer.from([1, 9, 9]), { binary: true });
    await new Promise(r => setTimeout(r, 200));
    assert(got.some(g => Buffer.isBuffer(g) && g[0] === 1), 'frame relayed');
    const info = await (await fetch(`http://${base}/api/rooms/${room.roomId}`)).json();
    assert(info.live && info.viewers === 1);
    const bad = new WebSocket(`ws://${base}/ingest/${room.roomId}?key=nope`);
    await new Promise(r => bad.on('error', r));
    ing.close();
    await new Promise(r => setTimeout(r, 200));
    assert.strictEqual((await fetch(`http://${base}/api/rooms/${room.roomId}`)).status, 404);
    console.log('OK');
    process.exit(0);
  } catch (e) { console.error(e); process.exit(1); }
});
