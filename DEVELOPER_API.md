# Game OS Developer API

Build an HTML/JS/CSS game, host it in a GitHub repo, and use Game OS accounts, achievements, cloud saves and multiplayer through one script.

## 1. Quick start

1. In **Settings → Roles** request the *Game Developer* role (an admin approves it from the inbox).
2. Put your game in a GitHub repo and publish a release/tag (the store serves files via jsDelivr `cdn.jsdelivr.net/gh/<owner>/<repo>@<tag>/`).
3. In **Settings → Submit a game** enter the details, repo link, release tag and entry file (e.g. `index.html`). An admin approves it and schedules the go-live date.
4. Add the SDK to your game:

```html
<script src="https://koriebonx98.github.io/Game.OS.Userdata/sdk/gameos.js"></script>
<script>
  GameOS.ready().then(({ user }) => console.log('Hello', user.username));
</script>
```

Games run in a sandboxed iframe (no access to Game OS cookies/storage). All Game OS features go through the SDK. Outside Game OS every SDK call rejects with `Not running inside Game OS`, so keep a plain-browser fallback.

## 2. Accounts

`await GameOS.ready()` → `{ user: { username }, game, offline, lan, launch }`.
`launch` is `{ join, room }` when the player opened your game from a lobby invite; call `GameOS.multiplayer.join(launch.join, launch.room)`.
Ownership/DRM is checked by the wrapper page before your game starts.

## 3. Achievements

Add `achievements.json` to the repo root:

```json
{ "Items": [ { "achievementId": "first_win", "Name": "First win", "Description": "Win a match", "hidden": false } ] }
```

```js
const r = await GameOS.achievements.unlock('first_win'); // { unlocked: true } first time only
const all = await GameOS.achievements.list();
```

Unknown ids are rejected. Unlocks appear on the player's profile.

## 4. Cloud save & playtime

```js
await GameOS.save.set({ level: 3 }); // any JSON, max 256 KB
const data = await GameOS.save.get(); // null if none
```

Playtime is tracked automatically while the game is open.

## 5. Multiplayer

Rooms are relayed by the Game OS servers: guests send to the host, the host sends to everyone (or one player). Messages are JSON, max 16 KB; rooms hold 2–8 players.

```js
// Host
const { roomId } = await GameOS.multiplayer.host({ maxPlayers: 4, public: true, mode: 'deathmatch' });
await GameOS.multiplayer.invite('Friend');
GameOS.on('join',    ({ username }) => {});
GameOS.on('leave',   ({ username }) => {});
GameOS.on('message', ({ from, data }) => {});
await GameOS.multiplayer.send({ state: 1 });        // everyone
await GameOS.multiplayer.send({ hi: 1 }, 'Friend'); // one player

// Guest
const rooms = await GameOS.multiplayer.listPublic();
await GameOS.multiplayer.join(hostName, roomId);
GameOS.on('ended', ({ reason }) => {});
```

Other methods: `players()` (friends / LAN players), `setInfo({public, open, mode})`, `kick(username)`, `leave()`.
The host is authoritative; build your game logic around that.

## 6. LAN / offline servers

Players can run `lan-server/` (see `lan-server/README.md`) on any machine. Game OS games automatically use it when opened from that server, so accounts, lobbies and invites work without internet, and it can act as a dedicated server if the official ones are down. Your SDK code needs no changes.

## 7. Limits & notes

- Save 256 KB, message 16 KB, 2–8 players.
- Only the entry HTML is cached for offline play automatically; use relative asset URLs and keep the game small.
- Use a tag/release for the store build; changes need a new submission/approval.
