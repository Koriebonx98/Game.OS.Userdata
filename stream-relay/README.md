# Game.OS stream relay

Small Node server that lets the launcher **broadcast** its screen (Start Broadcasting in the Quick Menu) and
**watch parties** (Movies & TV → Watch party) reach browsers, including iOS Safari — without exposing anyone's IP.

```
launcher ──ws /ingest/:room?key=…──►  relay  ──ws /view/:room──►  watch.html (any browser / iOS web app)
```

## Run

```bash
cd stream-relay
npm install
STREAM_ADMIN_KEY=choose-a-secret npm start     # STREAM_PORT defaults to 26502
npm test                                        # local end-to-end self-test
```

Host it anywhere that supports HTTP + WebSocket and put it behind **HTTPS** (the web app is served over HTTPS,
so browsers block `ws://` / `http://` relays as mixed content).

## Built in to the backend

The backend (`backend/stream-relay.js`) now serves this same relay. Signed-in launchers use it automatically when
*Public broadcast relay* is empty, so watch parties and broadcasts reach the website and iOS app with no extra server.

## Launcher setup

Settings → *Stream to iOS web app* → **Public broadcast relay**: enter the relay URL and (if set) `STREAM_ADMIN_KEY`.
`webAppUrl` in the launcher settings file is the hosted web app that serves `watch.html`
(default `https://koriebonx98.github.io/Game.OS.Userdata/`).

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/rooms` (`x-admin-key` if configured) | Create a room → `{roomId, ingestKey}` |
| `GET /api/rooms/:id` | `{live, viewers, title}` |
| `DELETE /api/rooms/:id?key=ingestKey` | End the room |
| `WS /ingest/:id?key=ingestKey` | Publisher. Binary `0x01`+JPEG, `0x02`+PCM; JSON `audio-format` / `meta` |
| `WS /view/:id` | Viewers receive the same messages |

The room ends when the publisher disconnects. Only the relay URL and an opaque room id are published to the user's
account (`accounts/<user>/broadcast.json`), so the streamer's IP is never shared.

## Watch parties

A party invite is a hidden friend message with `kind: "watch"`, `roomId`, `relayUrl`, `mediaType`, `season`, `episode`;
the recipient needs a launcher version that understands these messages.
If the host chose *wait for friends to accept*, playback starts once an invitee accepts. Viewers who watch for a
minute get the title recorded in `accounts/<user>/watched-media.json` for recommendations.
