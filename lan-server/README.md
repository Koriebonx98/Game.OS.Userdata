# Game OS LAN / dedicated server

Lets Game OS games (Snake Plus, Quizy, community games) work on a local network or when the official servers are down.

```
cd lan-server && npm install
node server.js --port 3002 --name "Living room" [--data ./data]
```

It prints LAN URLs. Players open `http://<host-ip>:3002/` in a browser; games detect the server (📡 badge; tap it to enter another address).

- **Accounts**: pick any username (2–24 chars). The first login claims the name for that device; no internet needed.
- **Lobbies/invites**: same room relay as the official backend. Snake Plus is invite-based on LAN (a Join banner appears); Quizy also has Browse.
- **Data** is stored as JSON in `--data` (default `lan-server/data`).
- **HTTPS note**: an https page cannot call an `http://` server, so use the site served by the LAN server itself.
- Tests: `node --test lan-server/test-lan-server.js`.
