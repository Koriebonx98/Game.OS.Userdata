# Game.OS virtual network relay

UDP rendezvous + relay for the Game.OS virtual LAN (used by LFG/groups). Needs a host with a public UDP port
(a VPS; HTTP-only hosts such as Railway cannot run it).

```
VPN_SECRET=<random string> VPN_PORT=26501 node server.js
```

Backend env vars (same `VPN_SECRET`): `VPN_SECRET`, `VPN_RELAY_HOST` (public hostname/IP of this relay), `VPN_RELAY_PORT` (default 26501).
Without them the launcher falls back to UPnP/LAN endpoints.

Launcher (Windows): put `wintun.dll` (from https://www.wintun.net, matching architecture) next to `GameLauncher.exe` and run
as administrator so the `GameOS` adapter can be created. Players join a room's `10.77.N.0/24` network automatically.
