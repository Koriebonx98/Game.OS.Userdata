# Game.OS virtual network relay

UDP rendezvous + relay for the Game.OS virtual LAN (used by LFG/groups). Needs a host with a public UDP port
(a VPS; HTTP-only hosts such as Railway cannot run it).

```
VPN_SECRET=<random string> VPN_PORT=26501 node server.js
```

Backend env vars (same `VPN_SECRET`): `VPN_SECRET`, `VPN_RELAY_HOST` (public hostname/IP of this relay), `VPN_RELAY_PORT` (default 26501).
Without them the launcher falls back to an automatically selected LAN/VPN address. All players must already be
on the same reachable network; Game.OS does not open a game port or create a VPN in this mode.
If automatic selection picks the wrong adapter, enter the host's LAN/VPN IPv4 address in Groups & LFG before
hosting or sending an invitation; supplying an address selects the existing LAN/VPN instead of Game.OS VPN.

Launcher (Windows): put `wintun.dll` (from https://www.wintun.net, matching architecture) next to `GameLauncher.exe` and run
as administrator so the `GameOS` adapter can be created. Players join a room's `10.77.N.0/24` network automatically.

Multiplayer and watch-party invitations are sent through friend messages; both parties need a launcher version
that supports these invitations. Sending a game invite creates a group room if necessary. After joining, the host
address is shown and replaces `{IP}` in that game's enabled mod-client connect template. For example, configure
the Ghosts executable with `-connect {IP}`. Otherwise, join in the game or emulator manually. LAN discovery,
Yuzu-style room servers, and Ryujinx network modes depend on the emulator and game and are not configured by
Game.OS. A room address alone does not start a game server or guarantee discovery.
During a running game, use the quick menu's Friends section to invite any friend to that room.
Disconnect stops the local tunnel and clears the launch address; it does not remove a member from the room.
