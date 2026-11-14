# Digital Abyss (Game OS exclusive)

Playable on the website, the iOS web app (▶ Play in the Game OS app) and the Windows desktop app
(`desktop/digital-abyss`). All three load this same build.

- **Account + DRM**: requires a signed-in Game OS account that owns *Digital Abyss* (PC) in its library
  and has **claimed** it (free "Claim & unlock"). Nothing is added to the library until then. Claiming issues a
  per-user licence key (`GOS-XXXX-…`, see `games/gameos-drm.js`) stored on the library entry (`licenseKey`) and cached on the
  device, so the game verifies and plays offline. Online launches re-check the library; a removed game revokes the cached key.
  Verification is client-side only; real enforcement would need server-signed keys.
- **Cloud saves**: `accounts/{user}/Saves/PC/Digital Abyss/save.json` (in-progress case, stats). Resume on any device.
- **Achievements**: `accounts/{user}/achievements.json` and `Achievements/PC/digital-abyss/achievements.json`.
  Hidden achievements are not in `achievements.json` or the synced per-game file until unlocked.
  Definitions live in `achievements.js` (regenerate `achievements.json` from the non-hidden defs when they change).
- **Playtime**: advances `playtimeMinutes` / `lastPlayedAt` for the PC library entry.

Test: `node --test games/digital-abyss/achievements.test.js`
