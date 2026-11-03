# Game.OS Launcher — Features

A full list of what the **Game.OS Launcher** (Avalonia / .NET 8 desktop app) does, grouped like an app-store listing.
Platform-specific notes are marked 🪟 Windows-only, 🐧 Linux, 🍎 macOS. Unmarked features work on every supported OS.

---

## 1. Accounts & Sign-in

- Sign in / register with the **same Game.OS account as the website** (PBKDF2-SHA256 and bcrypt accounts both supported)
- **Remember me** — session cached locally between launches
- Two connection modes: **backend REST API** (preferred, no token needed) or **GitHub-direct** fallback
- **Admin mode** — catalog management panel in the store (add/remove games)
- **Offline mode** — cached data lets you keep using the launcher without a connection; changes are queued and synced later
- **Demo mode** — sample data for screenshots/CI without any network login

## 2. Home / Dashboard

- Stat tiles, featured hero banner, recently added games, recently played, recent achievements
- Quick-resume of the most recently played game
- **Many dashboard styles**, one per console-style theme (see *Themes*)

## 3. Game Library

- Cloud-synced library with cover art, platform filter chips, search, genre filters and star ratings
- **Automatic local game detection** — scans all mounted drives for `Games/$GameFolder` and `Repacks` folders, detects executables and repack archives, watches for live changes and caches results
- Configurable **rescan interval**, scanner logging
- **ROMs scanner** for emulated platforms (RetroArch/Libretro-style folder names are normalised to canonical platforms)
- Title-ID detection from folder/file names (e.g. PS3 `BLUS30305`, Switch `0100ADC022586000`)
- **Game detail page** with description, screenshots carousel, trailers, ratings, playtime, achievements and a Play button
- Per-game **action menu**: launch, settings, saves, mods, links, reviews, etc.
- Per-game **reviews** and **compatibility verdict** badges per platform
- Per-game **saved links** (walkthroughs, download pages, guides)

## 4. Supported Platforms

| Family | Platforms |
|---|---|
| PC | Windows games, repacks, Steam / Epic / GOG / Xbox / EA / Ubisoft / Battle.net libraries |
| PlayStation | PS1, PS2, PS3, PS4, PS5, PSP, PS Vita |
| Xbox | Xbox 360, Xbox One |
| Nintendo | Switch, Wii, GameCube |

Platform names are normalised across the launcher so the same game ties together across the library, store, saves and achievements.

## 5. Games Store & Discovery

- Featured carousel, browse all, genre filter, search, one-click add to library
- Store skins: **Default**, **PS5**, **Xbox**, **Nintendo**
- **Recommendations** based on the genres, platforms and series you play
- Metadata from the **Games.Database**, with optional providers: **IGDB**, **RAWG**, **TheGamesDB** (separate game and ROM provider choice)
- Metadata cache with *prefer cached metadata for local games*
- Auto-update the Games Database on startup
- Contribute missing games, achievements, descriptions and trailers back to the public database (queued and batched)

## 6. Store Accounts (Linked Stores)

Link third-party store accounts per Game.OS user and import what you own:

| Store | Identifier used |
|---|---|
| 🎮 Steam | Web API key + SteamID64 |
| 🛒 Epic Games | Account ID / session token |
| 🌌 GOG | Username / session cookie |
| 🟩 Xbox | OpenXBL API key + Gamertag |
| ⚡ EA | EA account / session token |
| 🔷 Ubisoft | Ubisoft account / session token |
| ❄ Battle.net | BattleTag / session token |

- Sign in through the built-in browser; the launcher recognises each store's login host
- **Owned-games cache** per account, plus user-added download URLs
- **Steam library import** via the Steam Web API (per-user, so each Game.OS account can have a different Steam library)
- **Steam playtime sync** and **local Steam scanner**
- Store-specific **install/launch IDs** (e.g. Epic app names)

## 7. Achievements & Playtime

- Full achievements list on the profile and on each game
- **Steam emulator achievements** — reads unlocked IDs from all major Steam emulator save locations
- **Xenia** (Xbox 360) log reader — detects achievement unlocks live
- **Nintendo Switch** achievement detection — reads Ryujinx game logs, with a translation table (`Switch Ach/Translate.txt`) and optional toast status messages
- **Exophase** profile link and achievement auto-sync
- **Playtime tracking** — session start/exit detection, per-game totals, optional **Mod-client process tracking**
- Per-user playtime history viewer

## 8. Emulator Management

- Set the emulator executable per platform and launch games straight through them
- Supported emulator families include **RPCS3**, **Xenia**, **Ryujinx**, **PCSX2**, **DuckStation**, **Dolphin**, **Xemu**, **Vita3K**, **RetroArch** and others
- Emulator setup and **first-time setup** wizard
- Per-emulator **settings** and **save-path resolution**
- **Emulator mods**: Xenia optimized-settings (`{TitleID}.toml`) and PS2 HD texture packs
- **Ryujinx mod** configuration (`mods.json`) per Switch Title ID
- **PS2 → native PC recompilation** — run finished recompiled builds with render-resolution options
- **ROM conversion** — PS1/PS2 disc images between **CHD ↔ ISO / BIN-CUE** (via `chdman`)
- Switch game log reading after a session

## 9. Saves & Cloud Sync

- **Ludusavi integration** — back up and restore game saves to `Data/{user}/GameSaves/{platform}/{game}/`
- Custom Ludusavi path (or use the one on `PATH`) and configurable save-location rules
- Emulator save-path detection
- Profile, library, friends, achievements and settings synced through the Game.OS backend / GitHub data repository
- Pending-changes queue so edits made offline are pushed later

## 10. Downloads

- **Download manager** with queue, pause/resume, progress and history
- Multi-connection / segmented **direct downloads**
- Built-in **torrent client** (magnet links and `.torrent` files) with DHT peer finding, seeding, ratio limit, port forwarding (UPnP / NAT-PMP), speed and connection limits
- **Intercept browser downloads** automatically
- **Auto-extract** archives (and optionally delete after extraction)
- Configurable download locations per type/platform
- Download notifications: started, completed, failed, paused
- **Auto-update links** — checks saved game links at startup and every 4 hours (GitHub releases, or magnet links scraped from pages)

## 11. Mods

- Per-game mod presets and detection of installed mods in game sub-folders
- Save mod URLs per game with a mod-type tag
- Emulator-level mods (Xenia, PS2 HD textures, Ryujinx)

## 12. Friends & Social

- Friends list with **online / away / offline** presence and pending requests
- **Inbox** for messages and requests
- In-game / quick-menu **chat**
- Broadcast when you come online or start playing a game; toasts when friends do the same
- **Friend network addresses** — save Radmin, ZeroTier, Hamachi or LAN IPs per friend for LAN/VPN play
- Public profile with avatar, stats, badges (LIVE / ADMIN)

## 13. Media Center

- **Music** player with playlists, and **Spotify-style** and default views
- **Movies & TV** with a Cinema layout, watched-at percentage, skip length
- Metadata scrapers for movies, TV and music (**TMDB**, **OMDb**, with media stats)
- Picture-in-picture player (configurable size and position)

## 14. Built-in Web Browser

- Controller-friendly browser inside the launcher
- **Ad blocker** with cosmetic filtering, allow list and custom filters
- Popup blocking, new-tab handling, configurable search engine and home page
- **Gamepad cursor** — left stick moves the pointer, right stick scrolls, buttons act as clicks (XInput)
- On-screen keyboard

## 15. Controller & Big-Screen Experience

- Full **gamepad navigation** of the launcher (XInput) 🪟
- **Per-game controller profiles** — button remapping forwarded to the running game as keystrokes (SendInput) 🪟
- Controller configuration window with sticks, D-pad, buttons, cursor and scroll speed
- **On-screen keyboard** for text entry
- **Quick Menu / Guide overlay** with a global hotkey, configurable actions, and styles per theme
- **Intro video** on startup, with a gallery of videos to pick from or a custom override

## 16. Themes

Console-style looks that restyle the dashboard, library, game info, store and quick menu:

- **Default**, **PS5**, **PS6**, **Steam Big Picture**, **Switch**, **Wii**, **Xbox 360** (Blade, *OG* and *Kinetic* variants), **Xbox One**, plus **Cinema** for media

## 17. Capture & Streaming

- **Screenshots** and **screen recordings** (ffmpeg, downloaded on demand) saved to `{MediaLocation}/Games/{Platform}/{Game}/` 🪟
- Configurable frame rate, resolution and image quality
- **Stream to iOS web app / phone / tablet** — serves the primary screen as MJPEG (or H.264 when ffmpeg is available) over the LAN, protected by a pairing PIN 🪟

## 18. Notifications

- Toast notifications for downloads, friends, achievements, updates and emulator status
- Per-event toggles and a **Test toast** tool

## 19. Updates

- **Launcher auto-update** from GitHub Releases: prompt, on start, or on exit
- Separate **GameOS.Updater** helper app
- Game / database update checks

## 20. Settings & Developer Tools

- Sections: Account, App Preferences, Library, Store, Downloads, Browser, Media, Controller, Notifications, Sync & Data, Developer
- Minimise on game launch, startup behaviour, quick-guide / menu style
- **Dev.log** debug output, scanner logging, Steam import request logging
- Feature flags, update-flow testing

---

## Platform Support Summary

| Capability | 🪟 Windows | 🐧 Linux | 🍎 macOS |
|---|:--:|:--:|:--:|
| Launcher UI, themes, library, store | ✅ | ✅ | ✅ |
| Login, friends, sync, offline cache | ✅ | ✅ | ✅ |
| Downloads & torrents | ✅ | ✅ | ✅ |
| Ludusavi saves, built-in browser, media | ✅ | ✅ | ✅ |
| XInput gamepad navigation & controller profiles | ✅ | — | — |
| Screenshots, recording, phone streaming | ✅ | — | — |
| Installer | `.exe` | `install-linux.sh` + `.desktop` entry (Bazzite, Fedora, Ubuntu, Arch…) | Run from source |

> Session data location: Linux `~/.config/GameOS/sessions.json`; Windows `%APPDATA%/GameOS`.
