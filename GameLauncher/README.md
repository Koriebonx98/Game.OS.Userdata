# Game.OS Launcher — C# Console App

A cross-platform console game launcher for **Game.OS** — styled like Xbox / PlayStation / Steam / Playnite.  
Built with **.NET 8** and [Spectre.Console](https://spectreconsole.net/) for rich terminal UI.

---

## Features

| Screen | Description |
|---|---|
| 🔐 **Sign In / Register** | Login or create an account; PBKDF2 password hashing |
| 🏠 **Dashboard** | Stats overview, recently-added games, recent achievements |
| 🎮 **My Library** | Full game list with platform badges, star ratings, filter by platform |
| 🔍 **Game Details** | Per-game detail panel with description, rating, genre |
| 🛒 **Games Store** | Featured releases, browse all, search by title, browse by genre, add to library |
| 🏆 **Achievements** | All unlocked achievements grouped by game |
| 👤 **Profile** | Account info and library stats |

---

## Quick Start

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download) or later

### Run in Demo Mode (no GitHub account needed)
```bash
cd GameLauncher
dotnet run
# → Choose "🚀 Demo Mode" from the login menu
```

### Run in Live Mode (reads/writes your Game.OS GitHub data)
```bash
# Set your GitHub fine-grained PAT (needs read/write access to the private data repo)
export GAMEOS_PAT="ghp_yourTokenHere"
export GAMEOS_OWNER="YourGitHubUsername"
export GAMEOS_DATA_REPO="Game.OS.Private.Data"

cd GameLauncher
dotnet run
```

See **`Game OS API.txt`** (in the repo root) for full setup instructions including how to create a fine-grained PAT.

---

## Build a self-contained EXE (Windows / Mac / Linux)

```bash
# Windows x64
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# macOS ARM
dotnet publish -c Release -r osx-arm64 --self-contained true -p:PublishSingleFile=true

# Linux x64
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true
```

The published executable is placed in `bin/Release/net8.0/<rid>/publish/`.

---

## Project Structure

```
GameLauncher/
├── Program.cs              # Entry point + main navigation loop
├── GameOsClient.cs         # GitHub REST API client (login, library, store, friends…)
├── DemoData.cs             # Built-in demo library / store data (no GitHub needed)
├── Models/
│   └── Models.cs           # UserProfile, Game, Achievement, StoreGame, …
└── UI/
    ├── LoginScreen.cs      # Sign-In / Register / Demo-Mode screens
    ├── DashboardScreen.cs  # Main hub with stats + recent games/achievements
    ├── LibraryScreen.cs    # Full game library with filters + game details
    ├── StoreScreen.cs      # Games store with search, genre browse, add-to-library
    ├── AchievementsScreen.cs
    └── ProfileScreen.cs
```

---

## Authentication

Accounts are stored in your **private** GitHub data repository (see `Game OS API.txt §2`).  
Passwords are **never stored in plain text** — they are hashed client-side with PBKDF2-SHA256 (100 000 iterations) before being saved to GitHub.

The launcher reads the `GAMEOS_PAT` environment variable at startup.  
**Never hard-code a token in source code.**

---

## Screenshots

| Screen | Preview |
|---|---|
| Login | `Design/Screenshots/screen_login.html` |
| Dashboard | `Design/Screenshots/screen_dashboard.html` |
| My Library | `Design/Screenshots/screen_library.html` |
| Games Store | `Design/Screenshots/screen_store.html` |
| Achievements | `Design/Screenshots/screen_achievements.html` |
| Profile | `Design/Screenshots/screen_profile.html` |

Open any `.html` file in a browser for a live preview of the terminal UI.
