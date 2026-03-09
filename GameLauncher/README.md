# Game.OS Launcher — Graphical PC App

A **graphical Windows/Linux/macOS PC game launcher** for Game.OS — designed like  
**Xbox Dashboard / PlayStation 5 / Steam Big Picture / Playnite**.

Built with **.NET 8** + [Avalonia UI](https://avaloniaui.net/) (cross-platform WPF-style GUI).

> **Same backend as the website** — the launcher authenticates and stores data directly in the
> same private GitHub repository that the web frontend uses.  No separate Node.js server is needed.

---

## Visual Studio

Open **`Game.OS.Userdata.sln`** in the repository root to load both the launcher and the scanner
tests in **Visual Studio 2022+** with a single double-click.  
Both projects (`GameLauncher` and `GameScanner.Tests`) are included and configured for
Debug / Release × Any CPU.

---

## Login Flow — Same as the Website

The C# launcher authenticates with **exactly the same method** as the web frontend:

| Step | Web frontend (`script.js`) | C# launcher (`GitHubDataService.cs`) |
|---|---|---|
| Hash algorithm | PBKDF2-SHA256, 100 000 iter | PBKDF2-SHA256, 100 000 iter |
| Salt | `{username}:gameos` | `{username}:gameos` |
| Storage | GitHub data repo | GitHub data repo |
| Bcrypt support | ✅ backend-created accounts | ✅ `BCrypt.Net.BCrypt.Verify()` |

![Same Login — Web vs C# Launcher](../Design/Screenshots/screenshot_launcher_compare.png)

> *Left: web browser login · Right: C# launcher — both sign in as the same account using identical PBKDF2-SHA256 password hashing*

### Login Success — C# Launcher Dashboard

After a successful login the C# launcher shows the same account data fetched live from GitHub:

![C# Launcher — Login Success](../Design/Screenshots/screenshot_launcher_login_success.png)

> *Dashboard after login: account name, game library, achievements, and platform count all loaded from the real GitHub data repository*

---

## Screenshots

| 🔐 Login | 🏠 Dashboard |
|---|---|
| ![Login](../Design/Screenshots/screenshot_login.png) | ![Dashboard](../Design/Screenshots/screenshot_dashboard.png) |

| 🎮 My Library | 🛒 Games Store |
|---|---|
| ![Library](../Design/Screenshots/screenshot_library.png) | ![Store](../Design/Screenshots/screenshot_store.png) |

| 🎯 Game Details | 👤 Profile |
|---|---|
| ![Game Detail](../Design/Screenshots/screenshot_gamedetail.png) | ![Profile](../Design/Screenshots/screenshot_profile.png) |

| 👥 Friends | 🔍 Local Game Detection |
|---|---|
| ![Friends](../Design/Screenshots/screenshot_friends.png) | ![Detected on Drive](../Design/Screenshots/screenshot_library_detected.png) |

---

## Features

| Screen | What it does |
|---|---|
| 🔐 **Login / Register** | Dark-themed sign-in form; **Remember me** caches your session token between launches (same as the website) |
| 🏠 **Dashboard / Home** | Stats tiles, featured game hero banner, recently-added game cards, recent achievements |
| 🎮 **My Library** | Game cover cards loaded from the cloud, platform filter chips, search bar, star ratings |
| 🎯 **Game Details** | Full-screen overlay with cover art, description, rating, screenshots carousel, play button |
| 🛒 **Games Store** | Featured titles carousel, browse all, genre filter, search, one-click add to library |
| 👥 **Friends** | Live friend list with online/away/offline presence, pending friend requests |
| 👤 **Profile** | Avatar, stats, full achievements list, LIVE / ADMIN badge |
| 🛡️ **Admin Mode** | When logged in as `Admin.GameOS`, a catalog management panel appears in the store |

---

## Quick Start

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download) or later
- A Game.OS account (create one at the [web frontend](../README.md) — same account works in the launcher)

### Run the launcher

```bash
cd GameLauncher
dotnet run -c Release
# → sign in with your Game.OS username and password
```

The launcher connects to the **same private GitHub data repository** as the website — no local
server required.  Sign in with any account you already created on the web frontend.

### Configuration

The launcher reads the following optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `GAMEOS_DATA_REPO_OWNER` | `Koriebonx98` | GitHub owner of the private data repository |
| `GAMEOS_DATA_REPO_NAME` | `Game.OS.Private.Data` | Repository name for user data |
| `GAMEOS_GITHUB_TOKEN` | *(none)* | Fine-grained PAT with Contents read+write access (required only when the data repository is **private**) |

These variables are pre-configured for the default deployment.  You only need to set them if you
are hosting your own data repository.

---

## Account Setup

The launcher shares accounts with the web frontend.  To get started:

1. **Create an account** on the [Game.OS website](../README.md) (or via the in-app register form)
2. **Launch the app** and sign in with the same username and password
3. Your game library, friends list, achievements, and profile are all synced via GitHub

The **Remember me** checkbox saves your session locally so the next launch signs you in automatically
— identical to how the website handles `localStorage` session persistence.

---

## Admin Login

Log in with the admin account (`Admin.GameOS`) to unlock admin features:

- The **Games Store** page shows an **Admin — Catalog Management** panel
- Admin can **Add** new games to the in-store catalog
- Admin can **Remove** games from the catalog

The admin account is created automatically in the GitHub data repository on first web-frontend
launch.  The default password is `GameOS2026` — change it immediately via Account Settings.

---

## How It Connects to the Backend

The launcher calls the **GitHub REST API directly** — the same API calls made by the web frontend
(`script.js`).  No Node.js proxy server is involved:

```
Launcher  →  https://api.github.com/repos/{owner}/{repo}/contents/{path}
Website   →  https://api.github.com/repos/{owner}/{repo}/contents/{path}
```

Data is stored as JSON files in the private data repository:

```
accounts/
  email-index.json          ← email → username mapping
  {username}/
    profile.json            ← credentials + metadata
    games.json              ← game library
    achievements.json       ← achievements list
    friends.json            ← friend usernames
    friend_requests.json    ← incoming requests
    presence.json           ← last-seen timestamp
  messages/
    {user1}_{user2}.json    ← message threads
```

Password hashing uses **PBKDF2-SHA256 with 100,000 iterations** — identical to the website — so
an account created in the browser works in the launcher without any migration.

---

## Build a standalone EXE

```bash
# Windows x64 — produces a single .exe file
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# macOS (Apple Silicon)
dotnet publish -c Release -r osx-arm64 --self-contained true -p:PublishSingleFile=true

# Linux x64
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true
```

The published executable appears in `bin/Release/net8.0/<rid>/publish/`.

---

## Project Structure

```
GameLauncher/
├── Program.cs                  # Entry point (Avalonia bootstrap)
├── App.axaml / App.axaml.cs    # Application-level styles + startup
├── GameOsClient.cs             # Game.OS backend HTTP API client
├── DemoData.cs                 # Static store catalog + game metadata for enrichment
├── Models/Models.cs            # UserProfile, Game, Achievement, FriendEntry, …
├── Styles/
│   └── GameOsStyles.axaml      # Dark Xbox/PS5/Steam theme (colours, cards, buttons)
├── ViewModels/
│   ├── MainViewModel.cs        # Navigation state + session (MVVM root)
│   ├── LoginViewModel.cs       # Sign-in / register logic
│   ├── DashboardViewModel.cs   # Stats, recent games, featured hero
│   ├── LibraryViewModel.cs     # Filter, search, game collection
│   ├── StoreViewModel.cs       # Browse, search, genre filter, add to library, admin panel
│   ├── FriendsViewModel.cs     # Friends list loaded from API with presence status
│   └── ProfileViewModel.cs     # Avatar, stats, achievements
└── Views/
    ├── MainWindow.axaml        # Window shell with left-sidebar navigation
    ├── LoginView.axaml         # Graphical login/register screen
    ├── DashboardView.axaml     # Xbox-style home with hero banner + game tiles
    ├── LibraryView.axaml       # Game cover card grid
    ├── StoreView.axaml         # Store with featured carousel + catalogue + admin panel
    └── ProfileView.axaml       # Profile card + achievements list
```

---

## Design

- **Background**: `#0d1117` (GitHub dark / Xbox One dark)  
- **Accent**: `#1f6feb` (GitHub blue / Xbox-style blue)  
- **Success**: `#238636` (green — PS5 / Xbox add-to-library)  
- **Cards**: Rounded 10-12px, dark `#161b22` with hover lift  
- **Typography**: Inter / Segoe UI — bold headings, muted metadata
