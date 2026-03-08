# Game.OS Launcher — Graphical PC App

A **graphical Windows/Linux/macOS PC game launcher** for Game.OS — designed like  
**Xbox Dashboard / PlayStation 5 / Steam Big Picture / Playnite**.

Built with **.NET 8** + [Avalonia UI](https://avaloniaui.net/) (cross-platform WPF-style GUI).

---

## Screenshots

| Login | Dashboard |
|---|---|
| ![Login](../Design/Screenshots/screenshot_login.png) | ![Dashboard](../Design/Screenshots/screenshot_dashboard.png) |

| My Library | Games Store |
|---|---|
| ![Library](../Design/Screenshots/screenshot_library.png) | ![Store](../Design/Screenshots/screenshot_store.png) |

---

## Features

| Screen | What it does |
|---|---|
| 🔐 **Login / Register** | Dark-themed sign-in form with Game.OS logo; graphical register form with validation |
| 🏠 **Dashboard / Home** | Stats tiles, featured game hero banner, game card grid, recent achievements |
| 🎮 **My Library** | Game cover cards, platform filter chips, search, star ratings |
| 🛒 **Games Store** | Featured titles carousel, browse all, genre filter, search, add to library |
| 👤 **Profile** | Avatar, stats, all achievements list |
| 🚀 **Demo Mode** | One click — no GitHub account needed, built-in library of 8 games |

---

## Quick Start

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download) or later

### Run on any platform

```bash
cd GameLauncher
dotnet run -c Release
```

> On the login screen choose **🚀 Try Demo Mode** — no setup required.

### Run in Live Mode (reads/writes your real Game.OS data)

```bash
export GAMEOS_PAT="ghp_yourTokenHere"
cd GameLauncher
dotnet run -c Release
```

See **`Game OS API.txt`** in the repo root for full PAT setup instructions.

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
├── GameOsClient.cs             # GitHub REST API client (live + demo mode)
├── DemoData.cs                 # Built-in games, store & achievements (no credentials)
├── Models/Models.cs            # UserProfile, Game, Achievement, StoreGame, …
├── Styles/
│   └── GameOsStyles.axaml      # Dark Xbox/PS5/Steam theme (colours, cards, buttons)
├── ViewModels/
│   ├── MainViewModel.cs        # Navigation state + session (MVVM root)
│   ├── LoginViewModel.cs       # Sign-in / register / demo logic
│   ├── DashboardViewModel.cs   # Stats, recent games, featured hero
│   ├── LibraryViewModel.cs     # Filter, search, game collection
│   ├── StoreViewModel.cs       # Browse, search, genre filter, add to library
│   └── ProfileViewModel.cs     # Avatar, stats, achievements
└── Views/
    ├── MainWindow.axaml        # Window shell with left-sidebar navigation
    ├── LoginView.axaml         # Graphical login/register screen
    ├── DashboardView.axaml     # Xbox-style home with hero banner + game tiles
    ├── LibraryView.axaml       # Game cover card grid
    ├── StoreView.axaml         # Store with featured carousel + catalogue
    └── ProfileView.axaml       # Profile card + achievements list
```

---

## Design

- **Background**: `#0d1117` (GitHub dark / Xbox One dark)  
- **Accent**: `#1f6feb` (GitHub blue / Xbox-style blue)  
- **Success**: `#238636` (green — PS5 / Xbox add-to-library)  
- **Cards**: Rounded 10-12px, dark `#161b22` with hover lift  
- **Typography**: Inter / Segoe UI — bold headings, muted metadata
