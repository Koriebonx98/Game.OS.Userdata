# 🎮 Game OS Desktop Application

A cross-platform C# desktop application that replicates all the key functionality of the **Game OS** web platform. Built with **Avalonia UI** and **.NET 8+**, it runs locally on Windows, macOS, and Linux without requiring any server or internet connection.

## 📸 Screenshots

### Home Page
![Home Page](https://github.com/user-attachments/assets/3709fd7b-cd6a-4a03-b197-ff136f81c9b4)
*Welcome screen with hero section, player count, and feature cards*

### Browse Games
![Browse Games](https://github.com/user-attachments/assets/18124835-31f0-429a-af3b-c9ef7a9b7013)
*Multi-platform game browser with Add to Library and Wishlist buttons*

### Sign In
![Sign In](https://github.com/user-attachments/assets/ed5fd95a-0781-483c-86b8-7d17719fb04e)
*Authentication form — supports both username and email login*

### Create Account
![Create Account](https://github.com/user-attachments/assets/0b0eaf59-b538-4e5e-be31-f0aa6005b410)
*Registration form with username, email, password, and terms acceptance*

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 **Secure Authentication** | PBKDF2-SHA256 password hashing (100 000 iterations) matching the web app |
| 🎮 **Game Library** | Browse 27 built-in games across 7 platforms; add/remove from your personal library |
| ⭐ **Wishlist** | Mark games you want to own; dedicated Wishlist tab |
| 👥 **Friends System** | Send, accept, decline, and cancel friend requests; manage your friends list |
| 📬 **Inbox** | View and act on incoming friend requests with Accept / Decline buttons |
| ⚙️ **Account Settings** | Update email and password; generate, view, copy, and revoke API tokens |
| 👤 **User Profiles** | View any user's public game library grouped by platform |
| 💾 **Local Storage** | All data stored in `~/.gameos/` as JSON files — no server or internet required |
| 🔑 **API Tokens** | Generate `gos_<user>.<hex>` tokens compatible with the web app's backend API |

---

## 🗂️ Project Structure

```
GameOS.Desktop/
├── Models/
│   ├── User.cs               # User profile data
│   ├── Game.cs               # Game entity (platform, title, cover)
│   ├── FriendRequest.cs      # Incoming / outgoing friend request
│   ├── Message.cs            # Direct message
│   └── Achievement.cs        # Game achievement
│
├── Services/
│   ├── DataService.cs        # JSON file I/O (~/.gameos/)
│   ├── AuthService.cs        # Signup, login, PBKDF2 hashing, API tokens
│   ├── GameService.cs        # Library, wishlist, built-in game catalogue
│   ├── FriendService.cs      # Friend requests & friends list
│   └── MessageService.cs     # Direct messaging
│
├── ViewModels/
│   ├── MainWindowViewModel.cs  # Navigation hub & user session
│   ├── HomeViewModel.cs        # Hero section, player count
│   ├── LoginViewModel.cs       # Sign-in form logic
│   ├── SignupViewModel.cs      # Registration form logic
│   ├── GamesViewModel.cs       # Browse / Library / Wishlist tabs
│   ├── FriendsViewModel.cs     # Friends list, add friend, requests
│   ├── InboxViewModel.cs       # Incoming requests
│   ├── AccountViewModel.cs     # Profile update, API token management
│   ├── ProfileViewModel.cs     # Public user profile
│   ├── NavigationService.cs    # Navigation helper
│   └── Converters.cs           # Value converters for AXAML bindings
│
├── Views/
│   ├── MainWindow.axaml        # Shell with top nav bar
│   ├── HomeView.axaml          # Landing / welcome page
│   ├── LoginView.axaml         # Sign-in form
│   ├── SignupView.axaml        # Registration form
│   ├── GamesView.axaml         # Game browser (3 tabs)
│   ├── FriendsView.axaml       # Friends management
│   ├── InboxView.axaml         # Notification inbox
│   ├── AccountView.axaml       # Account settings
│   └── ProfileView.axaml       # User profile viewer
│
├── screenshots/                # App screenshots
├── App.axaml                   # Application resources & theme
├── Program.cs                  # Entry point
└── GameOS.Desktop.csproj       # Project file
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| UI Framework | [Avalonia UI 11](https://avaloniaui.net/) — cross-platform WPF-like XAML UI |
| MVVM | [CommunityToolkit.Mvvm](https://learn.microsoft.com/en-us/dotnet/communitytoolkit/mvvm/) with source-generated commands & properties |
| Styling | Avalonia Fluent theme — custom dark colour palette |
| Fonts | Inter (via `Avalonia.Fonts.Inter`) |
| Serialisation | `System.Text.Json` (built into .NET) |
| Cryptography | `System.Security.Cryptography.Rfc2898DeriveBytes` (PBKDF2-SHA256) |
| Target Framework | .NET 8 or newer |

---

## 🚀 Getting Started

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download) or newer

### Build & Run

```bash
# Clone the repo (if not already done)
git clone https://github.com/Koriebonx98/Game.OS.Userdata.git
cd Game.OS.Userdata/GameOS.Desktop

# Restore dependencies
dotnet restore

# Run in development mode
dotnet run

# Build a release binary
dotnet build -c Release
```

The compiled binary will be in `bin/Release/net8.0/`.

### First Run

1. Launch the app — the home page is shown by default.
2. Click **Get Started** or **Sign Up** to create a new account.
3. Fill in a username (≥ 3 chars), email address, and password (≥ 6 chars).
4. After registration you are automatically redirected to the home page.
5. Click **Sign In** and enter your credentials.
6. Once logged in, all features become available.

All data is stored in:
- **Windows**: `C:\Users\<you>\.gameos\`
- **macOS / Linux**: `~/.gameos/`

---

## 📋 Pages & Functionality

### 🏠 Home (`HomeView`)
- Hero banner with "Welcome to Game OS" heading
- Live registered-player count (reads `email-index.json`)
- Feature cards: Secure Accounts, Fast & Local, Multi-Platform
- **Browse Games** and **Sign Up Free** CTAs for guests
- **My Library** CTA when signed in

### 🔐 Login (`LoginView`)
- Username **or** email + password form
- Shows inline error message on bad credentials
- "Sign Up" link navigates to registration
- Session stored in `App.CurrentUser` (in-memory)

### 📝 Sign Up (`SignupView`)
- Username, email, password, confirm password fields
- Terms acceptance checkbox
- Real-time validation:
  - Username ≥ 3 characters
  - Valid email format
  - Password ≥ 6 characters
  - Passwords must match
- Duplicate username and email detection

### 🎮 Games (`GamesView`) — 3 tabs

**Browse tab**
- Platform filter: All, PC, PS3, PS4, PS5, Switch, Xbox 360, Xbox One
- Live search across all game titles
- Game cards show title, platform badge, and action buttons:
  - **+ Library** — add to your library (turns to "✓ In Library" when added)
  - **♡ Wishlist** — add to wishlist (turns to "♥ Wishlisted" when added)

**My Library tab** (requires sign-in)
- All owned games grouped by platform with counts
- **Remove** button on each game

**Wishlist tab** (requires sign-in)
- All wishlisted games grouped by platform
- **Remove** button on each game

### 👥 Friends (`FriendsView`)
- **Add Friend** — search by username; sends a friend request
- **Incoming Requests** — Accept ✓ or Decline ✗ any request
- **My Friends** — list of accepted friends with View Profile and Remove buttons
- **Sent Requests** — pending outgoing requests with Cancel button

### 📬 Inbox (`InboxView`)
- Shows all incoming friend requests
- Accept / Decline inline
- Red badge on "Inbox" nav item showing unread count
- Empty-state message when no pending items

### ⚙️ Account (`AccountView`)
- **Account info card**: avatar initials, username, email, member since
- **Update form**: change email or password (current password required)
- **API Token section**:
  - Generate a `gos_<username>.<hex>` token (matches web app format)
  - Show / Hide token toggle
  - Regenerate or Revoke
  - C# usage example shown when a token is active

### 👤 Profile (`ProfileView`)
- Displays any user's public game library
- Stats row: total games, platforms, wishlist count, last active
- Games grouped by platform

---

## 💾 Data Storage

All data is stored as JSON files under `~/.gameos/`:

```
~/.gameos/
└── accounts/
    ├── email-index.json          # email → username mapping
    └── <username>/
        ├── profile.json          # User account + password hash + API token hash
        ├── library.json          # [ { platform, title, addedAt } ]
        ├── wishlist.json         # [ { platform, title, addedAt } ]
        ├── friends.json          # [ "alice", "bob" ]
        ├── friend-requests.json  # [ { from, sentAt } ]
        ├── sent-requests.json    # [ { from, sentAt } ]
        └── conversations/
            └── alice_bob.json    # [ { from, text, sentAt } ]
```

This layout is intentionally identical to the web app's GitHub-repository layout, so data files are fully interoperable.

---

## 🔑 API Token Integration

Tokens generated in the desktop app use the same `gos_<username>.<random_hex>` format as the web backend. You can use them to authenticate against a running instance of the Node.js backend (`backend/index.js`):

```csharp
// Example: call the Game OS backend API
var client = new HttpClient();
client.DefaultRequestHeaders.Authorization =
    new AuthenticationHeaderValue("Bearer", "gos_alice.a1b2c3d4e5f6...");

var resp = await client.GetAsync("http://localhost:3000/api/me");
var json = await resp.Content.ReadAsStringAsync();
```

---

## 🎨 Design / Colour Palette

| Token | Hex | Usage |
|---|---|---|
| App Background | `#1a1a2e` | Main window background |
| Card Background | `#16213e` | Panels and form cards |
| Card Background 2 | `#0f3460` | Input fields, nested cards |
| Nav Background | `#0d0d1a` | Top navigation bar |
| Accent | `#e94560` | Primary buttons, highlights |
| Secondary | `#533483` | Secondary buttons, badges |
| Muted Text | `#8899aa` | Labels, captions |
| Success | `#27ae60` | Confirmation states |
| Danger | `#e74c3c` | Destructive actions |

---

## 🔒 Security Notes

- Passwords are **never stored in plain text**. They are hashed with PBKDF2-SHA256 (100 000 iterations, username as salt) — the same algorithm used by the web frontend.
- API tokens are stored as plain strings in the local profile file. Protect `~/.gameos/` with filesystem permissions on shared machines.
- No data is ever sent over the network in demo/local mode.

---

## 🤝 Extending the App

Because the ViewModel layer is cleanly separated from the data layer, you can swap `DataService` for a GitHub API-backed implementation (as described in `Game OS API.txt`) without touching any View or ViewModel code. Simply replace the file-read/write calls in each service with the corresponding `GET`/`PUT` calls to the GitHub Contents API.
