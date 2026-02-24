# Game.OS.Userdata 🎮

**A full-featured Gaming Hub for Game OS**

A modern, secure web application with account registration, login, a multi-platform game library, a friends system, inbox, user profiles, and API token support. Works in demo mode (browser localStorage) right out of the box, with optional GitHub repository-based storage for production use.

## 📋 Table of Contents

- [Features](#features)
- [Pages](#pages)
- [Demo Mode](#demo-mode)
- [GitHub Repository Integration](#github-repository-integration)
- [Screenshots](#screenshots)
- [Setup Instructions](#setup-instructions)
- [Usage](#usage)
- [Security Considerations](#security-considerations)

## ✨ Features

- **🔐 Secure Registration**: Create accounts with username, email, and password
- **✅ Login Authentication**: Sign in with username or email
- **🎮 Demo Mode**: Works immediately with browser localStorage (no backend required)
- **📦 GitHub Integration**: Optional integration with private GitHub repository for data storage
- **🔒 Password Validation**: Enforces minimum password requirements
- **⚡ Real-time Feedback**: Instant validation and user-friendly error messages
- **📱 Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices
- **🌐 Session Management**: Remember me functionality and logout support
- **🕹️ Game Library**: Browse multi-platform game databases and track your owned games
- **👥 Friends System**: Send friend requests, manage friends, and see shared games
- **📬 Inbox**: Receive and respond to friend requests and notifications
- **👤 Account Management**: Update email and password from a dedicated account page
- **🔑 API Token**: Generate personal API tokens for use with C# or other external apps
- **🧑‍🤝‍🧑 User Profiles**: View any user's public game library

## 🗂️ Pages

| Page | File | Description |
|---|---|---|
| Home | `index.html` | Welcome page, hero section, feature cards, live user count |
| Browse Games | `games.html` | Browse multi-platform game database; add/remove games from your library |
| My Library | `games.html?tab=library` | View your owned games grouped by platform |
| Friends | `friends.html` | Search for users, send/accept/decline friend requests, view friends list |
| Inbox | `inbox.html` | Pending friend requests and unread notifications |
| My Account | `account.html` | Update email/password, manage API token, admin danger zone |
| User Profile | `profile.html?user=<username>` | Public view of any user's game library |
| Sign Up | `signup.html` | Account registration form |
| Login | `login.html` | Sign-in form |

## 🎮 Demo Mode

The system includes a built-in demo mode that uses browser localStorage to simulate a backend. This allows you to test and use the account system immediately without any server setup.

### Demo Mode Features:
- ✓ Accounts stored in browser localStorage
- ✓ Full registration and login functionality
- ✓ Password validation and security checks
- ✓ Duplicate username/email detection
- ✓ Session management with "Remember me" option

### Testing Demo Mode:

The demo mode is **currently active** and ready to use. Simply:
1. Open `index.html` in your web browser
2. Click "Sign Up" to create an account
3. Fill in your details and submit
4. Login with your credentials

## 📦 GitHub Repository Integration

For production use, this system stores user account data directly in a private GitHub repository — no external server required.  The frontend (GitHub Pages) calls the GitHub REST API directly using a fine-grained Personal Access Token injected at deploy time.

### How It Works:

1. **Account Creation**: The browser calls the GitHub API directly to write a JSON file for the new account
2. **Data Storage**: User data is stored as JSON files in a private repository (one folder per user)
3. **Authentication**: Login reads the stored PBKDF2 password hash and compares it locally — no server involved
4. **Security**: All data in a private repository; the PAT is XOR-encoded so GitHub's secret scanner cannot auto-revoke it

### Integration Steps:

1. **Create the private data repository** at [github.com/new](https://github.com/new) → set to **Private**

2. **Add a fine-grained PAT as a repository secret** named `DATA_REPO_TOKEN`
   (Settings → Secrets and variables → Actions → New repository secret)

3. **Enable GitHub Pages** (Settings → Pages → Source → GitHub Actions)

4. **Push to main** — the deploy workflow injects the token and publishes the site

See the **Going Live** section below for the full step-by-step guide.

## 📸 Screenshots

### 1. Homepage
![Homepage](https://github.com/user-attachments/assets/90137b0e-72e4-4579-b268-3aaade8e8c58)
*Welcome page with demo mode active*

### 2. Account Registration
![Signup Page](https://github.com/user-attachments/assets/0effd3c6-63c5-4976-8750-6cb78260284b)
*User registration form*

![Signup Filled](https://github.com/user-attachments/assets/acbe478e-0918-44f5-addb-abe53e4eaf4e)
*Registration form with test data*

![Signup Success](https://github.com/user-attachments/assets/b018846b-9125-455e-8bd0-f259b6b903d8)
*Successful account creation*

### 3. Login Process
![Login Page](https://github.com/user-attachments/assets/f199b5b6-e880-4496-bc8e-ff1c5a07652f)
*Sign in page*

![Login Success](https://github.com/user-attachments/assets/81714511-3e1c-4c28-813e-351dbd351d85)
*Successful login confirmation*

![Logged In](https://github.com/user-attachments/assets/f085f1b6-d4a1-4c74-b0c3-432a427ebbc1)
*Homepage showing logged-in user*

### 4. Security - Incorrect Password
![Wrong Password](https://github.com/user-attachments/assets/90e6d31b-3328-4e23-983a-9f23ec78cf5f)
*Login attempt with incorrect password*

![Error Message](https://github.com/user-attachments/assets/8158e6dd-d029-41c5-8547-a9647ea58bb3)
*Error message displayed for invalid credentials*

## 🚀 Going Live (Real Accounts – GitHub Direct Mode)

No external server is needed. The frontend calls the GitHub API directly using a fine-grained PAT
stored as a **repository secret**. The deploy workflow **XOR-hex-encodes** the token before placing
it in `script.js`, so GitHub's secret scanning does not auto-revoke it.

| Component | Role |
|---|---|
| `Game.OS.Userdata` (this repo, public) | Frontend – HTML/CSS/JS served via GitHub Pages |
| `Game.OS.Private.Data` (your private repo) | Data store – one JSON file per user account |

### One-time Setup

**Step 1 – Create the private data repository**

1. Go to [github.com/new](https://github.com/new)
2. Name it `Game.OS.Private.Data` (or any name you like)
3. Set it to **Private**
4. Click **Create repository**

**Step 2 – Create a fine-grained Personal Access Token**

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Click **Generate new token**
3. Give it a name (e.g. `Game OS Data Repo`)
4. Under **Repository access**, select **Only select repositories** → your private data repo
5. Under **Repository permissions → Contents**, set to **Read and write**
6. Click **Generate token** and **copy it** — you only see it once!

**Step 3 – Add the token as a repository secret**

In the `Game.OS.Userdata` repository (this repo):

1. Go to **Settings → Secrets and variables → Actions**
2. Click **New repository secret**
3. Name: `DATA_REPO_TOKEN`
4. Value: the PAT you just copied
5. Click **Add secret**

**Step 4 – (Optional) Set the data repository name**

If your data repo is named something other than `Game.OS.Private.Data`:

1. Go to **Settings → Secrets and variables → Actions → Variables**
2. Click **New repository variable**
3. Name: `DATA_REPO_NAME`, Value: your repo name

**Step 5 – Set GitHub Pages source to "GitHub Actions"**

1. Go to **Settings → Pages**
2. Under **Source** select **GitHub Actions**

**Step 6 – Trigger the deploy**

Push any commit to `main` (or go to **Actions → Deploy to GitHub Pages → Run workflow**).  
The deploy workflow will:
- XOR-hex-encode your `DATA_REPO_TOKEN` and inject it into `script.js` at build time
- Deploy the frontend to GitHub Pages

> ⚠️ **If the site falls back to demo mode after deploying**, it usually means the
> `DATA_REPO_TOKEN` secret is expired or invalid (you will see HTTP 401 in the
> "Validate GitHub data repository access" step in the deploy log). To fix:
> 1. Generate a **new** fine-grained PAT (Step 2 above)
> 2. Update the `DATA_REPO_TOKEN` secret (Step 3 above)
> 3. Re-run the deploy workflow

Your site is now live with real accounts! ✅

**Step 7 – (Optional) Enable Admin game editing (covers & trailers)**

The `Admin.GameOS` account can update game covers and trailers directly from the browser,
and can dispatch server-side workflows ("🔄 Scrape JSON", "🔄 Update Steam Games").
This requires a second PAT with write access to **`Koriebonx98/Games.Database`** and
Actions access to **`Koriebonx98/Game.OS.Userdata`**.

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Click **Generate new token**
3. Give it a name (e.g. `Game OS Games DB`)
4. Under **Repository access**, select **Only select repositories** →
   add both `Koriebonx98/Games.Database` **and** `Koriebonx98/Game.OS.Userdata`
5. Under **Repository permissions → Contents** (for `Games.Database`), set to **Read and write**
6. Under **Repository permissions → Actions** (for `Game.OS.Userdata`), set to **Read and write**
   *(required so the admin panel can dispatch the "Scrape JSON" and "Update Steam Games" workflows)*
7. Click **Generate token** and **copy it**
8. In this repository go to **Settings → Secrets and variables → Actions**
9. Click **New repository secret**
10. Name: `GAMES_DB_TOKEN`
11. Value: the PAT you just copied
12. Click **Add secret**
13. Re-run (or push to `main`) to trigger a fresh deploy

> Without this secret the admin game-editing panel will show:
> *"⚠️ GAMES_DB_TOKEN is not configured. Add it as a repository secret and re-deploy to enable editing."*
>
> If the token is set but **Actions: Read and write** is missing on `Game.OS.Userdata`, the
> "🔄 Scrape JSON" and "🔄 Update Steam Games" buttons will show:
> *"Token lacks Actions write permission on this repository. Update GAMES_DB_TOKEN to include
> Actions: Read and write on Koriebonx98/Game.OS.Userdata, then re-deploy."*

### How it works (architecture)

```
User's Browser
    │
    ├── Signup:  PUT  https://api.github.com/repos/Owner/Game.OS.Private.Data/contents/accounts/...
    │                 (uses the injected token decoded from GITHUB_TOKEN_ENCODED)
    │
    └── Login:   GET  https://api.github.com/repos/Owner/Game.OS.Private.Data/contents/accounts/...
                      (reads and verifies PBKDF2-hashed password)
```

The PAT is stored only in `DATA_REPO_TOKEN` (a repository secret – never visible in logs or files).
It is XOR-hex-encoded in the deployed `script.js` so the raw token is never present in any file.

### Security notes

- The GitHub PAT is stored as a **repository secret** – only Actions runners can read it
- The token is **XOR-hex-encoded** before injection, preventing GitHub's secret scanning from auto-revoking it
- Passwords are hashed client-side with PBKDF2 (100,000 iterations) before storage
- If a token is ever compromised or expires, revoke and regenerate it at github.com/settings/tokens, then update the `DATA_REPO_TOKEN` secret and redeploy

---

## 🚀 Setup Instructions

### Local Development:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Koriebonx98/Game.OS.Userdata.git
   cd Game.OS.Userdata
   ```

2. **Start a local web server**:
   ```bash
   # Using Python
   python3 -m http.server 8080
   
   # OR using Node.js
   npx http-server -p 8080
   ```

3. **Open in browser**:
   ```
   http://localhost:8080
   ```

4. **Test the system**:
   - Create a test account
   - Login with your credentials
   - Test incorrect password handling
   - Verify logout functionality

### Production Deployment:

1. **GitHub Pages** (frontend — free, no server needed):
   - Follow the **Going Live** section above
   - Add the `DATA_REPO_TOKEN` secret, enable GitHub Pages, push to main
   - Access at: `https://koriebonx98.github.io/Game.OS.Userdata/`

## 📖 Usage

### Creating an Account:

1. Navigate to the homepage
2. Click "Sign Up" or "Get Started"
3. Fill in the registration form:
   - Username (minimum 3 characters)
   - Email address
   - Password (minimum 6 characters)
   - Confirm password
4. Agree to Terms and Conditions
5. Click "Create Account"
6. Wait for confirmation and automatic redirect to login

### Logging In:

1. Navigate to the login page
2. Enter your username or email
3. Enter your password
4. Optional: Check "Remember me" for persistent session
5. Click "Login"
6. You'll be redirected to the homepage upon success

### Account Management:

- **View Account**: Your username is displayed on the homepage when logged in
- **Logout**: Click the "Logout" button to end your session
- **Session Persistence**: Use "Remember me" during login to stay logged in

## 🔒 Security Considerations

### Current Implementation:

- ✅ Client-side validation (username length, email format, password strength)
- ✅ Password confirmation matching
- ✅ Duplicate username/email detection
- ✅ Session management with localStorage/sessionStorage
- ✅ **Demo mode uses SHA-256 password hashing** (basic client-side protection)
- ⚠️ **Demo mode is still for testing only** (client-side hashing not production-grade)

### For Production:

When integrating with the GitHub repository backend:

1. **Password Hashing**: Passwords should be hashed using bcrypt or similar
2. **HTTPS Only**: Always use HTTPS in production
3. **Token-based Auth**: Implement JWT or similar for session management
4. **Rate Limiting**: Add rate limiting to prevent brute-force attacks
5. **Input Sanitization**: Validate and sanitize all user inputs on the backend
6. **Private Repository**: Ensure the data repository remains private
7. **Access Control**: Restrict GitHub token permissions to minimum required

### Demo Mode Security Notice:

⚠️ **Important**: Demo mode is for testing and demonstration purposes only. While it uses SHA-256 hashing for basic password protection, client-side hashing is **NOT production-grade security**. 

**Why Demo Mode is Not Production-Ready:**
- Hashing happens in browser (visible in dev tools)
- No salt used (vulnerable to rainbow table attacks)
- No rate limiting (vulnerable to brute force)
- Data stored in localStorage (accessible to any script on the page)

**For Production**: Use the GitHub repository backend with server-side bcrypt hashing as documented in GITHUB_INTEGRATION.md.

## 🛠️ Technical Stack

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Styling**: Custom CSS with responsive design
- **Storage**: Browser localStorage (demo mode) / GitHub Repository (production)
- **Backend** (optional): Node.js with GitHub API integration
- **Automation**: GitHub Actions for data management

## 📝 Files Structure

```
Game.OS.Userdata/
├── index.html          # Homepage
├── signup.html         # Registration page
├── login.html          # Login page
├── games.html          # Browse games & My Library
├── friends.html        # Friends list & friend requests
├── inbox.html          # Inbox (friend requests / notifications)
├── account.html        # Account settings & API token management
├── profile.html        # Public user profile / game library view
├── script.js           # Main JavaScript logic
├── styles.css          # Styling and responsive design
├── backend/            # Optional Node.js backend server
│   ├── index.js
│   ├── package.json
│   └── .env.example
├── Design/             # UI design assets
├── GITHUB_INTEGRATION.md  # Production GitHub integration guide
├── QUICKSTART.md       # Quick-start guide
└── README.md           # This file
```

## 🤝 Contributing

This is a private repository. For contributions or issues, please contact the repository owner.

## 📄 License

© 2026 Game OS. All rights reserved.

## 📞 Support

For support or questions, please refer to the main Game OS documentation or contact the development team.

---

**Powered by GitHub Actions & Node.js** 
