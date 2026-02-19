# Game.OS Backend – Optional Alternative Deployment

> **Note:** The primary method for running Game.OS with real accounts is **GitHub-only** (no external server).  
> See the main [README.md](../README.md) for the recommended GitHub Pages + GitHub API setup.  
> The server in this folder is an **optional alternative** for those who prefer a traditional hosted backend (e.g. Railway, Render).

---

# Game.OS Backend – Deployment Guide 🚀

The backend is a small Node.js/Express server that stores user accounts as JSON
files in a **private** GitHub repository.

---

## 1. Prerequisites

| What | Why |
|---|---|
| A **private** GitHub repo for data (e.g. `Game.OS.Private.Data`) | Where account files are stored |
| A GitHub **Personal Access Token** with `repo` scope | Lets the server read/write to that repo |

### Create a Personal Access Token

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)**
2. Click **Generate new token (classic)**
3. Give it a name (e.g. `Game.OS Backend`)
4. Under *Select scopes*, check **`repo`** (Full control of private repositories)
5. Click **Generate token** and copy it — you only see it once!

---

## 2. Deploy to Railway (recommended – free tier available)

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template)

1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click **New Project → Deploy from GitHub repo**
3. Select this repository (`Game.OS.Userdata`) and set the **root directory** to `backend/`
4. Railway will auto-detect Node.js and run `npm start`
5. In the Railway dashboard, open **Variables** and add:

   | Variable | Value |
   |---|---|
   | `GITHUB_TOKEN` | Your personal access token |
   | `REPO_OWNER` | Your GitHub username |
   | `REPO_NAME` | `Game.OS.Private.Data` (or your data repo name) |

6. Copy the **public URL** Railway gives you (e.g. `https://gameos-backend.up.railway.app`)

---

## 3. Deploy to Render (free tier available)

1. Go to [render.com](https://render.com) and sign in with GitHub
2. Click **New → Web Service**
3. Connect this repository, set **Root Directory** to `backend`, **Build Command** to `npm install`, **Start Command** to `npm start`
4. Add environment variables in the Render dashboard (same as above)
5. Copy the public URL Render assigns

---

## 4. Update the frontend

Edit **`script.js`** in the root of this repository:

```js
// Replace this placeholder:
const API_BASE_URL = 'https://your-backend-url.com';

// With your real deployed URL, e.g.:
const API_BASE_URL = 'https://gameos-backend.up.railway.app';
```

Commit and push. GitHub Pages will redeploy automatically. Users can now create
real accounts that persist across all browsers and devices. ✅

---

## 5. Verify it works

```bash
# Health check
curl https://your-backend-url.com/health
# Expected: {"status":"ok","message":"Game.OS backend running"}

# Create a test account
curl -X POST https://your-backend-url.com/api/create-account \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'

# Login
curl -X POST https://your-backend-url.com/api/verify-account \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

---

## Local development

```bash
cd backend
cp .env.example .env        # fill in your token & repo details
npm install
npm run dev                 # starts with nodemon (auto-reload)
# Server running at http://localhost:3000
```

---

## Data structure

Each user gets their own **folder** in the data repo, allowing future per-user files to be added easily:

```
accounts/
├── email-index.json              ← email → username mapping
├── alice/
│   ├── profile.json              ← account details & password hash
│   └── friends.json              ← friend list (array of usernames)
├── bob/
│   ├── profile.json
│   └── friends.json
└── ...
```

`accounts/alice/profile.json` example:

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password_hash": "$2b$10$...",
  "created_at": "2026-02-19T12:00:00.000Z"
}
```

`accounts/alice/friends.json` example:

```json
["bob", "charlie"]
```

Passwords are hashed with **bcrypt** (10 rounds) on the server — plain-text passwords never reach the database.

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Server health check |
| `POST` | `/api/create-account` | Register a new user |
| `POST` | `/api/verify-account` | Login (email or username + password) |
| `POST` | `/api/update-account` | Update email and/or password |
| `GET`  | `/api/check-user?username=` | Check whether a username exists |
| `POST` | `/api/add-friend` | Add a user to your friends list |
| `GET`  | `/api/get-friends?username=` | Retrieve a user's friends list |
| `POST` | `/api/remove-friend` | Remove a user from your friends list |
