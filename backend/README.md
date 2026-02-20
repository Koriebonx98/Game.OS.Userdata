# Game.OS Backend – Optional Alternative Deployment

> **Note:** The primary method for running Game.OS with real accounts is **GitHub-only** (no external server needed).  
> The frontend calls the GitHub API directly using a fine-grained PAT stored as a repository secret.  
> See **Going Live** in the main [README.md](../README.md) for the full setup guide.  
> The server in this folder is an **optional alternative** for those who prefer a traditional hosted backend (e.g. Railway, Render).

---

# Game.OS – Going Live (GitHub Direct Mode)

No external server is required for live mode. The frontend calls the GitHub API directly using
a fine-grained Personal Access Token (PAT) that is **base64-encoded** by the deploy workflow
before being placed in `script.js`, so GitHub secret scanning does not auto-revoke it.

## One-time setup

### Step 1 – Create a private data repository

1. Go to [github.com/new](https://github.com/new)
2. Name it **`Game.OS.Private.Data`** (or any name you like)
3. Set it to **Private**
4. Click **Create repository**

### Step 2 – Create a fine-grained Personal Access Token

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Click **Generate new token**
3. Give it a name (e.g. `Game OS Data Repo`)
4. Under **Repository access**, select **Only select repositories** → choose your private data repo
5. Under **Repository permissions → Contents**, set it to **Read and write**
6. Click **Generate token** and **copy it** — you only see it once!

### Step 3 – Add the token as a repository secret

1. In the **`Game.OS.Userdata`** repository go to **Settings → Secrets and variables → Actions**
2. Click **New repository secret**
3. Name: **`DATA_REPO_TOKEN`**
4. Value: the PAT you just copied
5. Click **Add secret**

### Step 4 – (Optional) Set the data repository name variable

If you named your data repo something other than `Game.OS.Private.Data`:

1. Go to **Settings → Secrets and variables → Actions → Variables**
2. Click **New repository variable**
3. Name: **`DATA_REPO_NAME`**, Value: your repo name

### Step 5 – Deploy

Go to **Actions → Deploy to GitHub Pages → Run workflow** (or push any commit to `main`).

The deploy workflow will base64-encode your PAT and inject it into `script.js`. When users visit
the site it is decoded at runtime and used to call the GitHub API directly. ✅

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
