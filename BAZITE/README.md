# Game.OS Custom Bazzite Image

A **custom Bazzite OCI image** with the **Game.OS Launcher pre-installed** — ready to use on first boot, no post-install steps needed.

Built on top of [`ghcr.io/ublue-os/bazzite:latest`](https://github.com/ublue-os/bazzite) (Universal Blue / immutable Fedora).

---

## What's included

| Addition | Details |
|---|---|
| `dotnet-runtime-8.0` | Required by the Avalonia-based Game.OS Launcher |
| `GameLauncher` binary | Pre-built Linux x64 binary from the latest GitHub Release, placed in `/usr/local/bin/` |
| `gameos-token.dat` | XOR-encoded `DATA_REPO_TOKEN` — same encoding as the website and Windows launcher |
| `gameos-backend.url` | Backend server URL (optional) — baked in if `GAMEOS_BACKEND_URL` secret is set |
| `.desktop` entry | Registers the launcher in the GNOME / KDE application menu |

---

## Build the image / ISO

Go to **Actions → Build Bazzite Image → Run workflow** in this repository.

| Input | Default | Description |
|---|---|---|
| `build_iso` | `false` | Also generate a bootable `.iso` (takes ~25 min extra) |
| `image_tag` | `latest` | Tag to push to `ghcr.io` |

### Required secrets

| Secret | Purpose |
|---|---|
| `DATA_REPO_TOKEN` | Fine-grained PAT — Contents read+write on `Game.OS.Private.Data`. Same secret used by `deploy.yml` and `release-launcher.yml`. |
| `GAMEOS_BACKEND_URL` | *(optional)* Deployed backend URL. If set, the launcher connects via REST API instead of GitHub-direct mode. |

---

## How the build works

```
bazzite-build.yml
│
├── 1. Download GameOS-Launcher-linux-x64.tar.gz from latest GitHub Release
│        → extracts binary to BAZITE/build_files/GameLauncher
│
├── 2. XOR-encode DATA_REPO_TOKEN with key "GameOS_KEY"
│        → writes to BAZITE/build_files/gameos-token.dat
│
├── 3. Write GAMEOS_BACKEND_URL (if set)
│        → writes to BAZITE/build_files/gameos-backend.url
│
├── 4. docker buildx build -f BAZITE/Containerfile BAZITE/
│        Containerfile layers:
│          FROM ghcr.io/ublue-os/bazzite:latest
│          RUN  rpm-ostree install dotnet-runtime-8.0
│          COPY binary + config files → /usr/local/bin/
│          COPY .desktop entry + icon → /usr/share/...
│
├── 5. Push OCI image to ghcr.io/<owner>/game-os-bazzite:latest
│
└── 6. (if build_iso=true) jasonn3/build-container-installer
         → produces Game-OS-Bazzite-x86_64.iso as a workflow artifact
```

---

## After flashing the ISO

1. Boot from the USB / install as normal Bazzite
2. On first login, open the **application menu** and search for **"Game.OS Launcher"**
3. Sign in with your Game.OS username and password — same account as the website

No additional setup required.

---

## Folder structure

```
BAZITE/
├── Containerfile                                   ← OCI image definition
├── README.md                                       ← this file
├── build_files/
│   ├── GameLauncher                                ← injected by CI (not committed)
│   ├── gameos-token.dat                            ← empty placeholder; CI writes XOR-encoded token
│   └── gameos-backend.url                          ← empty placeholder; CI writes backend URL
└── files/
    └── usr/
        └── share/
            ├── applications/
            │   └── gameos-launcher.desktop          ← app menu entry
            └── icons/hicolor/256x256/apps/
                └── gameos-launcher.png              ← injected by CI from release tarball
```

The `GameLauncher` binary and icon are **never committed** to this repository.
They are downloaded from the latest GitHub Release during the CI build.
