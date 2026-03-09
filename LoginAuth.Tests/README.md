# LoginAuth.Tests — Login Authentication Verification

A lightweight console application that proves the **C# launcher login is identical to the web
frontend login** — same PBKDF2-SHA256 algorithm, same salt, same bcrypt fallback.

Run this to verify the launcher will accept any account created on the website.

## What it tests

| # | Test | What it proves |
|---|------|----------------|
| 1 | **PBKDF2 Hash Parity** | C# `HashPassword()` produces the exact same hex string as JavaScript `hashPassword()` in `script.js`, verified against Node.js reference vectors |
| 2 | **Salt Case-Insensitivity** | `hash("Koriebonx98") == hash("koriebonx98") == hash("KORIEBONX98")` — username is lowercased before salt construction, matching the JS behaviour |
| 3 | **Bcrypt Hash Detection** | Accounts created via the Node.js backend store bcrypt hashes; the launcher correctly routes to `BCrypt.Net.BCrypt.Verify()` |
| 4 | **Dual-Hash Login Flow** | Both PBKDF2 (web-created accounts) and bcrypt (backend-created accounts) accept correct passwords and reject wrong ones |
| 5 | **Live Backend (optional)** | Connects to the real GitHub data repo and logs in with a real account — skipped gracefully when no PAT is available |

## Test output

![Login Auth Tests — all 14 checks pass](https://github.com/user-attachments/assets/14f91c83-3d3b-49ee-8952-402666294cce)

## How to run

```bash
# From the repo root:
cd LoginAuth.Tests
dotnet run

# With real backend login:
GAMEOS_GITHUB_TOKEN=<your_PAT> \
GAMEOS_TEST_USERNAME=<username> \
GAMEOS_TEST_PASSWORD=<password> \
dotnet run
```

Or open `Game.OS.Userdata.sln` in Visual Studio 2022+ and run the `LoginAuth.Tests` project.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | One or more checks failed |
