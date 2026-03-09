using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher
{
    /// <summary>
    /// Game.OS API client.  Supports two authentication modes:
    ///
    /// 1. <b>Backend mode</b> (preferred — no GitHub PAT required)
    ///    When <c>GAMEOS_BACKEND_URL</c> is set, all calls go through the Node.js
    ///    backend REST API — exactly the same way the web frontend calls the backend.
    ///    The backend holds the GitHub PAT; users log in with just username+password.
    ///    Set the env var to the deployed backend URL, e.g.:
    ///      GAMEOS_BACKEND_URL=https://gameos.up.railway.app
    ///
    /// 2. <b>GitHub-direct mode</b> (fallback — requires a bundled GitHub PAT)
    ///    When <c>GAMEOS_BACKEND_URL</c> is NOT set the launcher calls the GitHub
    ///    API directly, mirroring the web frontend's GitHub-direct path.
    ///    Requires <c>GAMEOS_GITHUB_TOKEN</c> env var or a valid <c>gameos-token.dat</c>.
    /// </summary>
    public sealed class GameOsClient : IDisposable
    {
        private static readonly string AdminUsername = "Admin.GameOS";

        // One of these will be non-null depending on which mode is active.
        private readonly BackendApiService?  _backend;
        private readonly GitHubDataService?  _github;

        private string? _username;
        private string? _bearerToken;   // set in backend mode after login

        /// <summary>The currently logged-in username, or <c>null</c> if not authenticated.</summary>
        public string? LoggedInUser => _username;

        /// <summary>True once the user has authenticated.</summary>
        public bool IsAuthenticated => _username != null;

        /// <summary>
        /// Session token persisted locally so the next launch can restore the session.
        /// In backend mode this is the HMAC bearer token.
        /// In GitHub-direct mode this is the username (a stable, secret-free marker).
        /// </summary>
        public string? Token => _bearerToken ?? _username;

        /// <summary>True when running against the Node.js backend REST API.</summary>
        public bool IsBackendMode => _backend != null;

        /// <summary>True when the logged-in account is the admin account.</summary>
        public bool IsAdmin =>
            string.Equals(_username, AdminUsername, StringComparison.OrdinalIgnoreCase);

        public GameOsClient()
        {
            if (BackendApiService.IsConfigured)
            {
                _backend = new BackendApiService();
                System.Diagnostics.Debug.WriteLine(
                    $"[GameOsClient] Backend mode — {BackendApiService.BackendUrl}");
            }
            else
            {
                _github = new GitHubDataService();
                System.Diagnostics.Debug.WriteLine(
                    $"[GameOsClient] GitHub-direct mode — " +
                    (string.IsNullOrEmpty(GitHubDataService.GitHubToken) ? "no token" : "token configured"));
            }
        }

        // ── Authentication ────────────────────────────────────────────────────

        /// <summary>
        /// Restore a previously-saved session without re-entering credentials.
        ///
        /// In backend mode the saved <paramref name="token"/> is the HMAC bearer token
        /// issued by <c>POST /api/auth/token</c>; the backend verifies it via GET /api/me.
        ///
        /// In GitHub-direct mode the saved <paramref name="token"/> is the username;
        /// the account is verified by reading its profile from the data repository.
        /// </summary>
        public async Task<UserProfile> RestoreSessionAsync(
            string token, string username, CancellationToken ct = default)
        {
            if (_backend != null)
            {
                var profile = await _backend.RestoreSessionAsync(token, ct);
                _username    = profile.Username;
                _bearerToken = token;
                return profile;
            }

            // GitHub-direct mode
            var ghProfile = await _github!.GetProfileAsync(username, ct)
                ?? throw new GameOsException(404,
                    "Account not found. Please log in again.");
            _username = ghProfile.Username;
            return ghProfile;
        }

        /// <summary>
        /// Log in with username (or email) and password.
        ///
        /// In backend mode calls POST {backendUrl}/api/auth/token — the same endpoint
        /// the web frontend uses.  No GitHub PAT required from the client.
        ///
        /// In GitHub-direct mode verifies the PBKDF2 hash against the data repository.
        /// Requires a GitHub PAT configured via GAMEOS_GITHUB_TOKEN or gameos-token.dat.
        /// </summary>
        public async Task<UserProfile> LoginAsync(
            string usernameOrEmail, string password, CancellationToken ct = default)
        {
            if (_backend != null)
            {
                var (profile, token) = await _backend.LoginAsync(usernameOrEmail, password, ct);
                _username    = profile.Username;
                _bearerToken = token;
                return profile;
            }

            // GitHub-direct mode — requires a PAT bundled in gameos-token.dat
            if (string.IsNullOrEmpty(GitHubDataService.GitHubToken))
                throw new GameOsException(503,
                    "Game.OS is not configured for login.\n\n" +
                    "Please download the official Game.OS Launcher from GitHub Actions\n" +
                    "(Actions → Build & Live-Login Test → GameOS-Launcher-win-x64 artifact),\n" +
                    "which includes the credentials needed to connect to the data store.\n\n" +
                    "Alternatively, set GAMEOS_BACKEND_URL to point to your backend server,\n" +
                    "or set GAMEOS_GITHUB_TOKEN to your GitHub Personal Access Token.");

            var ghProfile = await _github!.VerifyLoginAsync(usernameOrEmail, password, ct)
                ?? throw new GameOsException(401,
                    "Invalid username/email or password.");
            _username = ghProfile.Username;
            return ghProfile;
        }

        /// <summary>
        /// Register a new account.
        ///
        /// In backend mode calls POST {backendUrl}/api/create-account.
        /// In GitHub-direct mode writes directly to the data repository.
        /// </summary>
        public async Task<UserProfile> RegisterAsync(
            string username, string email, string password,
            CancellationToken ct = default)
        {
            if (_backend != null)
            {
                var (profile, token) = await _backend.RegisterAsync(username, email, password, ct);
                _username    = profile.Username;
                _bearerToken = token;
                return profile;
            }

            var ghProfile = await _github!.CreateAccountAsync(username, email, password, ct);
            _username = ghProfile.Username;
            return ghProfile;
        }

        public void Logout()
        {
            _username    = null;
            _bearerToken = null;
        }

        // ── Profile ───────────────────────────────────────────────────────────
        public async Task<UserProfile> GetProfileAsync(CancellationToken ct = default)
        {
            if (_username == null)
                throw new GameOsException(401, "Not authenticated.");

            if (_backend != null)
                return await _backend.GetProfileAsync(ct);

            return await _github!.GetProfileAsync(_username, ct)
                ?? new UserProfile { Username = _username };
        }

        // ── Games ─────────────────────────────────────────────────────────────
        public async Task<List<Game>> GetGamesAsync(CancellationToken ct = default)
        {
            if (_username == null) return new List<Game>();

            if (_backend != null)
                return await _backend.GetGamesAsync(ct);

            return await _github!.GetGamesAsync(_username, ct);
        }

        public async Task AddGameAsync(
            Game game, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");

            if (_backend != null)
            {
                await _backend.AddGameAsync(game, ct);
                return;
            }
            await _github!.AddGameAsync(_username, game, ct);
        }

        public async Task RemoveGameAsync(
            string platform, string title, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");

            if (_backend != null)
            {
                await _backend.RemoveGameAsync(platform, title, ct);
                return;
            }
            await _github!.RemoveGameAsync(_username, platform, title, ct);
        }

        // ── Achievements ──────────────────────────────────────────────────────
        public async Task<List<Achievement>> GetAchievementsAsync(CancellationToken ct = default)
        {
            if (_username == null) return new List<Achievement>();

            if (_backend != null)
                return await _backend.GetAchievementsAsync(ct);

            return await _github!.GetAchievementsAsync(_username, ct);
        }

        // ── Friends ───────────────────────────────────────────────────────────
        public async Task<List<string>> GetFriendsAsync(CancellationToken ct = default)
        {
            if (_username == null) return new List<string>();

            if (_backend != null)
                return await _backend.GetFriendsAsync(ct);

            return await _github!.GetFriendsAsync(_username, ct);
        }

        public async Task<List<FriendRequest>> GetFriendRequestsAsync(
            string username, CancellationToken ct = default)
        {
            if (_backend != null)
                return await _backend.GetFriendRequestsAsync(username, ct);

            return await _github!.GetFriendRequestsAsync(username, ct);
        }

        public async Task SendFriendRequestAsync(
            string friendUsername, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");

            if (_backend != null)
            {
                await _backend.SendFriendRequestAsync(_username, friendUsername, ct);
                return;
            }
            await _github!.SendFriendRequestAsync(_username, friendUsername, ct);
        }

        public async Task AcceptFriendRequestAsync(
            string fromUsername, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");

            if (_backend != null)
            {
                await _backend.AcceptFriendRequestAsync(_username, fromUsername, ct);
                return;
            }
            await _github!.AcceptFriendRequestAsync(_username, fromUsername, ct);
        }

        public async Task DeclineFriendRequestAsync(
            string fromUsername, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");

            if (_backend != null)
            {
                await _backend.DeclineFriendRequestAsync(_username, fromUsername, ct);
                return;
            }
            await _github!.DeclineFriendRequestAsync(_username, fromUsername, ct);
        }

        // ── Presence ──────────────────────────────────────────────────────────
        public async Task UpdatePresenceAsync(CancellationToken ct = default)
        {
            if (_username == null) return;

            if (_backend != null)
            {
                await _backend.UpdatePresenceAsync(_username, ct);
                return;
            }
            await _github!.UpdatePresenceAsync(_username, ct);
        }

        public async Task<string?> GetPresenceAsync(
            string username, CancellationToken ct = default)
        {
            if (_backend != null)
                return await _backend.GetPresenceAsync(username, ct);

            return await _github!.GetPresenceAsync(username, ct);
        }

        // ── Messages ──────────────────────────────────────────────────────────
        public async Task SendMessageAsync(
            string toUsername, string text, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");

            if (_backend != null)
            {
                await _backend.SendMessageAsync(_username, toUsername, text, ct);
                return;
            }
            await _github!.SendMessageAsync(_username, toUsername, text, ct);
        }

        public async Task<List<Message>> GetMessagesAsync(
            string withUsername, CancellationToken ct = default)
        {
            if (_username == null) return new List<Message>();

            if (_backend != null)
                return await _backend.GetMessagesAsync(_username, withUsername, ct);

            return await _github!.GetMessagesAsync(_username, withUsername, ct);
        }

        // ── Health check ──────────────────────────────────────────────────────
        /// <summary>
        /// Returns true when the data backend is reachable.
        /// In backend mode checks the Node.js /health endpoint.
        /// In GitHub-direct mode reads the email index from the data repository.
        /// </summary>
        public async Task<bool> CheckHealthAsync(CancellationToken ct = default)
        {
            try
            {
                if (_backend != null)
                    return await _backend.CheckHealthAsync(ct);

                // GitHub-direct: read the email index as a quick connectivity check
                await _github!.ReadFileAsync<object>("accounts/email-index.json", ct);
                return true;
            }
            catch { return false; }
        }

        public void Dispose()
        {
            _backend?.Dispose();
            _github?.Dispose();
        }
    }

    // ── Custom exception ──────────────────────────────────────────────────────
    public class GameOsException : Exception
    {
        public int StatusCode { get; }
        public GameOsException(int statusCode, string message)
            : base(message) => StatusCode = statusCode;
    }
}
