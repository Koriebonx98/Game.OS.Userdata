using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher
{
    /// <summary>
    /// Game.OS API client.  Authenticates users and reads/writes their data
    /// directly from the GitHub data repository — exactly the same way the
    /// web frontend does.  No Node.js backend or PAT is required from the user:
    /// just a regular username and password.
    ///
    /// Configure the data repository and optional GitHub token via environment
    /// variables (see <see cref="GitHubDataService"/> for details):
    ///   GAMEOS_DATA_REPO_OWNER  (default: Koriebonx98)
    ///   GAMEOS_DATA_REPO_NAME   (default: Game.OS.Private.Data)
    ///   GAMEOS_GITHUB_TOKEN     (fine-grained PAT; omit for public repos)
    /// </summary>
    public sealed class GameOsClient : IDisposable
    {
        private static readonly string AdminUsername = "Admin.GameOS";

        private readonly GitHubDataService _github;

        private string? _username;

        /// <summary>The currently logged-in username, or <c>null</c> if not authenticated.</summary>
        public string? LoggedInUser => _username;

        /// <summary>
        /// True once the user has authenticated.  Used by the main view-model to
        /// distinguish GitHub mode from demo mode.
        /// </summary>
        public bool IsAuthenticated => _username != null;

        /// <summary>
        /// A stable session marker stored in the local session cache so the next
        /// launch can silently restore the session without re-entering credentials
        /// (mirrors the web app's <c>gameOSUser</c> localStorage entry).
        /// In GitHub mode this is the username — no bearer token is needed.
        /// </summary>
        public string? Token => _username;

        /// <summary>True when the logged-in account is the admin account.</summary>
        public bool IsAdmin =>
            string.Equals(_username, AdminUsername, StringComparison.OrdinalIgnoreCase);

        public GameOsClient()
        {
            _github = new GitHubDataService();
        }

        // ── Authentication ────────────────────────────────────────────────────

        /// <summary>
        /// Restore a previously-saved session without re-entering credentials.
        /// Verifies the account still exists in the GitHub data repository.
        /// Throws <see cref="GameOsException"/> if the account cannot be found —
        /// the caller should then show the login form.
        /// </summary>
        public async Task<UserProfile> RestoreSessionAsync(
            string token, string username, CancellationToken ct = default)
        {
            // In GitHub mode the token is the username (a stable session marker).
            // Verify the account still exists in the data repository.
            var profile = await _github.GetProfileAsync(username, ct)
                ?? throw new GameOsException(404,
                    "Account not found. Please log in again.");
            _username = profile.Username;
            return profile;
        }

        /// <summary>
        /// Log in with username (or email) and password.
        /// Verifies credentials against the GitHub data repository using PBKDF2-SHA256
        /// with 100,000 iterations — exactly matching the web login flow.
        /// Returns the full profile on success.
        /// Throws <see cref="GameOsException"/> with status 401 if credentials are wrong,
        /// or status 503 if the data repository cannot be reached (no GitHub token configured).
        /// </summary>
        public async Task<UserProfile> LoginAsync(
            string usernameOrEmail, string password, CancellationToken ct = default)
        {
            // Warn early if no GitHub token is configured — the data repository is
            // private so every API call will silently return 404 without auth.
            if (string.IsNullOrEmpty(GitHubDataService.GitHubToken))
                throw new GameOsException(503,
                    "No GitHub token is configured. " +
                    "Please use the official pre-built launcher (which has the token bundled) " +
                    "or set the GAMEOS_GITHUB_TOKEN environment variable to a valid PAT.");

            var profile = await _github.VerifyLoginAsync(usernameOrEmail, password, ct)
                ?? throw new GameOsException(401,
                    "Invalid username/email or password.");
            _username = profile.Username;
            return profile;
        }

        /// <summary>
        /// Register a new account in the GitHub data repository.
        /// Returns the created profile on success.
        /// </summary>
        public async Task<UserProfile> RegisterAsync(
            string username, string email, string password,
            CancellationToken ct = default)
        {
            var profile = await _github.CreateAccountAsync(username, email, password, ct);
            _username = profile.Username;
            return profile;
        }

        public void Logout()
        {
            _username = null;
        }

        // ── Profile ───────────────────────────────────────────────────────────
        public async Task<UserProfile> GetProfileAsync(CancellationToken ct = default)
        {
            if (_username == null)
                throw new GameOsException(401, "Not authenticated.");
            return await _github.GetProfileAsync(_username, ct)
                ?? new UserProfile { Username = _username };
        }

        // ── Games ─────────────────────────────────────────────────────────────
        public async Task<List<Game>> GetGamesAsync(CancellationToken ct = default)
        {
            if (_username == null) return new List<Game>();
            return await _github.GetGamesAsync(_username, ct);
        }

        public async Task AddGameAsync(
            Game game, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");
            await _github.AddGameAsync(_username, game, ct);
        }

        public async Task RemoveGameAsync(
            string platform, string title, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");
            await _github.RemoveGameAsync(_username, platform, title, ct);
        }

        // ── Achievements ──────────────────────────────────────────────────────
        public async Task<List<Achievement>> GetAchievementsAsync(CancellationToken ct = default)
        {
            if (_username == null) return new List<Achievement>();
            return await _github.GetAchievementsAsync(_username, ct);
        }

        // ── Friends ───────────────────────────────────────────────────────────
        public async Task<List<string>> GetFriendsAsync(CancellationToken ct = default)
        {
            if (_username == null) return new List<string>();
            return await _github.GetFriendsAsync(_username, ct);
        }

        public async Task<List<FriendRequest>> GetFriendRequestsAsync(
            string username, CancellationToken ct = default)
            => await _github.GetFriendRequestsAsync(username, ct);

        public async Task SendFriendRequestAsync(
            string friendUsername, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");
            await _github.SendFriendRequestAsync(_username, friendUsername, ct);
        }

        public async Task AcceptFriendRequestAsync(
            string fromUsername, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");
            await _github.AcceptFriendRequestAsync(_username, fromUsername, ct);
        }

        public async Task DeclineFriendRequestAsync(
            string fromUsername, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");
            await _github.DeclineFriendRequestAsync(_username, fromUsername, ct);
        }

        // ── Presence ──────────────────────────────────────────────────────────
        public async Task UpdatePresenceAsync(CancellationToken ct = default)
        {
            if (_username == null) return;
            await _github.UpdatePresenceAsync(_username, ct);
        }

        public async Task<string?> GetPresenceAsync(
            string username, CancellationToken ct = default)
            => await _github.GetPresenceAsync(username, ct);

        // ── Messages ──────────────────────────────────────────────────────────
        public async Task SendMessageAsync(
            string toUsername, string text, CancellationToken ct = default)
        {
            if (_username == null) throw new GameOsException(401, "Not authenticated.");
            await _github.SendMessageAsync(_username, toUsername, text, ct);
        }

        public async Task<List<Message>> GetMessagesAsync(
            string withUsername, CancellationToken ct = default)
        {
            if (_username == null) return new List<Message>();
            return await _github.GetMessagesAsync(_username, withUsername, ct);
        }

        // ── Health check ──────────────────────────────────────────────────────
        /// <summary>Returns true when the GitHub data repository is reachable.</summary>
        public async Task<bool> CheckHealthAsync(CancellationToken ct = default)
        {
            try
            {
                // A quick read of the email index tells us the repo is accessible.
                await _github.ReadFileAsync<object>("accounts/email-index.json", ct);
                return true;
            }
            catch { return false; }
        }

        public void Dispose() => _github.Dispose();
    }

    // ── Custom exception ──────────────────────────────────────────────────────
    public class GameOsException : Exception
    {
        public int StatusCode { get; }
        public GameOsException(int statusCode, string message)
            : base(message) => StatusCode = statusCode;
    }
}
