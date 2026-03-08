using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using GameLauncher.Models;

namespace GameLauncher
{
    /// <summary>
    /// Game OS client that calls the GitHub REST API to read and write player data.
    /// No external server is required — everything runs on GitHub's infrastructure.
    ///
    /// PAT is loaded from the GAMEOS_PAT environment variable at runtime.
    /// Never hard-code a token in source code.
    /// </summary>
    public sealed class GameOsClient : IDisposable
    {
        // ── Configuration ─────────────────────────────────────────────────────
        // Set GAMEOS_OWNER and GAMEOS_DATA_REPO environment variables, or
        // change the fallback values below for your own deployment.
        private static readonly string Owner    = Environment.GetEnvironmentVariable("GAMEOS_OWNER")    ?? "Koriebonx98";
        private static readonly string DataRepo = Environment.GetEnvironmentVariable("GAMEOS_DATA_REPO") ?? "Game.OS.Private.Data";

        // PAT is loaded at runtime from a secure source — never from source code.
        private static string GetPat() =>
            Environment.GetEnvironmentVariable("GAMEOS_PAT")
            ?? throw new InvalidOperationException(
                "GAMEOS_PAT environment variable is not set.\n" +
                "Set it to your GitHub fine-grained personal access token before launching.");

        private static readonly string BaseUrl =
            $"https://api.github.com/repos/{Owner}/{DataRepo}/contents/";

        private readonly HttpClient _http;
        private string? _username;
        private bool _demoMode;

        public string? LoggedInUser => _username;

        /// <summary>
        /// When true the client runs against built-in demo data and makes no
        /// real network calls.  Useful for first-run / offline demonstrations.
        /// </summary>
        public bool DemoMode
        {
            get => _demoMode;
            set => _demoMode = value;
        }

        public GameOsClient(bool demoMode = false)
        {
            _demoMode = demoMode;
            _http = new HttpClient();
            if (!demoMode)
            {
                string pat = GetPat();
                _http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", pat);
                _http.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
                _http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
                _http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher/1.0");
            }
        }

        // ── Password hashing (PBKDF2) ─────────────────────────────────────────
        public static string HashPassword(string password, string username)
        {
            byte[] salt = Encoding.UTF8.GetBytes($"{username.ToLower()}:gameos");
            byte[] pass = Encoding.UTF8.GetBytes(password);
            using var pbkdf2 = new Rfc2898DeriveBytes(
                pass, salt, 100_000, HashAlgorithmName.SHA256);
            return Convert.ToHexString(pbkdf2.GetBytes(32)).ToLower();
        }

        // ── Low-level GitHub file helpers ─────────────────────────────────────
        public async Task<(T? content, string? sha)> ReadFileAsync<T>(
            string path, CancellationToken ct = default)
        {
            var resp = await _http.GetAsync(BaseUrl + path, ct);
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return (default, null);
            resp.EnsureSuccessStatusCode();

            var ghFile = await resp.Content.ReadFromJsonAsync<GitHubFile>(
                cancellationToken: ct);
            if (ghFile?.Content == null) return (default, null);

            string json = Encoding.UTF8.GetString(
                Convert.FromBase64String(ghFile.Content.Replace("\n", "")));
            var obj = JsonSerializer.Deserialize<T>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return (obj, ghFile.Sha);
        }

        public async Task<string> WriteFileAsync(
            string path, object content, string message,
            string? sha = null, CancellationToken ct = default)
        {
            string json = JsonSerializer.Serialize(content,
                new JsonSerializerOptions { WriteIndented = true });
            string b64  = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

            var body = new Dictionary<string, object?>
            {
                ["message"]   = message,
                ["content"]   = b64,
                ["sha"]       = sha,
                ["committer"] = new { name  = "Game.OS Launcher",
                                      email = "gameos-launcher@users.noreply.github.com" }
            };

            var resp = await _http.PutAsJsonAsync(BaseUrl + path, body, ct);
            if (!resp.IsSuccessStatusCode)
            {
                string err = await resp.Content.ReadAsStringAsync(ct);
                throw new GameOsException((int)resp.StatusCode,
                    $"Write failed ({(int)resp.StatusCode}): {err}");
            }
            var result = await resp.Content.ReadFromJsonAsync<GitHubWriteResult>(
                cancellationToken: ct);
            return result?.Content?.Sha ?? sha ?? "";
        }

        // ── Login / Logout ────────────────────────────────────────────────────
        public async Task<UserProfile> LoginAsync(
            string usernameOrEmail, string password, CancellationToken ct = default)
        {
            if (_demoMode)
                return DemoLogin(usernameOrEmail, password);

            string accountKey;
            if (usernameOrEmail.Contains('@'))
            {
                var (idx, _) = await ReadFileAsync<Dictionary<string, string>>(
                    "accounts/email-index.json", ct);
                if (idx == null || !idx.TryGetValue(
                        usernameOrEmail.ToLower(), out accountKey!))
                    throw new GameOsException(401, "Account not found.");
            }
            else
            {
                accountKey = usernameOrEmail.ToLower();
            }

            var (profile, _) = await ReadFileAsync<UserProfile>(
                $"accounts/{accountKey}/profile.json", ct);
            if (profile == null)
                throw new GameOsException(401, "Account not found.");

            string computed = HashPassword(password, profile.Username);
            if (computed != profile.PasswordHash)
                throw new GameOsException(401, "Invalid password.");

            _username = profile.Username;
            return profile;
        }

        public async Task<UserProfile> RegisterAsync(
            string username, string email, string password,
            CancellationToken ct = default)
        {
            if (_demoMode)
                return DemoRegister(username, email);

            string accountKey = username.ToLower();
            var (existing, _) = await ReadFileAsync<UserProfile>(
                $"accounts/{accountKey}/profile.json", ct);
            if (existing != null)
                throw new GameOsException(409, "Username is already taken.");

            string hash = HashPassword(password, username);
            var profile = new UserProfile
            {
                Username     = username,
                Email        = email,
                PasswordHash = hash,
                CreatedAt    = DateTimeOffset.UtcNow.ToString("o")
            };
            await WriteFileAsync(
                $"accounts/{accountKey}/profile.json",
                profile, $"Register: {username}", null, ct);

            // Update email index
            var (idx, idxSha) = await ReadFileAsync<Dictionary<string, string>>(
                "accounts/email-index.json", ct);
            idx ??= new Dictionary<string, string>();
            idx[email.ToLower()] = accountKey;
            await WriteFileAsync("accounts/email-index.json", idx,
                $"Email index: {email}", idxSha, ct);

            _username = username;
            return profile;
        }

        public void Logout() => _username = null;

        // ── Profile / games / achievements ───────────────────────────────────
        public Task<(UserProfile? p, string? sha)> GetProfileAsync(
            string username, CancellationToken ct = default)
            => ReadFileAsync<UserProfile>(
                $"accounts/{username.ToLower()}/profile.json", ct);

        public Task<(List<Game>? g, string? sha)> GetGamesAsync(
            string username, CancellationToken ct = default)
            => ReadFileAsync<List<Game>>(
                $"accounts/{username.ToLower()}/games.json", ct);

        public Task<(List<Achievement>? a, string? sha)> GetAchievementsAsync(
            string username, CancellationToken ct = default)
            => ReadFileAsync<List<Achievement>>(
                $"accounts/{username.ToLower()}/achievements.json", ct);

        public async Task AddGameAsync(
            string username, string platform, string title,
            string? titleId = null, string? coverUrl = null,
            CancellationToken ct = default)
        {
            string path = $"accounts/{username.ToLower()}/games.json";
            var (games, sha) = await ReadFileAsync<List<Game>>(path, ct);
            games ??= new List<Game>();

            if (games.Exists(g =>
                g.Platform == platform &&
                string.Equals(g.Title, title, StringComparison.OrdinalIgnoreCase)))
                throw new GameOsException(400, "Game already in library.");

            games.Add(new Game
            {
                Platform = platform,
                Title    = title,
                TitleId  = titleId,
                CoverUrl = coverUrl,
                AddedAt  = DateTimeOffset.UtcNow.ToString("o")
            });
            await WriteFileAsync(path, games, $"Add game: {title} ({platform})", sha, ct);
        }

        public async Task RemoveGameAsync(
            string username, string platform, string title,
            CancellationToken ct = default)
        {
            string path = $"accounts/{username.ToLower()}/games.json";
            var (games, sha) = await ReadFileAsync<List<Game>>(path, ct);
            if (games == null) return;
            games.RemoveAll(g =>
                g.Platform == platform &&
                string.Equals(g.Title, title, StringComparison.OrdinalIgnoreCase));
            await WriteFileAsync(path, games, $"Remove game: {title} ({platform})", sha, ct);
        }

        // ── Friends ───────────────────────────────────────────────────────────
        public Task<(List<string>? f, string? sha)> GetFriendsAsync(
            string username, CancellationToken ct = default)
            => ReadFileAsync<List<string>>(
                $"accounts/{username.ToLower()}/friends.json", ct);

        // ── Presence ──────────────────────────────────────────────────────────
        public async Task UpdatePresenceAsync(
            string username, CancellationToken ct = default)
        {
            if (_demoMode) return;
            string path = $"accounts/{username.ToLower()}/presence.json";
            var (_, sha) = await ReadFileAsync<object>(path, ct);
            var data = new { username, lastSeen = DateTimeOffset.UtcNow.ToString("o") };
            await WriteFileAsync(path, data, $"Presence: {username}", sha, ct);
        }

        // ── Direct messages ───────────────────────────────────────────────────
        public async Task SendMessageAsync(
            string fromUsername, string toUsername, string text,
            CancellationToken ct = default)
        {
            if (text.Length > 1000)
                throw new GameOsException(400, "Message too long (max 1,000 characters).");

            string convPath = ConversationPath(fromUsername, toUsername);
            var (msgs, sha) = await ReadFileAsync<List<Message>>(convPath, ct);
            msgs ??= new List<Message>();
            msgs.Add(new Message
            {
                From   = fromUsername,
                Text   = text,
                SentAt = DateTimeOffset.UtcNow.ToString("o")
            });
            await WriteFileAsync(convPath, msgs,
                $"Message from {fromUsername} to {toUsername}", sha, ct);
        }

        public Task<(List<Message>? msgs, string? sha)> GetMessagesAsync(
            string userA, string userB, CancellationToken ct = default)
            => ReadFileAsync<List<Message>>(ConversationPath(userA, userB), ct);

        private static string ConversationPath(string a, string b)
        {
            string la = a.ToLower(), lb = b.ToLower();
            return string.Compare(la, lb, StringComparison.Ordinal) < 0
                ? $"accounts/{la}/conversations/{la}_{lb}.json"
                : $"accounts/{lb}/conversations/{lb}_{la}.json";
        }

        // ── Demo mode helpers ─────────────────────────────────────────────────
        private static readonly Dictionary<string, UserProfile> _demoUsers = new(StringComparer.OrdinalIgnoreCase)
        {
            ["demo"] = new UserProfile
            {
                Username     = "Demo",
                Email        = "demo@gameos.local",
                PasswordHash = HashPassword("demo123", "Demo"),
                CreatedAt    = "2025-01-01T00:00:00Z"
            }
        };

        private UserProfile DemoLogin(string usernameOrEmail, string password)
        {
            string key = usernameOrEmail.Contains('@')
                ? usernameOrEmail.Split('@')[0]
                : usernameOrEmail;

            if (!_demoUsers.TryGetValue(key, out var profile))
                throw new GameOsException(401, "Account not found.");

            string computed = HashPassword(password, profile.Username);
            if (computed != profile.PasswordHash)
                throw new GameOsException(401, "Invalid password.");

            _username = profile.Username;
            return profile;
        }

        private UserProfile DemoRegister(string username, string email)
        {
            var profile = new UserProfile
            {
                Username  = username,
                Email     = email,
                CreatedAt = DateTimeOffset.UtcNow.ToString("o")
            };
            _username = username;
            return profile;
        }

        public void Dispose() => _http.Dispose();

        // ── GitHub API wrappers ───────────────────────────────────────────────
        private class GitHubFile
        {
            [JsonPropertyName("content")] public string? Content { get; set; }
            [JsonPropertyName("sha")]     public string? Sha     { get; set; }
        }

        private class GitHubWriteResult
        {
            [JsonPropertyName("content")] public GitHubFile? Content { get; set; }
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
