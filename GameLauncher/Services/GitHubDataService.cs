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

namespace GameLauncher.Services
{
    /// <summary>
    /// Direct GitHub API client for Game.OS user data.
    ///
    /// Mirrors the JavaScript helpers in script.js:
    ///   githubRead()           → <see cref="ReadFileAsync{T}"/>
    ///   githubWrite()          → <see cref="WriteFileAsync"/>
    ///   hashPassword()         → <see cref="HashPassword"/>
    ///   verifyAccountGitHub()  → <see cref="VerifyLoginAsync"/>
    ///   createAccountGitHub()  → <see cref="CreateAccountAsync"/>
    ///
    /// Configuration (via environment variables):
    ///   GAMEOS_DATA_REPO_OWNER  – GitHub account that owns the private data repo
    ///                             (default: Koriebonx98)
    ///   GAMEOS_DATA_REPO_NAME   – repository name for user data
    ///                             (default: Game.OS.Private.Data)
    ///   GAMEOS_GITHUB_TOKEN     – fine-grained PAT with Contents read+write access
    ///                             to the data repository.  Leave empty only when
    ///                             the data repository is public.
    /// </summary>
    public sealed class GitHubDataService : IDisposable
    {
        // ── Configuration ─────────────────────────────────────────────────────
        public static readonly string DataRepoOwner =
            Environment.GetEnvironmentVariable("GAMEOS_DATA_REPO_OWNER") ?? "Koriebonx98";

        public static readonly string DataRepoName =
            Environment.GetEnvironmentVariable("GAMEOS_DATA_REPO_NAME") ?? "Game.OS.Private.Data";

        public static readonly string? GitHubToken =
            Environment.GetEnvironmentVariable("GAMEOS_GITHUB_TOKEN");

        private readonly HttpClient _http;

        private static readonly JsonSerializerOptions _jsonOpts = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented               = true,
        };

        public GitHubDataService()
        {
            _http = new HttpClient();
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher/2.0");
            _http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            _http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");

            if (!string.IsNullOrEmpty(GitHubToken))
                _http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", GitHubToken);
        }

        // ── Password hashing ──────────────────────────────────────────────────
        /// <summary>
        /// Hash a password using PBKDF2-SHA256 with 100,000 iterations.
        /// Exactly matches <c>hashPassword(password, username)</c> in script.js.
        /// Salt is <c>{username_lower}:gameos</c>, output is 32-byte hex string.
        /// </summary>
        public static string HashPassword(string password, string username)
        {
            var salt      = Encoding.UTF8.GetBytes($"{username.ToLowerInvariant()}:gameos");
            using var kdf = new Rfc2898DeriveBytes(
                password, salt, 100_000, HashAlgorithmName.SHA256);
            return Convert.ToHexString(kdf.GetBytes(32)).ToLowerInvariant();
        }

        // ── GitHub file I/O ───────────────────────────────────────────────────
        /// <summary>
        /// Read and decode a JSON file from the data repository.
        /// Returns (<c>default</c>, <c>null</c>) when the file does not exist (404).
        /// Mirrors <c>githubRead(path)</c> in script.js.
        /// </summary>
        public async Task<(T? Content, string? Sha)> ReadFileAsync<T>(
            string path, CancellationToken ct = default)
        {
            var url  = $"https://api.github.com/repos/{DataRepoOwner}/{DataRepoName}/contents/{path}";
            var resp = await _http.GetAsync(url, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return (default, null);

            if (!resp.IsSuccessStatusCode)
                throw new GameOsException(
                    (int)resp.StatusCode,
                    $"GitHub API error {(int)resp.StatusCode} reading {path}");

            var file = await resp.Content
                .ReadFromJsonAsync<GitHubFileResponse>(cancellationToken: ct)
                ?? throw new GameOsException(500, "Invalid GitHub API response");

            var bytes   = Convert.FromBase64String(file.Content.Replace("\n", ""));
            var json    = Encoding.UTF8.GetString(bytes);
            var content = JsonSerializer.Deserialize<T>(json, _jsonOpts);
            return (content, file.Sha);
        }

        /// <summary>
        /// Create or overwrite a JSON file in the data repository.
        /// Pass <paramref name="sha"/> when overwriting an existing file.
        /// Mirrors <c>githubWrite(path, content, message, sha)</c> in script.js.
        /// </summary>
        public async Task WriteFileAsync(
            string path, object content, string message,
            string? sha = null, CancellationToken ct = default)
        {
            var json   = JsonSerializer.Serialize(content, _jsonOpts);
            var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

            var body = new GitHubWriteBody
            {
                Message   = message,
                Content   = base64,
                Sha       = sha,
                Committer = new GitHubCommitter
                {
                    Name  = "Game.OS Bot",
                    Email = "game-os-bot@users.noreply.github.com"
                }
            };

            var url  = $"https://api.github.com/repos/{DataRepoOwner}/{DataRepoName}/contents/{path}";
            var resp = await _http.PutAsJsonAsync(url, body, ct);

            if (!resp.IsSuccessStatusCode)
            {
                var err = await resp.Content.ReadAsStringAsync(ct);
                throw new GameOsException(
                    (int)resp.StatusCode,
                    $"GitHub write error {(int)resp.StatusCode}: {err}");
            }
        }

        // ── Authentication ────────────────────────────────────────────────────
        /// <summary>
        /// Verify username/email and password against the GitHub data repository.
        /// Mirrors <c>verifyAccountGitHub(identifier, password)</c> in script.js.
        /// Returns the <see cref="UserProfile"/> on success, or <c>null</c> on failure.
        /// </summary>
        public async Task<UserProfile?> VerifyLoginAsync(
            string identifier, string password, CancellationToken ct = default)
        {
            string accountKey;
            if (identifier.Contains('@'))
            {
                // Email login: look up username via email index
                var (index, _) = await ReadFileAsync<Dictionary<string, string>>(
                    "accounts/email-index.json", ct);
                if (index == null) return null;
                if (!index.TryGetValue(identifier.ToLowerInvariant(), out accountKey!))
                    return null;
            }
            else
            {
                accountKey = identifier.ToLowerInvariant();
            }

            var (profile, _) = await ReadFileAsync<UserProfile>(
                $"accounts/{accountKey}/profile.json", ct);
            if (profile == null) return null;

            var inputHash = HashPassword(password, profile.Username);
            if (!string.Equals(profile.PasswordHash, inputHash, StringComparison.Ordinal))
                return null;

            return profile;
        }

        /// <summary>
        /// Register a new account in the GitHub data repository.
        /// Mirrors <c>createAccountGitHub(username, email, password)</c> in script.js.
        /// Throws <see cref="GameOsException"/> if the username or email is already taken.
        /// </summary>
        public async Task<UserProfile> CreateAccountAsync(
            string username, string email, string password, CancellationToken ct = default)
        {
            var usernameLower = username.ToLowerInvariant();
            var emailLower    = email.ToLowerInvariant();

            // Duplicate username check
            var (existing, _) = await ReadFileAsync<UserProfile>(
                $"accounts/{usernameLower}/profile.json", ct);
            if (existing != null)
                throw new GameOsException(409, "Username already exists.");

            // Duplicate email check
            var (indexContent, indexSha) = await ReadFileAsync<Dictionary<string, string>>(
                "accounts/email-index.json", ct);
            var emailMap = indexContent ?? new Dictionary<string, string>();
            if (emailMap.ContainsKey(emailLower))
                throw new GameOsException(409, "Email already registered.");

            // Create profile
            var profile = new UserProfile
            {
                Username     = username,
                Email        = email,
                PasswordHash = HashPassword(password, username),
                CreatedAt    = DateTimeOffset.UtcNow.ToString("o"),
            };
            await WriteFileAsync(
                $"accounts/{usernameLower}/profile.json",
                profile,
                $"Create account: {username}",
                null, ct);

            // Update email index (up to 3 attempts to handle concurrent write conflicts,
            // matching the retry loop in script.js createAccountGitHub)
            emailMap[emailLower] = usernameLower;
            string? currentIndexSha = indexSha;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    await WriteFileAsync(
                        "accounts/email-index.json",
                        emailMap,
                        $"Add email index for: {username}",
                        currentIndexSha, ct);
                    break;
                }
                catch (GameOsException ex) when (attempt < 2)
                {
                    // GitHub returns 409 Conflict when the SHA is stale — re-read for
                    // the updated SHA then retry with a brief back-off, mirroring the
                    // retry loop in script.js createAccountGitHub.
                    System.Diagnostics.Debug.WriteLine(
                        $"[GitHubDataService] Email index write conflict (attempt {attempt + 1}): {ex.Message}");
                    var (refreshed, refreshedSha) = await ReadFileAsync<Dictionary<string, string>>(
                        "accounts/email-index.json", ct);
                    emailMap             = refreshed ?? new Dictionary<string, string>();
                    emailMap[emailLower] = usernameLower;
                    currentIndexSha      = refreshedSha;
                    await Task.Delay(200 * (attempt + 1), ct);
                }
            }

            return profile;
        }

        // ── User data reads ───────────────────────────────────────────────────
        public async Task<UserProfile?> GetProfileAsync(
            string username, CancellationToken ct = default)
        {
            var (profile, _) = await ReadFileAsync<UserProfile>(
                $"accounts/{username.ToLowerInvariant()}/profile.json", ct);
            return profile;
        }

        public async Task<List<Game>> GetGamesAsync(
            string username, CancellationToken ct = default)
        {
            var (games, _) = await ReadFileAsync<List<Game>>(
                $"accounts/{username.ToLowerInvariant()}/games.json", ct);
            return games ?? new List<Game>();
        }

        public async Task<List<Achievement>> GetAchievementsAsync(
            string username, CancellationToken ct = default)
        {
            var (achievements, _) = await ReadFileAsync<List<Achievement>>(
                $"accounts/{username.ToLowerInvariant()}/achievements.json", ct);
            return achievements ?? new List<Achievement>();
        }

        public async Task<List<string>> GetFriendsAsync(
            string username, CancellationToken ct = default)
        {
            var (friends, _) = await ReadFileAsync<List<string>>(
                $"accounts/{username.ToLowerInvariant()}/friends.json", ct);
            return friends ?? new List<string>();
        }

        public async Task<List<FriendRequest>> GetFriendRequestsAsync(
            string username, CancellationToken ct = default)
        {
            var (requests, _) = await ReadFileAsync<List<FriendRequest>>(
                $"accounts/{username.ToLowerInvariant()}/friend_requests.json", ct);
            return requests ?? new List<FriendRequest>();
        }

        public async Task<string?> GetPresenceAsync(
            string username, CancellationToken ct = default)
        {
            try
            {
                var (data, _) = await ReadFileAsync<PresenceData>(
                    $"accounts/{username.ToLowerInvariant()}/presence.json", ct);
                return data?.LastSeen;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[GitHubDataService] GetPresence failed for '{username}': {ex.Message}");
                return null;
            }
        }

        // ── User data writes ──────────────────────────────────────────────────
        public async Task AddGameAsync(
            string username, string platform, string title, string? titleId,
            CancellationToken ct = default)
        {
            var key = $"accounts/{username.ToLowerInvariant()}/games.json";
            var (games, sha) = await ReadFileAsync<List<Game>>(key, ct);
            var library = games ?? new List<Game>();

            library.Add(new Game
            {
                Platform = platform,
                Title    = title,
                TitleId  = titleId,
                AddedAt  = DateTimeOffset.UtcNow.ToString("o"),
            });

            await WriteFileAsync(key, library, $"Add game '{title}' for {username}", sha, ct);
        }

        public async Task RemoveGameAsync(
            string username, string platform, string title,
            CancellationToken ct = default)
        {
            var key = $"accounts/{username.ToLowerInvariant()}/games.json";
            var (games, sha) = await ReadFileAsync<List<Game>>(key, ct);
            if (games == null) return;

            games.RemoveAll(g =>
                string.Equals(g.Platform, platform, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.Title,    title,    StringComparison.OrdinalIgnoreCase));

            await WriteFileAsync(key, games, $"Remove game '{title}' for {username}", sha, ct);
        }

        public async Task UpdatePresenceAsync(
            string username, CancellationToken ct = default)
        {
            try
            {
                var key = $"accounts/{username.ToLowerInvariant()}/presence.json";
                var (_, sha) = await ReadFileAsync<PresenceData>(key, ct);
                var data = new PresenceData
                {
                    Username = username,
                    LastSeen = DateTimeOffset.UtcNow.ToString("o"),
                };
                await WriteFileAsync(key, data, $"Update presence: {username}", sha, ct);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[GitHubDataService] UpdatePresence failed: {ex.Message}");
            }
        }

        public async Task SendMessageAsync(
            string from, string to, string text, CancellationToken ct = default)
        {
            // Thread file key is always <lower_alphabetical_first>_<lower_alphabetical_second>
            var (a, b) = BuildThreadKey(from, to);
            var key = $"accounts/messages/{a}_{b}.json";

            var (existing, sha) = await ReadFileAsync<List<Message>>(key, ct);
            var thread = existing ?? new List<Message>();
            thread.Add(new Message
            {
                From   = from,
                Text   = text,
                SentAt = DateTimeOffset.UtcNow.ToString("o"),
            });
            await WriteFileAsync(key, thread, $"Message from {from} to {to}", sha, ct);
        }

        public async Task<List<Message>> GetMessagesAsync(
            string username, string withUsername, CancellationToken ct = default)
        {
            var (a, b) = BuildThreadKey(username, withUsername);
            var (messages, _) = await ReadFileAsync<List<Message>>(
                $"accounts/messages/{a}_{b}.json", ct);
            return messages ?? new List<Message>();
        }

        public async Task SendFriendRequestAsync(
            string from, string to, CancellationToken ct = default)
        {
            var fromLower = from.ToLowerInvariant();
            var toLower   = to.ToLowerInvariant();

            // Add to recipient's incoming requests
            var reqKey = $"accounts/{toLower}/friend_requests.json";
            var (requests, reqSha) = await ReadFileAsync<List<FriendRequest>>(reqKey, ct);
            var reqList = requests ?? new List<FriendRequest>();
            reqList.Add(new FriendRequest { From = from, SentAt = DateTimeOffset.UtcNow.ToString("o") });
            await WriteFileAsync(reqKey, reqList, $"Friend request from {from} to {to}", reqSha, ct);

            // Add to sender's sent requests.
            // In sent_requests.json the FriendRequest.From field holds the RECIPIENT
            // (the person the request was sent to), so that AcceptFriendRequestAsync
            // can locate and remove this entry by matching on the accepter's username.
            var sentKey = $"accounts/{fromLower}/sent_requests.json";
            var (sent, sentSha) = await ReadFileAsync<List<FriendRequest>>(sentKey, ct);
            var sentList = sent ?? new List<FriendRequest>();
            sentList.Add(new FriendRequest { From = to, SentAt = DateTimeOffset.UtcNow.ToString("o") });
            await WriteFileAsync(sentKey, sentList, $"Sent friend request from {from} to {to}", sentSha, ct);
        }

        public async Task AcceptFriendRequestAsync(
            string username, string fromUsername, CancellationToken ct = default)
        {
            var userLower = username.ToLowerInvariant();
            var fromLower = fromUsername.ToLowerInvariant();

            // Remove from incoming requests
            var reqKey = $"accounts/{userLower}/friend_requests.json";
            var (requests, reqSha) = await ReadFileAsync<List<FriendRequest>>(reqKey, ct);
            if (requests != null)
            {
                requests.RemoveAll(r =>
                    string.Equals(r.From, fromUsername, StringComparison.OrdinalIgnoreCase));
                await WriteFileAsync(reqKey, requests,
                    $"Accept friend request from {fromUsername}", reqSha, ct);
            }

            // Remove from sender's sent requests
            var sentKey = $"accounts/{fromLower}/sent_requests.json";
            var (sent, sentSha) = await ReadFileAsync<List<FriendRequest>>(sentKey, ct);
            if (sent != null)
            {
                sent.RemoveAll(r =>
                    string.Equals(r.From, username, StringComparison.OrdinalIgnoreCase));
                await WriteFileAsync(sentKey, sent,
                    $"Friend request accepted by {username}", sentSha, ct);
            }

            // Add to both users' friends lists
            await AddFriendAsync(userLower, fromUsername, ct);
            await AddFriendAsync(fromLower, username, ct);
        }

        public async Task DeclineFriendRequestAsync(
            string username, string fromUsername, CancellationToken ct = default)
        {
            var userLower = username.ToLowerInvariant();
            var fromLower = fromUsername.ToLowerInvariant();

            var reqKey = $"accounts/{userLower}/friend_requests.json";
            var (requests, reqSha) = await ReadFileAsync<List<FriendRequest>>(reqKey, ct);
            if (requests != null)
            {
                requests.RemoveAll(r =>
                    string.Equals(r.From, fromUsername, StringComparison.OrdinalIgnoreCase));
                await WriteFileAsync(reqKey, requests,
                    $"Decline friend request from {fromUsername}", reqSha, ct);
            }

            var sentKey = $"accounts/{fromLower}/sent_requests.json";
            var (sent, sentSha) = await ReadFileAsync<List<FriendRequest>>(sentKey, ct);
            if (sent != null)
            {
                sent.RemoveAll(r =>
                    string.Equals(r.From, username, StringComparison.OrdinalIgnoreCase));
                await WriteFileAsync(sentKey, sent,
                    $"Friend request declined by {username}", sentSha, ct);
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────
        private async Task AddFriendAsync(
            string userLower, string friendUsername, CancellationToken ct)
        {
            var key = $"accounts/{userLower}/friends.json";
            var (friends, sha) = await ReadFileAsync<List<string>>(key, ct);
            var list = friends ?? new List<string>();
            if (!list.Exists(f => string.Equals(f, friendUsername,
                                                 StringComparison.OrdinalIgnoreCase)))
                list.Add(friendUsername);
            await WriteFileAsync(key, list, $"Add friend {friendUsername} for {userLower}", sha, ct);
        }

        private static (string a, string b) BuildThreadKey(string user1, string user2)
        {
            var lo1 = user1.ToLowerInvariant();
            var lo2 = user2.ToLowerInvariant();
            return string.Compare(lo1, lo2, StringComparison.Ordinal) <= 0
                ? (lo1, lo2)
                : (lo2, lo1);
        }

        public void Dispose() => _http.Dispose();

        // ── GitHub API response models ─────────────────────────────────────────
        private sealed class GitHubFileResponse
        {
            [JsonPropertyName("content")] public string Content { get; set; } = "";
            [JsonPropertyName("sha")]     public string Sha     { get; set; } = "";
        }

        private sealed class GitHubWriteBody
        {
            [JsonPropertyName("message")]   public string          Message   { get; set; } = "";
            [JsonPropertyName("content")]   public string          Content   { get; set; } = "";
            [JsonPropertyName("sha")]       public string?         Sha       { get; set; }
            [JsonPropertyName("committer")] public GitHubCommitter Committer { get; set; } = new();
        }

        private sealed class GitHubCommitter
        {
            [JsonPropertyName("name")]  public string Name  { get; set; } = "";
            [JsonPropertyName("email")] public string Email { get; set; } = "";
        }
    }
}
