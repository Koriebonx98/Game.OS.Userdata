using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using GameLauncher.Models;

namespace GameLauncher
{
    /// <summary>
    /// Game.OS API client that calls the backend HTTP server.
    /// Configure the API base URL via the GAMEOS_API_BASEURL environment variable
    /// (default: http://localhost:3000).  No GitHub PAT is required.
    /// </summary>
    public sealed class GameOsClient : IDisposable
    {
        // ── Configuration ─────────────────────────────────────────────────────
        /// <summary>Backend API base URL.  Override with GAMEOS_API_BASEURL env var.</summary>
        public static readonly string ApiBaseUrl =
            (Environment.GetEnvironmentVariable("GAMEOS_API_BASEURL") ?? "http://localhost:3000")
            .TrimEnd('/');

        private static readonly string AdminUsername = "Admin.GameOS";

        private readonly HttpClient _http;
        private string? _token;
        private string? _username;

        public string? LoggedInUser    => _username;
        public bool    IsAuthenticated => _token != null;
        /// <summary>The raw bearer token for the current session.  Persist this to
        /// enable silent re-login on next launch (same as localStorage on the website).</summary>
        public string? Token => _token;

        /// <summary>True when the logged-in account is the admin account.</summary>
        public bool IsAdmin =>
            string.Equals(_username, AdminUsername, StringComparison.OrdinalIgnoreCase);

        public GameOsClient()
        {
            // HttpClient is created per-instance here because the launcher is a
            // desktop application where a single client instance lives for the
            // entire session.  In a server scenario use IHttpClientFactory instead.
            _http = new HttpClient { BaseAddress = new Uri(ApiBaseUrl + "/") };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher/2.0");
        }

        // ── Authentication ────────────────────────────────────────────────────
        /// <summary>
        /// Restore a previously-saved session without re-entering credentials.
        /// Sets the bearer token directly and validates it by calling <c>/api/me</c>.
        /// Throws <see cref="GameOsException"/> if the token is expired or invalid —
        /// the caller should then fall back to the full login form.
        /// </summary>
        public async Task<UserProfile> RestoreSessionAsync(
            string token, string username, CancellationToken ct = default)
        {
            _token    = token;
            _username = username;
            SetAuthHeader();
            return await FetchProfileAsync(ct);
        }

        /// <summary>Log in with username (or email) and password.  Returns the full profile.</summary>
        public async Task<UserProfile> LoginAsync(
            string usernameOrEmail, string password, CancellationToken ct = default)
        {
            var resp = await _http.PostAsJsonAsync("api/auth/token",
                new { username = usernameOrEmail, password }, ct);
            var result = await ParseResponseAsync<TokenResult>(resp, ct);

            _token    = result.Token
                ?? throw new GameOsException(500, "Server did not return an API token.");
            _username = result.Username;
            SetAuthHeader();

            return await FetchProfileAsync(ct);
        }

        /// <summary>Register a new account.  Returns the created profile.</summary>
        public async Task<UserProfile> RegisterAsync(
            string username, string email, string password,
            CancellationToken ct = default)
        {
            var resp = await _http.PostAsJsonAsync("api/create-account",
                new { username, email, password }, ct);
            var result = await ParseResponseAsync<TokenResult>(resp, ct);

            _token    = result.Token
                ?? throw new GameOsException(500, "Server did not return an API token.");
            _username = result.Username;
            SetAuthHeader();

            return await FetchProfileAsync(ct);
        }

        public void Logout()
        {
            _token    = null;
            _username = null;
            _http.DefaultRequestHeaders.Authorization = null;
        }

        // ── Profile ───────────────────────────────────────────────────────────
        public async Task<UserProfile> GetProfileAsync(CancellationToken ct = default)
            => await FetchProfileAsync(ct);

        private async Task<UserProfile> FetchProfileAsync(CancellationToken ct)
        {
            var resp   = await _http.GetAsync("api/me", ct);
            var result = await ParseResponseAsync<ProfileResult>(resp, ct);
            return result.Profile ?? new UserProfile { Username = _username ?? "" };
        }

        // ── Games ─────────────────────────────────────────────────────────────
        public async Task<List<Game>> GetGamesAsync(CancellationToken ct = default)
        {
            var resp   = await _http.GetAsync("api/me/games", ct);
            var result = await ParseResponseAsync<GamesResult>(resp, ct);
            return result.Games ?? new List<Game>();
        }

        public async Task AddGameAsync(
            string platform, string title, string? titleId = null,
            CancellationToken ct = default)
        {
            var resp = await _http.PostAsJsonAsync("api/me/games",
                new { platform, title, titleId }, ct);
            await ParseResponseAsync<ApiResult>(resp, ct);
        }

        public async Task RemoveGameAsync(
            string platform, string title, CancellationToken ct = default)
        {
            var req = new HttpRequestMessage(HttpMethod.Delete, "api/me/games")
            {
                Content = JsonContent.Create(new { platform, title })
            };
            var resp = await _http.SendAsync(req, ct);
            await ParseResponseAsync<ApiResult>(resp, ct);
        }

        // ── Achievements ──────────────────────────────────────────────────────
        public async Task<List<Achievement>> GetAchievementsAsync(CancellationToken ct = default)
        {
            var resp   = await _http.GetAsync("api/me/achievements", ct);
            var result = await ParseResponseAsync<AchievementsResult>(resp, ct);
            return result.Achievements ?? new List<Achievement>();
        }

        // ── Friends ───────────────────────────────────────────────────────────
        public async Task<List<string>> GetFriendsAsync(CancellationToken ct = default)
        {
            var resp   = await _http.GetAsync("api/me/friends", ct);
            var result = await ParseResponseAsync<FriendsResult>(resp, ct);
            return result.Friends ?? new List<string>();
        }

        public async Task<List<FriendRequest>> GetFriendRequestsAsync(
            string username, CancellationToken ct = default)
        {
            var resp   = await _http.GetAsync(
                $"api/get-friend-requests?username={Uri.EscapeDataString(username)}", ct);
            var result = await ParseResponseAsync<FriendRequestsResult>(resp, ct);
            return result.Requests ?? new List<FriendRequest>();
        }

        public async Task SendFriendRequestAsync(
            string friendUsername, CancellationToken ct = default)
        {
            var resp = await _http.PostAsJsonAsync("api/send-friend-request",
                new { username = _username, friendUsername }, ct);
            await ParseResponseAsync<ApiResult>(resp, ct);
        }

        public async Task AcceptFriendRequestAsync(
            string fromUsername, CancellationToken ct = default)
        {
            var resp = await _http.PostAsJsonAsync("api/accept-friend-request",
                new { username = _username, fromUsername }, ct);
            await ParseResponseAsync<ApiResult>(resp, ct);
        }

        public async Task DeclineFriendRequestAsync(
            string fromUsername, CancellationToken ct = default)
        {
            var resp = await _http.PostAsJsonAsync("api/decline-friend-request",
                new { username = _username, fromUsername }, ct);
            await ParseResponseAsync<ApiResult>(resp, ct);
        }

        // ── Presence ──────────────────────────────────────────────────────────
        public async Task UpdatePresenceAsync(CancellationToken ct = default)
        {
            if (_username == null) return;
            await _http.PostAsJsonAsync("api/update-presence",
                new { username = _username }, ct);
        }

        public async Task<string?> GetPresenceAsync(
            string username, CancellationToken ct = default)
        {
            try
            {
                var resp = await _http.GetAsync(
                    $"api/get-presence?username={Uri.EscapeDataString(username)}", ct);
                if (!resp.IsSuccessStatusCode) return null;
                var result = await resp.Content
                    .ReadFromJsonAsync<PresenceResult>(cancellationToken: ct);
                return result?.LastSeen;
            }
            catch { return null; }
        }

        // ── Messages ──────────────────────────────────────────────────────────
        public async Task SendMessageAsync(
            string toUsername, string text, CancellationToken ct = default)
        {
            var resp = await _http.PostAsJsonAsync("api/send-message",
                new { username = _username, toUsername, text }, ct);
            await ParseResponseAsync<ApiResult>(resp, ct);
        }

        public async Task<List<Message>> GetMessagesAsync(
            string withUsername, CancellationToken ct = default)
        {
            var resp   = await _http.GetAsync(
                $"api/get-messages?username={Uri.EscapeDataString(_username ?? "")}" +
                $"&withUsername={Uri.EscapeDataString(withUsername)}", ct);
            var result = await ParseResponseAsync<MessagesResult>(resp, ct);
            return result.Messages ?? new List<Message>();
        }

        // ── Health check ──────────────────────────────────────────────────────
        public async Task<bool> CheckHealthAsync(CancellationToken ct = default)
        {
            try
            {
                var resp = await _http.GetAsync("health", ct);
                return resp.IsSuccessStatusCode;
            }
            catch { return false; }
        }

        public void Dispose() => _http.Dispose();

        // ── Helpers ───────────────────────────────────────────────────────────
        private void SetAuthHeader()
        {
            if (_token != null)
                _http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", _token);
        }

        private static async Task<T> ParseResponseAsync<T>(
            HttpResponseMessage resp, CancellationToken ct)
            where T : ApiResult
        {
            T? result;
            try
            {
                result = await resp.Content
                    .ReadFromJsonAsync<T>(cancellationToken: ct);
            }
            catch
            {
                throw new GameOsException((int)resp.StatusCode,
                    $"Unexpected response from server (HTTP {(int)resp.StatusCode}).");
            }

            if (result == null || !result.Success)
            {
                string msg = result?.Message
                    ?? $"Request failed (HTTP {(int)resp.StatusCode}).";
                throw new GameOsException((int)resp.StatusCode, msg);
            }
            return result;
        }

        // ── Response models ───────────────────────────────────────────────────
        private class ApiResult
        {
            [JsonPropertyName("success")] public bool    Success { get; set; }
            [JsonPropertyName("message")] public string? Message { get; set; }
        }

        private class TokenResult : ApiResult
        {
            [JsonPropertyName("token")]    public string? Token    { get; set; }
            [JsonPropertyName("username")] public string? Username { get; set; }
        }

        private class ProfileResult : ApiResult
        {
            [JsonPropertyName("profile")] public UserProfile? Profile { get; set; }
        }

        private class GamesResult : ApiResult
        {
            [JsonPropertyName("games")] public List<Game>? Games { get; set; }
        }

        private class AchievementsResult : ApiResult
        {
            [JsonPropertyName("achievements")] public List<Achievement>? Achievements { get; set; }
        }

        private class FriendsResult : ApiResult
        {
            [JsonPropertyName("friends")] public List<string>? Friends { get; set; }
        }

        private class FriendRequestsResult : ApiResult
        {
            [JsonPropertyName("requests")] public List<FriendRequest>? Requests { get; set; }
        }

        private class PresenceResult
        {
            [JsonPropertyName("success")]  public bool    Success  { get; set; }
            [JsonPropertyName("lastSeen")] public string? LastSeen { get; set; }
        }

        private class MessagesResult : ApiResult
        {
            [JsonPropertyName("messages")] public List<Message>? Messages { get; set; }
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
