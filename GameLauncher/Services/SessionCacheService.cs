using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// A single saved login session stored on disk.
    /// Mirrors the web app's <c>gameOSUser</c> localStorage entry but also
    /// persists the API token so the launcher can silently restore the session
    /// on next launch (equivalent to the web's "Remember me" behaviour).
    /// </summary>
    public class CachedSession
    {
        [JsonPropertyName("username")]    public string Username    { get; set; } = "";
        [JsonPropertyName("email")]       public string Email       { get; set; } = "";
        [JsonPropertyName("token")]       public string Token       { get; set; } = "";
        [JsonPropertyName("avatarColor")] public string AvatarColor { get; set; } = "#1e90ff";
        [JsonPropertyName("savedAt")]     public string SavedAt     { get; set; } = "";
        [JsonPropertyName("rememberMe")]  public bool   RememberMe  { get; set; }
    }

    /// <summary>
    /// Reads and writes the local session cache file.
    ///
    /// The cache file is stored at:
    ///   Windows : %APPDATA%\GameOS\sessions.json
    ///   Linux   : ~/.config/GameOS/sessions.json
    ///   macOS   : ~/Library/Application Support/GameOS/sessions.json
    ///
    /// This reproduces the same "remember me → localStorage" pattern used by
    /// the Game.OS website so that users only need to enter their credentials
    /// once per device.
    /// </summary>
    public class SessionCacheService
    {
        private static readonly string CacheDir =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "GameOS");

        private static readonly string CacheFile =
            Path.Combine(CacheDir, "sessions.json");

        private static readonly JsonSerializerOptions _json =
            new() { WriteIndented = true };

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Persist a new (or updated) session for <paramref name="username"/>.
        /// If <c>RememberMe</c> is <c>false</c> the token is not written, so the
        /// account still appears in the quick-login panel but will require a
        /// password on the next launch — exactly like the web's sessionStorage.
        /// </summary>
        public void SaveSession(CachedSession session)
        {
            var sessions = LoadAll();

            // Replace existing entry for the same username (case-insensitive)
            sessions.RemoveAll(s =>
                string.Equals(s.Username, session.Username,
                              StringComparison.OrdinalIgnoreCase));

            // Most-recently-used first
            sessions.Insert(0, session);

            WriteAll(sessions);
        }

        /// <summary>
        /// Returns the most-recently-used session that has a saved token
        /// (i.e. the user ticked "Remember me"), or <c>null</c> if none.
        /// </summary>
        public CachedSession? GetRememberedSession()
            => LoadAll().FirstOrDefault(s => s.RememberMe && !string.IsNullOrEmpty(s.Token));

        /// <summary>
        /// Returns all saved accounts (with or without tokens) for display in
        /// the quick-login panel.
        /// </summary>
        public List<SavedSession> GetSavedAccounts()
            => LoadAll()
               .Select(s => new SavedSession
               {
                   Username    = s.Username,
                   DisplayName = s.Username,
                   AvatarColor = s.AvatarColor,
                   SavedAt     = s.SavedAt,
               })
               .ToList();

        /// <summary>
        /// Returns the <see cref="CachedSession"/> for a specific username, or
        /// <c>null</c> if not found.
        /// </summary>
        public CachedSession? GetSession(string username)
            => LoadAll().FirstOrDefault(s =>
               string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Remove the saved token for a specific user (logout without removing
        /// the account from the quick-login panel).
        /// </summary>
        public void ClearToken(string username)
        {
            var sessions = LoadAll();
            var entry = sessions.FirstOrDefault(s =>
                string.Equals(s.Username, username, StringComparison.OrdinalIgnoreCase));
            if (entry != null)
            {
                entry.Token      = "";
                entry.RememberMe = false;
            }
            WriteAll(sessions);
        }

        /// <summary>Remove all saved sessions (full logout / clear data).</summary>
        public void ClearAll()
        {
            try { File.Delete(CacheFile); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                System.Diagnostics.Debug.WriteLine($"[SessionCache] Could not delete session file: {ex.Message}");
            }
        }

        // ── Private helpers ───────────────────────────────────────────────────

        private List<CachedSession> LoadAll()
        {
            try
            {
                if (!File.Exists(CacheFile)) return new List<CachedSession>();
                var json = File.ReadAllText(CacheFile);
                return JsonSerializer.Deserialize<List<CachedSession>>(json) ?? new();
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                return new List<CachedSession>();
            }
        }

        private void WriteAll(List<CachedSession> sessions)
        {
            try
            {
                Directory.CreateDirectory(CacheDir);
                File.WriteAllText(CacheFile,
                    JsonSerializer.Serialize(sessions, _json));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                System.Diagnostics.Debug.WriteLine($"[SessionCache] Could not write sessions: {ex.Message}");
            }
        }
    }
}
