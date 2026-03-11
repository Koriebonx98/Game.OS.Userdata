using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// Loads and saves per-game launch settings from/to the user's AppData folder.
    /// Each game gets its own JSON file at:
    ///   %APPDATA%/GameOS/GameSettings/{SafeTitle}.json
    /// </summary>
    public static class GameSettingsService
    {
        private static readonly string SettingsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "GameOS", "GameSettings");

        private static readonly JsonSerializerOptions _jsonOpts =
            new JsonSerializerOptions { WriteIndented = true };

        private static readonly char[] _invalidFileNameChars = Path.GetInvalidFileNameChars();

        /// <summary>
        /// Loads saved settings for the given game title.
        /// Returns a default (empty) <see cref="GameSettings"/> when no file exists.
        /// </summary>
        public static GameSettings Load(string gameTitle)
        {
            try
            {
                var path = GetPath(gameTitle);
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    return JsonSerializer.Deserialize<GameSettings>(json)
                           ?? new GameSettings { GameTitle = gameTitle };
                }
            }
            catch { /* best-effort */ }

            return new GameSettings { GameTitle = gameTitle };
        }

        /// <summary>Persists the given settings to disk.</summary>
        public static void Save(GameSettings settings)
        {
            try
            {
                Directory.CreateDirectory(SettingsDir);
                var path = GetPath(settings.GameTitle);
                File.WriteAllText(path, JsonSerializer.Serialize(settings, _jsonOpts));
            }
            catch { /* best-effort */ }
        }

        private static string GetPath(string title)
        {
            // Build a safe filename: keep alphanumeric and common chars, replace
            // invalid characters with '_', then append a short hash of the original
            // title to prevent collisions between sanitised names (e.g. "Game:One"
            // and "GameOne" would otherwise produce the same filename).
            var safe = string.Concat(title.Select(c =>
                _invalidFileNameChars.Contains(c) ? '_' : c));
            if (string.IsNullOrWhiteSpace(safe)) safe = "unknown";

            // Append first 8 chars of a stable SHA-256 hash of the original title
            using var sha = System.Security.Cryptography.SHA256.Create();
            var hashBytes = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(title));
            var hashShort = BitConverter.ToString(hashBytes, 0, 4).Replace("-", "");

            return Path.Combine(SettingsDir, $"{safe}_{hashShort}.settings.json");
        }
    }
}
