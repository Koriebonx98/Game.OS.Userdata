using System;
using System.IO;
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
            // Strip characters that are invalid in file names on any OS
            var safe = string.Concat(title.Split(Path.GetInvalidFileNameChars()));
            if (string.IsNullOrWhiteSpace(safe)) safe = "unknown";
            return Path.Combine(SettingsDir, $"{safe}.settings.json");
        }
    }
}
