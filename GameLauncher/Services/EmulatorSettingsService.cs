using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// Loads and saves per-platform emulator settings to AppData.
    /// Settings are stored at %APPDATA%/GameOS/EmulatorSettings/{Platform}.json
    /// </summary>
    public static class EmulatorSettingsService
    {
        private static readonly string SettingsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "GameOS", "EmulatorSettings");

        private static readonly JsonSerializerOptions _jsonOpts =
            new JsonSerializerOptions { WriteIndented = true };

        private static readonly char[] _invalidFileNameChars = Path.GetInvalidFileNameChars();

        /// <summary>Returns the list of all supported non-PC platforms.</summary>
        public static IReadOnlyList<string> SupportedPlatforms { get; } = new[]
        {
            "PS1", "PS2", "PS3", "PS4", "PS5", "PSP", "PS Vita",
            "Xbox 360", "Xbox One",
            "Switch", "Nintendo - 3DS", "Nintendo - GameBoy",
        };

        /// <summary>
        /// Loads saved emulator settings for the given platform.
        /// Returns a default instance (empty paths) when no file exists.
        /// </summary>
        public static EmulatorSettings Load(string platform)
        {
            try
            {
                var path = GetPath(platform);
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    return JsonSerializer.Deserialize<EmulatorSettings>(json)
                           ?? new EmulatorSettings { Platform = platform };
                }
            }
            catch { /* best-effort */ }

            return new EmulatorSettings { Platform = platform, Arguments = "{rom}" };
        }

        /// <summary>Persists emulator settings for the given platform to disk.</summary>
        public static void Save(EmulatorSettings settings)
        {
            try
            {
                Directory.CreateDirectory(SettingsDir);
                File.WriteAllText(
                    GetPath(settings.Platform),
                    JsonSerializer.Serialize(settings, _jsonOpts));
            }
            catch { /* best-effort */ }
        }

        private static string GetPath(string platform)
        {
            // Sanitise platform name for use as a filename
            var safe = string.Concat(platform.Select(c =>
                _invalidFileNameChars.Contains(c) ? '_' : c));
            if (string.IsNullOrWhiteSpace(safe)) safe = "unknown";
            return Path.Combine(SettingsDir, $"{safe}.emu.json");
        }
    }
}
