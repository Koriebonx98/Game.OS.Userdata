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
    /// Settings are stored at %APPDATA%/GameOS/EmulatorSettings/{Platform}.emu.json
    /// Each file is a JSON array of <see cref="EmulatorSettings"/>, allowing multiple
    /// emulators to be configured per platform.  Single-object legacy files are
    /// automatically upgraded to an array on first read.
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
        /// Loads ALL saved emulator configurations for the given platform.
        /// Returns a list with one default (empty) entry when no file exists.
        /// Handles both the legacy single-object format and the new array format.
        /// </summary>
        public static List<EmulatorSettings> LoadAll(string platform)
        {
            try
            {
                var path = GetPath(platform);
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    if (root.ValueKind == JsonValueKind.Array)
                    {
                        // New format: array of emulator settings
                        var list = JsonSerializer.Deserialize<List<EmulatorSettings>>(json) ?? new();
                        if (list.Count > 0) return list;
                    }
                    else if (root.ValueKind == JsonValueKind.Object)
                    {
                        // Legacy format: single object → wrap in list
                        var single = JsonSerializer.Deserialize<EmulatorSettings>(json);
                        if (single != null) return new List<EmulatorSettings> { single };
                    }
                }
            }
            catch { /* best-effort */ }

            return new List<EmulatorSettings>
            {
                new EmulatorSettings { Platform = platform, Arguments = "{rom}" }
            };
        }

        /// <summary>
        /// Loads the first enabled emulator for the given platform.
        /// Returns a default instance (empty paths) when no file exists.
        /// </summary>
        public static EmulatorSettings Load(string platform)
        {
            var all = LoadAll(platform);
            return all.FirstOrDefault(e => e.Enabled)
                   ?? all.FirstOrDefault()
                   ?? new EmulatorSettings { Platform = platform, Arguments = "{rom}" };
        }

        /// <summary>
        /// Returns the emulator with the given name for <paramref name="platform"/>,
        /// or the first enabled one if the name is not found / empty.
        /// </summary>
        public static EmulatorSettings LoadByName(string platform, string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return Load(platform);
            var all = LoadAll(platform);
            return all.FirstOrDefault(e => string.Equals(e.EmulatorName, name, StringComparison.OrdinalIgnoreCase))
                   ?? Load(platform);
        }

        /// <summary>Persists the full list of emulator settings for the given platform to disk.</summary>
        public static void SaveAll(string platform, List<EmulatorSettings> settings)
        {
            try
            {
                // Ensure every entry carries the platform name
                foreach (var s in settings)
                    s.Platform = platform;

                Directory.CreateDirectory(SettingsDir);
                File.WriteAllText(
                    GetPath(platform),
                    JsonSerializer.Serialize(settings, _jsonOpts));
            }
            catch { /* best-effort */ }
        }

        /// <summary>Persists emulator settings for the given platform to disk (single-emulator helper).</summary>
        public static void Save(EmulatorSettings settings)
        {
            var all = LoadAll(settings.Platform);
            // Replace the first entry or add a new one
            if (all.Count == 0) all.Add(settings);
            else all[0] = settings;
            SaveAll(settings.Platform, all);
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
