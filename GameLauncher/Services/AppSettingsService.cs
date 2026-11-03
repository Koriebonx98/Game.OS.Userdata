using System;
using System.IO;
using System.Text.Json;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// Loads and saves application-wide settings from/to the user's AppData folder.
    /// Settings are stored at <c>%APPDATA%\GameOS\appsettings.json</c>.
    /// </summary>
    public static class AppSettingsService
    {
        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "GameOS", "appsettings.json");

        private static readonly JsonSerializerOptions _jsonOpts =
            new JsonSerializerOptions { WriteIndented = true };

        /// <summary>
        /// Loads the saved application settings.
        /// Returns a default <see cref="AppSettings"/> instance when no file exists.
        /// </summary>
        public static AppSettings Load()
        {
            var settings = LoadRaw();
            if (StoreAccountsService.CurrentUser == null) return settings;

            // The legacy global Steam credentials move to the first account that signs in; after that they are per-account.
            if (!StoreAccountsService.HasFile &&
                (!string.IsNullOrWhiteSpace(settings.SteamApiKey) || !string.IsNullOrWhiteSpace(settings.SteamUserId)))
            {
                StoreAccountsService.Set("Steam", settings.SteamApiKey, settings.SteamUserId, "");
                Save(settings);
            }
            var steam = StoreAccountsService.Get("Steam");
            settings.SteamApiKey = steam.ApiKey;
            settings.SteamUserId = steam.UserId;
            return settings;
        }

        private static AppSettings LoadRaw()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
            }
            catch { /* best-effort */ }
            return new AppSettings();
        }

        /// <summary>Persists the given settings to disk.</summary>
        public static void Save(AppSettings settings)
        {
            if (StoreAccountsService.CurrentUser != null)
            {
                // Steam credentials belong to the signed-in account and never go into the shared settings file.
                StoreAccountsService.Set("Steam", settings.SteamApiKey, settings.SteamUserId, StoreAccountsService.Get("Steam").Token);
                settings = JsonSerializer.Deserialize<AppSettings>(JsonSerializer.Serialize(settings)) ?? settings;
                settings.SteamApiKey = "";
                settings.SteamUserId = "";
            }
            try
            {
                string? dir = Path.GetDirectoryName(SettingsPath);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);
                File.WriteAllText(SettingsPath, JsonSerializer.Serialize(settings, _jsonOpts));
            }
            catch { /* best-effort */ }
        }
    }
}
