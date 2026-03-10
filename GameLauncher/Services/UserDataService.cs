using System;
using System.IO;

namespace GameLauncher.Services
{
    /// <summary>
    /// Creates and manages the per-user data folder hierarchy beneath the
    /// application directory, providing a local backup store for saves,
    /// media recordings and screenshots.
    ///
    /// Folder layout (relative to the executable directory):
    /// <code>
    ///   Data/
    ///   Data/{username}/
    ///   Data/{username}/GameSaves/{platform}/   (one per known platform)
    ///   Data/{username}/Media/Videos/Recordings/
    ///   Data/{username}/Media/Images/ScreenShots/
    ///   Data/{username}/Media/Audio/Recordings/
    /// </code>
    /// </summary>
    public static class UserDataService
    {
        /// <summary>Known game platforms — a GameSaves sub-folder is created for each.</summary>
        private static readonly string[] Platforms =
            { "PC", "PS3", "PS4", "Switch", "Xbox 360" };

        /// <summary>
        /// Root of the Data directory, always next to the running executable.
        /// </summary>
        public static readonly string DataRoot =
            Path.Combine(AppContext.BaseDirectory, "Data");

        /// <summary>
        /// Creates the full data folder structure for <paramref name="username"/>.
        /// Any folders that already exist are silently skipped.
        /// </summary>
        public static void CreateUserFolders(string username)
        {
            if (string.IsNullOrWhiteSpace(username)) return;

            // Sanitise the username so it is safe as a folder name
            string safeUser = SanitiseFolderName(username);

            string userRoot = Path.Combine(DataRoot, safeUser);

            // GameSaves per platform
            foreach (var platform in Platforms)
            {
                string safePlatform = SanitiseFolderName(platform);
                EnsureDir(Path.Combine(userRoot, "GameSaves", safePlatform));
            }

            // Media sub-trees
            EnsureDir(Path.Combine(userRoot, "Media", "Videos",  "Recordings"));
            EnsureDir(Path.Combine(userRoot, "Media", "Images",  "ScreenShots"));
            EnsureDir(Path.Combine(userRoot, "Media", "Audio",   "Recordings"));
        }

        /// <summary>Returns the GameSaves path for a specific platform.</summary>
        public static string GetGameSavesPath(string username, string platform)
        {
            string safeUser     = SanitiseFolderName(username);
            string safePlatform = SanitiseFolderName(platform);
            return Path.Combine(DataRoot, safeUser, "GameSaves", safePlatform);
        }

        /// <summary>Returns the ScreenShots path for a user.</summary>
        public static string GetScreenShotsPath(string username) =>
            Path.Combine(DataRoot, SanitiseFolderName(username), "Media", "Images", "ScreenShots");

        /// <summary>Returns the Video Recordings path for a user.</summary>
        public static string GetVideoRecordingsPath(string username) =>
            Path.Combine(DataRoot, SanitiseFolderName(username), "Media", "Videos", "Recordings");

        /// <summary>Returns the Audio Recordings path for a user.</summary>
        public static string GetAudioRecordingsPath(string username) =>
            Path.Combine(DataRoot, SanitiseFolderName(username), "Media", "Audio", "Recordings");

        // ── helpers ───────────────────────────────────────────────────────────

        private static void EnsureDir(string path)
        {
            try { Directory.CreateDirectory(path); }
            catch { /* best-effort; folder may already exist or path may be read-only */ }
        }

        /// <summary>
        /// Strips characters that are illegal in Windows / macOS / Linux folder names.
        /// ":" is the main culprit on Windows; also removes /\*?|"&lt;&gt;.
        /// </summary>
        internal static string SanitiseFolderName(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;
            // Replace colon with hyphen (matches the rest of the codebase convention)
            name = name.Replace(':', '-');
            // Remove other characters that are invalid on Windows
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c.ToString(), "");
            return name.Trim();
        }
    }
}
