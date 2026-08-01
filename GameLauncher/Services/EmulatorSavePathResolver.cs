using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace GameLauncher.Services
{
    /// <summary>
    /// Resolves the on-disk save-data folder for an emulated game by combining
    /// the user-configured <c>SaveDataPath</c> (the emulator's save root) with a
    /// platform-specific sub-path pattern that contains the game's TitleID.
    ///
    /// <para>
    /// Most emulators store saves as <c>{saveRoot}/{titleId}/</c>.  A few use
    /// a deeper structure (e.g. RPCS3, Vita3K) which is captured in
    /// <see cref="_platformPatterns"/>.
    /// </para>
    /// </summary>
    public static class EmulatorSavePathResolver
    {
        // ── Pattern table ──────────────────────────────────────────────────────
        //
        // Key   : normalised platform name (lower-case).
        // Value : path segments relative to SaveDataPath; the last segment that
        //         equals "{titleId}" is substituted at resolve time.
        //
        // Emulator-specific overrides are checked first when the emulator name is
        // recognised; the platform-level default is used otherwise.

        private static readonly Dictionary<string, string[]> _platformPatterns =
            new(StringComparer.OrdinalIgnoreCase)
        {
            // Nintendo Switch — Ryujinx: <saveRoot>/<titleId>/
            ["switch"]         = new[] { "{titleId}" },

            // Xbox 360 — Xenia: resolved via special-case logic
            ["xbox 360"]       = new[] { "{titleId}" },

            // PS3 — RPCS3: <saveRoot>/dev_hdd0/home/{profileId}/savedata/<titleId>/
            ["ps3"]            = new[] { "dev_hdd0", "home", "{profileId}", "savedata", "{titleId}" },

            // PS Vita — Vita3K: <saveRoot>/ux0/user/00/savedata/<titleId>/
            ["ps vita"]        = new[] { "ux0", "user", "00", "savedata", "{titleId}" },

            // PS4 — RPCS4 / shadPS4: <saveRoot>/<titleId>/  (simple layout)
            ["ps4"]            = new[] { "{titleId}" },

            // PS1 — DuckStation: <saveRoot>/memcards/<gameName>.mcd  (resolved via special-case)
            ["ps1"]            = new[] { "memcards", "{titleId}" },

            // Nintendo 3DS — Citra: <saveRoot>/<titleId>/
            ["nintendo - 3ds"] = new[] { "{titleId}" },

            // Nintendo GameCube — Dolphin: <saveRoot>/GC/<titleId>/
            ["gamecube"]       = new[] { "GC", "{titleId}" },

            // Nintendo Wii — Dolphin: <saveRoot>/Wii/title/<highWord>/<lowWord>/data/
            // titleId is treated as the full folder name here; Dolphin uses a more complex
            // path but <saveRoot>/<titleId>/ is used as the best approximation.
            ["wii"]            = new[] { "Wii", "{titleId}" },
        };

        // Emulator-name overrides (take precedence over the platform default).
        // Keys: lower-case emulator name fragment (substring match).
        private static readonly Dictionary<string, string[]> _emulatorNamePatterns =
            new(StringComparer.OrdinalIgnoreCase)
        {
            // Ryujinx portable layout: <saveRoot>/<titleId>/
            ["ryujinx"]        = new[] { "{titleId}" },

            // RPCS3: <saveRoot>/dev_hdd0/home/{profileId}/savedata/<titleId>/
            ["rpcs3"]          = new[] { "dev_hdd0", "home", "{profileId}", "savedata", "{titleId}" },

            // Xenia has multiple layouts (canary / legacy). Resolved via special-case logic.
            ["xenia"]          = new[] { "{titleId}" },

            // Vita3K: same as PS Vita platform default
            ["vita3k"]         = new[] { "ux0", "user", "00", "savedata", "{titleId}" },

            // Dolphin (GameCube & Wii): <saveRoot>/GC/<titleId>/
            ["dolphin"]        = new[] { "GC", "{titleId}" },

            // DuckStation (PS1): <saveRoot>/memcards/<titleId>  (per-game memory card)
            ["duckstation"]    = new[] { "memcards", "{titleId}" },
        };

        // ── Public API ─────────────────────────────────────────────────────────

        /// <summary>
        /// Returns the fully-resolved path to the game's save folder, or
        /// <see langword="null"/> when the required inputs are missing / the
        /// platform pattern is unknown.
        /// </summary>
        /// <param name="platform">Platform name as stored in the game entry (e.g. "Switch", "PS3").</param>
        /// <param name="emulatorName">Emulator label from <see cref="Models.EmulatorSettings.EmulatorName"/>; may be empty.</param>
        /// <param name="saveDataPath">Root save folder from <see cref="Models.EmulatorSettings.SaveDataPath"/>; may be empty.</param>
        /// <param name="titleId">Platform-specific title ID for the game (e.g. "0100ADC022586000" for Switch).</param>
        /// <param name="gameTitle">
        /// Game display title used by platforms whose save files are title-based
        /// rather than TitleID-based (e.g. DuckStation PS1 <c>memcards/{gameTitle}.mcd</c>).
        /// </param>
        /// <param name="profileId">
        /// Emulator user profile ID; required for Xenia where the canonical save path is
        /// <c>Content/{profileId}/{titleId}/00000001/</c>
        /// (e.g. "E03000003D7E0695").  Pass <see langword="null"/> or empty for
        /// emulators that do not use a profile ID.
        /// </param>
        /// <returns>
        /// The resolved folder path, which may or may not exist on disk.
        /// Returns <see langword="null"/> when any required input is missing or
        /// no pattern is registered for the platform / emulator combination.
        /// </returns>
        public static string? Resolve(
            string  platform,
            string? emulatorName,
            string? saveDataPath,
            string? titleId,
            string? profileId = null,
            string? gameTitle = null)
        {
            if (string.IsNullOrWhiteSpace(saveDataPath)) return null;
            bool isDuckStation = IsDuckStation(platform, emulatorName);
            if (!isDuckStation && string.IsNullOrWhiteSpace(titleId)) return null;

            // Trim once and reuse throughout the method.
            string safeRoot    = NormalizeSaveRoot(saveDataPath);
            string safeTitleId = (titleId ?? "").Trim();
            if (string.IsNullOrWhiteSpace(safeRoot)) return null;

            if (isDuckStation)
                return ResolveDuckStationMemcardPath(safeRoot, safeTitleId, gameTitle);

            // Xenia canonical layout:
            //  - {saveRoot}/Content/{profileId}/{titleId}/
            // Also tolerate lower-case "content".
            string platformKey = (platform ?? "").Replace(" ", "", StringComparison.Ordinal).Trim();
            if ((emulatorName ?? "").Contains("xenia", StringComparison.OrdinalIgnoreCase) ||
                platformKey.Equals("xbox360", StringComparison.OrdinalIgnoreCase))
            {
                return ResolveXeniaPath(safeRoot, safeTitleId, profileId);
            }

            string[] segments = ResolvePattern(platform ?? "", emulatorName);
            if (segments.Length == 0) return null;

            // For patterns that require a {profileId} (RPCS3/PS3), use the supplied
            // profile when available; otherwise auto-detect from existing save data
            // and finally fall back to the standard RPCS3 offline profile "00000001".
            bool needsProfile = Array.Exists(segments, s =>
                string.Equals(s, "{profileId}", StringComparison.OrdinalIgnoreCase));
            if (needsProfile && string.IsNullOrWhiteSpace(profileId))
            {
                profileId = ResolveDefaultProfileId(platform ?? "", emulatorName, safeRoot, safeTitleId);
            }

            // Build the path by substituting {titleId} and {profileId} in each segment
            string safeProfileId  = profileId?.Trim() ?? "";
            var parts = new string[segments.Length + 1];
            parts[0] = safeRoot;
            for (int i = 0; i < segments.Length; i++)
            {
                if (string.Equals(segments[i], "{titleId}", StringComparison.OrdinalIgnoreCase))
                    parts[i + 1] = safeTitleId;
                else if (string.Equals(segments[i], "{profileId}", StringComparison.OrdinalIgnoreCase))
                    parts[i + 1] = safeProfileId;
                else
                    parts[i + 1] = segments[i];
            }

            return Path.Combine(parts);
        }

        private static string NormalizeSaveRoot(string saveDataPath)
        {
            string root = (saveDataPath ?? "").Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(root)) return "";

            // Users sometimes paste/select the emulator executable; use its folder instead.
            if (LooksLikeExecutablePath(root))
            {
                string? dir = Path.GetDirectoryName(root);
                if (!string.IsNullOrWhiteSpace(dir))
                    return dir.Trim();
            }

            return root;
        }

        private static bool LooksLikeExecutablePath(string path)
        {
            string ext = (Path.GetExtension(path) ?? "").Trim();
            return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".bat", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".sh", StringComparison.OrdinalIgnoreCase)
                   || ext.Equals(".appimage", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsDuckStation(string platform, string? emulatorName)
        {
            string platformKey = (platform ?? "").Replace(" ", "", StringComparison.Ordinal).Trim();
            return platformKey.Equals("ps1", StringComparison.OrdinalIgnoreCase)
                || (emulatorName ?? "").Contains("duckstation", StringComparison.OrdinalIgnoreCase);
        }

        private static string ResolveDefaultProfileId(
            string platform,
            string? emulatorName,
            string saveRoot,
            string titleId)
        {
            string platformKey = (platform ?? "").Replace(" ", "", StringComparison.Ordinal).Trim();
            bool isRpcs3 =
                (emulatorName ?? "").Contains("rpcs3", StringComparison.OrdinalIgnoreCase) ||
                platformKey.Equals("ps3", StringComparison.OrdinalIgnoreCase);

            if (isRpcs3)
            {
                string? detected = TryDetectRpcs3ProfileId(saveRoot, titleId);
                if (!string.IsNullOrWhiteSpace(detected))
                    return detected;
            }

            return "00000001";
        }

        private static string? TryDetectRpcs3ProfileId(string saveRoot, string titleId)
        {
            if (string.IsNullOrWhiteSpace(saveRoot) || string.IsNullOrWhiteSpace(titleId))
                return null;

            try
            {
                string rootName = Path.GetFileName(
                    saveRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

                if (rootName.Equals("savedata", StringComparison.OrdinalIgnoreCase))
                {
                    string? directProfile = Path.GetFileName(Path.GetDirectoryName(saveRoot) ?? "");
                    if (!string.IsNullOrWhiteSpace(directProfile))
                        return directProfile;
                }

                string homeRoot = Path.Combine(saveRoot, "dev_hdd0", "home");
                if (!Directory.Exists(homeRoot))
                    return null;

                foreach (string profileDir in Directory.EnumerateDirectories(homeRoot))
                {
                    string candidate = Path.Combine(profileDir, "savedata", titleId);
                    if (Directory.Exists(candidate))
                        return Path.GetFileName(profileDir);
                }

                string? firstProfile = Directory.EnumerateDirectories(homeRoot)
                    .Select(Path.GetFileName)
                    .FirstOrDefault(name => !string.IsNullOrWhiteSpace(name));
                if (!string.IsNullOrWhiteSpace(firstProfile))
                    return firstProfile;
            }
            catch { /* best-effort */ }

            return null;
        }

        private static string ResolveDuckStationMemcardsRoot(string saveRoot)
        {
            string rootName = Path.GetFileName(
                saveRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if (rootName.Equals("memcards", StringComparison.OrdinalIgnoreCase))
                return saveRoot;

            string memcards = Path.Combine(saveRoot, "memcards");
            if (Directory.Exists(memcards))
                return memcards;

            return memcards;
        }

        private static string? ResolveDuckStationMemcardPath(
            string saveRoot,
            string titleId,
            string? gameTitle)
        {
            string memcardsRoot = ResolveDuckStationMemcardsRoot(saveRoot);
            var identifiers = new List<string>();

            void AddId(string? value)
            {
                if (string.IsNullOrWhiteSpace(value)) return;
                string trimmed = value.Trim();
                if (!identifiers.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
                    identifiers.Add(trimmed);
            }

            AddId(titleId);
            AddId(gameTitle);

            if (Directory.Exists(memcardsRoot))
            {
                try
                {
                    foreach (string file in Directory.EnumerateFiles(memcardsRoot, "*.mcd", SearchOption.TopDirectoryOnly))
                    {
                        string stem = Path.GetFileNameWithoutExtension(file);
                        if (identifiers.Contains(stem, StringComparer.OrdinalIgnoreCase))
                            return file;
                    }

                    foreach (string file in Directory.EnumerateFiles(memcardsRoot, "*.mcd", SearchOption.TopDirectoryOnly))
                    {
                        string stem = Path.GetFileNameWithoutExtension(file);
                        // Pass 2a: normalize the full stem (minus numeric card suffix)
                        string normalizedStem = NormalizeLooseToken(RemoveDuckStationCardSuffix(stem));
                        // Pass 2b: also try with region/language parenthetical groups stripped
                        // e.g. "Yetisports Deluxe (Europe) (En,Fr,De,Es,It)_1" → "Yetisports Deluxe"
                        string strippedStem = StripParenthesizedSuffixes(RemoveDuckStationCardSuffix(stem));
                        string normalizedStrippedStem = NormalizeLooseToken(strippedStem);
                        foreach (string id in identifiers)
                        {
                            string normalizedId = NormalizeLooseToken(id);
                            if (normalizedStem.Equals(normalizedId, StringComparison.Ordinal) ||
                                normalizedStrippedStem.Equals(normalizedId, StringComparison.Ordinal))
                                return file;
                        }
                    }
                }
                catch { /* best-effort */ }
            }

            if (!string.IsNullOrWhiteSpace(gameTitle))
                return Path.Combine(memcardsRoot, $"{SanitizeFileStem(gameTitle)}.mcd");
            if (!string.IsNullOrWhiteSpace(titleId))
                return Path.Combine(memcardsRoot, $"{SanitizeFileStem(titleId)}.mcd");

            return null;
        }

        private static string RemoveDuckStationCardSuffix(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return value;
            int underscore = value.LastIndexOf('_');
            if (underscore <= 0 || underscore == value.Length - 1)
                return value;

            string suffix = value[(underscore + 1)..];
            return suffix.All(char.IsDigit) ? value[..underscore] : value;
        }

        /// <summary>
        /// Strips trailing parenthesized groups from a file stem so that region and
        /// language tags appended by No-Intro / Redump naming conventions are removed
        /// before a fuzzy title comparison.
        ///
        /// Example: "Yetisports Deluxe (Europe) (En,Fr,De,Es,It)" → "Yetisports Deluxe"
        /// </summary>
        private static string StripParenthesizedSuffixes(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return value;
            // Repeatedly remove the last (...) group and any preceding whitespace
            // until there is nothing more to remove.
            string result = value.TrimEnd();
            while (result.EndsWith(')'))
            {
                int closeIdx = result.Length - 1;
                int openIdx  = result.LastIndexOf('(');
                if (openIdx < 0) break;
                result = result[..openIdx].TrimEnd();
            }
            return result;
        }

        private static string NormalizeLooseToken(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "";
            var chars = new List<char>(value.Length);
            foreach (char c in value.Trim().ToLowerInvariant())
            {
                if (char.IsLetterOrDigit(c))
                    chars.Add(c);
            }
            return new string(chars.ToArray());
        }

        private static string SanitizeFileStem(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "";
            string sanitized = value.Trim();
            foreach (char invalid in Path.GetInvalidFileNameChars())
                sanitized = sanitized.Replace(invalid, '_');
            return sanitized;
        }

        // Returns null when no profile ID is available and one cannot be auto-detected,
        // since Xenia saves live under Content/{profileId}/{titleId}/.
        private static string? ResolveXeniaPath(string saveRoot, string titleId, string? profileId)
        {
            string safeProfileId = (profileId ?? "").Trim();
            string contentRoot = ResolveXeniaContentRoot(saveRoot);

            if (!string.IsNullOrWhiteSpace(safeProfileId))
            {
                // Canonical save location: Content/{profileId}/{titleId}/00000001/
                return Path.Combine(contentRoot, safeProfileId, titleId, "00000001");
            }

            // Auto-detect profile from existing content folder: first try to find a
            // profile that already has a folder for this specific titleId.
            if (Directory.Exists(contentRoot))
            {
                string? detectedProfile = TryDetectXeniaProfileId(saveRoot, titleId);
                if (!string.IsNullOrWhiteSpace(detectedProfile))
                    return Path.Combine(contentRoot, detectedProfile, titleId, "00000001");

                // Fallback: use the first profile folder found even if it does not yet
                // contain this game's titleId (e.g. backing up a freshly-installed game).
                string? anyProfile = TryDetectAnyXeniaProfileId(contentRoot);
                if (!string.IsNullOrWhiteSpace(anyProfile))
                    return Path.Combine(contentRoot, anyProfile, titleId, "00000001");
            }

            // No profile known and none detected — use the standard Xenia offline
            // default profile ("00000001"), which is the 8-digit hex profile created
            // automatically by Xenia for local/offline play.
            return Path.Combine(contentRoot, "00000001", titleId, "00000001");
        }

        // ── Helpers ────────────────────────────────────────────────────────────

        private static string ResolveXeniaContentRoot(string saveRoot)
        {
            string rootName = Path.GetFileName(
                saveRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

            // Users may set SaveDataPath directly to ".../Content". In that case,
            // treat the provided path as the content root and do not append again.
            if (rootName.Equals("content", StringComparison.OrdinalIgnoreCase))
                return saveRoot;

            string upperContent = Path.Combine(saveRoot, "Content");
            if (Directory.Exists(upperContent)) return upperContent;

            string lowerContent = Path.Combine(saveRoot, "content");
            if (Directory.Exists(lowerContent)) return lowerContent;

            // Prefer Xenia's typical casing for newly created paths.
            return upperContent;
        }

        /// <summary>
        /// Scans <c>{saveDataPath}/content/</c> for a profile sub-directory that
        /// contains a <c>{titleId}</c> folder, returning the first match.
        /// This lets Xenia saves be located even when the user has not manually
        /// entered their profile ID in the emulator settings.
        /// </summary>
        private static string? TryDetectXeniaProfileId(string saveDataPath, string titleId)
        {
            try
            {
                string contentDir = ResolveXeniaContentRoot(saveDataPath);
                if (!Directory.Exists(contentDir)) return null;

                foreach (string profileDir in Directory.EnumerateDirectories(contentDir))
                {
                    string candidate = Path.Combine(profileDir, titleId);
                    if (Directory.Exists(candidate))
                        return Path.GetFileName(profileDir);
                }
            }
            catch { /* best-effort */ }

            return null;
        }

        // Xbox 360 / Xenia profile IDs are 8–16 uppercase hex characters,
        // e.g. "00000001" (offline/default) or "E03000003D7E0695" (gamertag-derived).
        private const int MinXeniaProfileIdLength = 8;
        private const int MaxXeniaProfileIdLength = 16;

        /// <summary>
        /// Scans <paramref name="contentRoot"/> for the first sub-directory whose name
        /// is 8–16 hex characters — the standard Xenia profile folder format
        /// (e.g. "00000001" for offline play, "E03000003D7E0695" for a gamertag profile).
        /// Used as a last-resort fallback when game-specific detection fails.
        /// </summary>
        private static string? TryDetectAnyXeniaProfileId(string contentRoot)
        {
            try
            {
                if (!Directory.Exists(contentRoot)) return null;

                foreach (string profileDir in Directory.EnumerateDirectories(contentRoot))
                {
                    string name = Path.GetFileName(profileDir);
                    if (name.Length >= MinXeniaProfileIdLength &&
                        name.Length <= MaxXeniaProfileIdLength &&
                        IsHexString(name))
                        return name;
                }
            }
            catch (Exception ex)
            {
                DevLogService.Log($"[EmulatorSavePathResolver] TryDetectAnyXeniaProfileId failed for '{contentRoot}': {ex.Message}");
            }

            return null;
        }

        private static string[] ResolvePattern(string platform, string? emulatorName)
        {
            // 1. Try emulator-name override (substring, case-insensitive)
            if (!string.IsNullOrWhiteSpace(emulatorName))
            {
                foreach (var kvp in _emulatorNamePatterns)
                {
                    if (emulatorName.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
                        return kvp.Value;
                }
            }

            // 2. Fall back to platform-level default
            if (_platformPatterns.TryGetValue(platform ?? "", out var pattern))
                return pattern;

            return Array.Empty<string>();
        }

        private static bool IsHexString(string value)
        {
            foreach (char c in value)
            {
                if (!Uri.IsHexDigit(c))
                    return false;
            }
            return value.Length > 0;
        }
    }
}
