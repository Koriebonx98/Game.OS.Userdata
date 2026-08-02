using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// Checks GitHub Releases for a newer version of the Game.OS launcher and
    /// downloads the release asset to the same directory as the running executable.
    ///
    /// Version comparison uses the dot-separated tag attached to each GitHub Release
    /// (e.g. <c>v1.2.0</c> or <c>v1.0.7.6.5.0.9.9.6.5</c>).  The current application
    /// version is read from the assembly informational version so launcher builds can
    /// track the repository's multi-part Git tag format.
    ///
    /// The download is placed alongside the exe as
    /// <c>GameOS-Update-{version}.zip</c> (or the asset's original file name if it
    /// differs).  The user is notified via a toast; no files are replaced while the
    /// application is running.
    /// </summary>
    public static class LauncherUpdateService
    {
        // ── Configuration ──────────────────────────────────────────────────────

        private const string Owner = "Koriebonx98";
        private const string Repo  = "Game.OS.Userdata";

        /// <summary>
        /// File in the exe directory that stores the last-checked release tag so we
        /// don't hammer the GitHub API on every startup.
        /// </summary>
        private static readonly string LastCheckedPath = Path.Combine(
            Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly()?.Location ?? "") ?? "",
            ".gameos-last-update-check");

        /// <summary>Minimum interval between GitHub API checks (12 hours).</summary>
        private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(12);

        // ── Public surface ─────────────────────────────────────────────────────

        /// <summary>
        /// Writes a <c>Version.json</c> file next to the running executable containing
        /// the current version tag.  Called on startup so the version is always
        /// machine-readable without inspecting assembly metadata.
        /// </summary>
        public static void WriteVersionJson()
        {
            try
            {
                string exeDir = Path.GetDirectoryName(
                    System.Reflection.Assembly.GetEntryAssembly()?.Location ?? "") ?? "";
                string path = Path.Combine(exeDir, "Version.json");
                var obj = new { version = CurrentVersionTag, channel = "stable" };
                File.WriteAllText(path, JsonSerializer.Serialize(obj,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* best-effort */ }
        }

        /// <summary>
        /// Launches <c>GameOS.Updater.exe</c> (located next to the running exe) to
        /// extract the downloaded zip, replace the launcher files, and relaunch Game.OS.
        /// </summary>
        /// <param name="zipPath">Full path to the downloaded update zip.</param>
        /// <param name="username">Username for auto-login after the update completes.</param>
        public static void LaunchUpdater(string zipPath, string? username = null)
        {
            try
            {
                string exeDir = Path.GetDirectoryName(
                    System.Reflection.Assembly.GetEntryAssembly()?.Location ?? "") ?? "";

                // Try both the .exe name (Windows) and bare binary name (Linux/macOS).
                string updaterExe = Path.Combine(exeDir, "GameOS.Updater.exe");
                if (!File.Exists(updaterExe))
                    updaterExe = Path.Combine(exeDir, "GameOS.Updater");

                if (!File.Exists(updaterExe))
                {
                    DevLogService.Log("[LauncherUpdate] Updater not found – cannot apply update.");
                    return;
                }

                string launcherPath = System.Reflection.Assembly.GetEntryAssembly()?.Location ?? "";
                var args = $"--zip \"{zipPath}\" --target \"{exeDir}\" --launcher \"{launcherPath}\"";
                if (!string.IsNullOrWhiteSpace(username))
                    args += $" --username \"{username}\"";

                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = updaterExe,
                    Arguments       = args,
                    UseShellExecute = false,
                });
            }
            catch (Exception ex)
            {
                DevLogService.Log($"[LauncherUpdate] Failed to launch updater: {ex.Message}");
            }
        }

        /// <summary>
        /// Returns the current application version tag with a leading <c>v</c>.
        /// Falls back to <c>v0.0.0.0</c> when the version cannot be determined.
        /// </summary>
        public static string CurrentVersionTag
        {
            get
            {
                try
                {
                    var asm = System.Reflection.Assembly.GetEntryAssembly();
                    if (asm != null)
                    {
                        var informational =
                            System.Reflection.CustomAttributeExtensions
                                .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm)
                                ?.InformationalVersion;
                        if (TryParseVersion(informational, out _, out var informationalTag))
                            return informationalTag;
                    }

                    var fv = System.Diagnostics.FileVersionInfo.GetVersionInfo(
                        asm?.Location ?? "");
                    if (TryParseVersion(fv.ProductVersion, out _, out var productTag))
                        return productTag;
                    if (TryParseVersion(fv.FileVersion, out _, out var fileTag))
                        return fileTag;
                }
                catch { /* best-effort */ }
                return "v0.0.0.0";
            }
        }

        /// <summary>
        /// Checks the GitHub Releases API for a newer version of Game.OS.
        /// When a newer release is found and its asset has not already been downloaded,
        /// the asset is downloaded to the exe directory.
        ///
        /// <para>Calls are rate-limited to once per <see cref="CheckInterval"/>;
        /// duplicate downloads are skipped when the target file already exists.</para>
        /// </summary>
        /// <param name="force">When <see langword="true"/>, skips the rate-limit check (used by manual "Check for update" button).</param>
        /// <returns>
        /// A <see cref="UpdateCheckResult"/> describing what happened (no update,
        /// update available, download complete, or any error that occurred).
        /// </returns>
        public static async Task<UpdateCheckResult> CheckForAppUpdateAsync(
            bool force = false,
            CancellationToken ct = default)
        {
            try
            {
                // Rate-limit: skip if we checked recently (unless forced by user).
                if (!force && WasCheckedRecently())
                    return new UpdateCheckResult(UpdateCheckStatus.CheckSkipped, null, null);

                // Fetch the latest release from GitHub
                var release = await FetchLatestReleaseAsync(ct).ConfigureAwait(false);
                if (release == null)
                    return new UpdateCheckResult(UpdateCheckStatus.NoRelease, null, null);

                // Parse the tag (strips leading 'v' / 'V')
                string tag = release.TagName ?? "";
                if (!TryParseVersion(tag, out var remoteVersion, out var normalisedTag))
                    return new UpdateCheckResult(UpdateCheckStatus.ParseError, tag, null);

                RecordLastChecked(normalisedTag);

                if (!TryParseVersion(CurrentVersionTag, out var currentVersion, out _))
                    currentVersion = new[] { 0, 0, 0, 0 };

                if (CompareVersions(remoteVersion, currentVersion) <= 0)
                    return new UpdateCheckResult(UpdateCheckStatus.UpToDate, normalisedTag, null);

                // A newer version exists — find a downloadable asset
                var asset = PickAsset(release);
                if (asset == null)
                    return new UpdateCheckResult(UpdateCheckStatus.UpdateAvailable, normalisedTag, null);

                // Determine destination path
                string exeDir = Path.GetDirectoryName(
                    System.Reflection.Assembly.GetEntryAssembly()?.Location ?? "") ?? "";
                string destFileName = SanitiseFileName(asset.Name ?? $"GameOS-Update-{normalisedTag}.zip");
                string destPath     = Path.Combine(exeDir, destFileName);

                // Skip download when the file is already present
                if (File.Exists(destPath))
                    return new UpdateCheckResult(UpdateCheckStatus.AlreadyDownloaded, normalisedTag, destPath);

                // Download
                await DownloadAssetAsync(asset.BrowserDownloadUrl!, destPath, ct)
                    .ConfigureAwait(false);

                DevLogService.Log(
                    $"[LauncherUpdate] Downloaded {normalisedTag} to '{destPath}'.");

                return new UpdateCheckResult(UpdateCheckStatus.Downloaded, normalisedTag, destPath);
            }
            catch (Exception ex)
            {
                DevLogService.Log($"[LauncherUpdate] Check failed: {ex.Message}");
                return new UpdateCheckResult(UpdateCheckStatus.Error, null, null);
            }
        }

        // ── Private helpers ────────────────────────────────────────────────────

        private static bool WasCheckedRecently()
        {
            try
            {
                if (!File.Exists(LastCheckedPath)) return false;
                var raw = File.ReadAllText(LastCheckedPath).Trim();
                // Format: "tag|ISO8601Timestamp"
                int sep = raw.LastIndexOf('|');
                if (sep < 0) return false;
                if (!DateTime.TryParse(raw[(sep + 1)..],
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.RoundtripKind,
                        out var ts))
                    return false;
                return DateTime.UtcNow - ts < CheckInterval;
            }
            catch { return false; }
        }

        private static void RecordLastChecked(string tag)
        {
            try
            {
                File.WriteAllText(LastCheckedPath,
                    $"{tag}|{DateTime.UtcNow:O}");
            }
            catch { /* best-effort */ }
        }

        private static async Task<GitHubRelease?> FetchLatestReleaseAsync(CancellationToken ct)
        {
            var url = $"https://api.github.com/repos/{Owner}/{Repo}/releases/latest";
            using var http = new HttpClient();
            http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher/2.0");
            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github.v3+json");

            using var resp = await http.GetAsync(url, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;

            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return JsonSerializer.Deserialize<GitHubRelease>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }

        private static GitHubAsset? PickAsset(GitHubRelease release)
        {
            if (release.Assets == null || release.Assets.Length == 0) return null;

            // Prefer an OS-specific zip (windows / linux / osx in the filename).
            string osSuffix = OperatingSystem.IsWindows() ? "win"
                            : OperatingSystem.IsMacOS()   ? "osx"
                            : "linux";

            var osSpecific = release.Assets.FirstOrDefault(a =>
                a.Name != null &&
                a.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                a.Name.Contains(osSuffix, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrEmpty(a.BrowserDownloadUrl));

            if (osSpecific != null) return osSpecific;

            // Fall back to the first zip regardless of OS label.
            var preferred = release.Assets.FirstOrDefault(a =>
                a.Name != null &&
                a.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrEmpty(a.BrowserDownloadUrl));

            if (preferred != null) return preferred;

            // Fall back to the first downloadable asset
            return release.Assets.FirstOrDefault(a =>
                !string.IsNullOrEmpty(a.BrowserDownloadUrl));
        }

        private static async Task DownloadAssetAsync(string url, string destPath,
            CancellationToken ct)
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher/2.0");
            using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();

            string tmpPath = destPath + ".tmp";
            try
            {
                using (var fs   = new FileStream(tmpPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var body = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
                    await body.CopyToAsync(fs, ct).ConfigureAwait(false);

                // Atomic replace: rename tmp → final
                if (File.Exists(destPath)) File.Delete(destPath);
                File.Move(tmpPath, destPath);
            }
            catch
            {
                try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
                throw;
            }
        }

        private static int CompareVersions(int[] left, int[] right)
        {
            int count = Math.Max(left.Length, right.Length);
            for (int i = 0; i < count; i++)
            {
                int leftPart = i < left.Length ? left[i] : 0;
                int rightPart = i < right.Length ? right[i] : 0;
                if (leftPart != rightPart)
                    return leftPart.CompareTo(rightPart);
            }

            return 0;
        }

        private static bool TryParseVersion(string? tag, out int[] version, out string normalisedTag)
        {
            version = Array.Empty<int>();
            normalisedTag = "v0.0.0.0";
            if (string.IsNullOrWhiteSpace(tag))
                return false;

            var clean = tag.Trim();
            int suffixSep = clean.IndexOfAny(['+', '-', ' ']);
            if (suffixSep >= 0)
                clean = clean[..suffixSep];

            clean = clean.TrimStart('v', 'V');
            if (string.IsNullOrWhiteSpace(clean))
                return false;

            var parts = clean.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 0)
                return false;

            version = new int[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                if (!int.TryParse(parts[i], out version[i]))
                    return false;
            }

            normalisedTag = $"v{string.Join(".", version)}";
            return true;
        }

        private static string SanitiseFileName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return name;
        }

        // ── GitHub API DTOs ───────────────────────────────────────────────────

        private sealed class GitHubRelease
        {
            [System.Text.Json.Serialization.JsonPropertyName("tag_name")]
            public string? TagName { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("prerelease")]
            public bool Prerelease { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("draft")]
            public bool Draft { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("assets")]
            public GitHubAsset[]? Assets { get; set; }
        }

        private sealed class GitHubAsset
        {
            [System.Text.Json.Serialization.JsonPropertyName("name")]
            public string? Name { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("browser_download_url")]
            public string? BrowserDownloadUrl { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("size")]
            public long Size { get; set; }
        }
    }

    // ── Result type ───────────────────────────────────────────────────────────

    /// <summary>Outcome of a <see cref="LauncherUpdateService.CheckForAppUpdateAsync"/> call.</summary>
    public sealed class UpdateCheckResult
    {
        public UpdateCheckStatus Status   { get; }
        /// <summary>The latest release tag (e.g. "v1.2.0"), or null when unavailable.</summary>
        public string?           Tag      { get; }
        /// <summary>Full path to the downloaded file, or null when no download was made.</summary>
        public string?           FilePath { get; }

        public bool IsUpdateDownloaded =>
            Status is UpdateCheckStatus.Downloaded or UpdateCheckStatus.AlreadyDownloaded;

        internal UpdateCheckResult(UpdateCheckStatus status, string? tag, string? filePath)
        {
            Status   = status;
            Tag      = tag;
            FilePath = filePath;
        }
    }

    /// <summary>Possible outcomes of <see cref="LauncherUpdateService.CheckForAppUpdateAsync"/>.</summary>
    public enum UpdateCheckStatus
    {
        /// <summary>The check was skipped because it ran recently.</summary>
        CheckSkipped,
        /// <summary>No releases found in the repository.</summary>
        NoRelease,
        /// <summary>The release tag could not be parsed as a version number.</summary>
        ParseError,
        /// <summary>The installed version is already up to date.</summary>
        UpToDate,
        /// <summary>A newer version exists but has no downloadable asset.</summary>
        UpdateAvailable,
        /// <summary>The update file was already downloaded in a previous check.</summary>
        AlreadyDownloaded,
        /// <summary>The update file was successfully downloaded this run.</summary>
        Downloaded,
        /// <summary>An error occurred during the check or download.</summary>
        Error,
    }
}
