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
    /// Version comparison uses the semantic-version tag attached to each GitHub Release
    /// (e.g. <c>v1.2.0</c>).  The current application version is read from the
    /// assembly <c>FileVersion</c> attribute so it always stays in sync with the
    /// published build.
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

        /// <summary>Minimum interval between GitHub API checks (24 hours).</summary>
        private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(24);

        // ── Public surface ─────────────────────────────────────────────────────

        /// <summary>
        /// Returns the current application version as a <see cref="Version"/> object.
        /// Falls back to <c>0.0.0.0</c> when the version cannot be determined.
        /// </summary>
        public static Version CurrentVersion
        {
            get
            {
                try
                {
                    var fv = System.Diagnostics.FileVersionInfo.GetVersionInfo(
                        System.Reflection.Assembly.GetEntryAssembly()?.Location ?? "");
                    if (!string.IsNullOrEmpty(fv.FileVersion) &&
                        Version.TryParse(fv.FileVersion, out var v))
                        return v;
                }
                catch { /* best-effort */ }
                return new Version(0, 0, 0, 0);
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
        /// <returns>
        /// A <see cref="UpdateCheckResult"/> describing what happened (no update,
        /// update available, download complete, or any error that occurred).
        /// </returns>
        public static async Task<UpdateCheckResult> CheckForAppUpdateAsync(
            CancellationToken ct = default)
        {
            try
            {
                // Rate-limit: skip if we checked recently
                if (WasCheckedRecently())
                    return new UpdateCheckResult(UpdateCheckStatus.CheckSkipped, null, null);

                // Fetch the latest release from GitHub
                var release = await FetchLatestReleaseAsync(ct).ConfigureAwait(false);
                if (release == null)
                    return new UpdateCheckResult(UpdateCheckStatus.NoRelease, null, null);

                // Parse the tag (strips leading 'v' / 'V')
                string tag = release.TagName ?? "";
                if (!TryParseVersion(tag, out var remoteVersion))
                    return new UpdateCheckResult(UpdateCheckStatus.ParseError, tag, null);

                RecordLastChecked(tag);

                if (remoteVersion <= CurrentVersion)
                    return new UpdateCheckResult(UpdateCheckStatus.UpToDate, tag, null);

                // A newer version exists — find a downloadable asset
                var asset = PickAsset(release);
                if (asset == null)
                    return new UpdateCheckResult(UpdateCheckStatus.UpdateAvailable, tag, null);

                // Determine destination path
                string exeDir = Path.GetDirectoryName(
                    System.Reflection.Assembly.GetEntryAssembly()?.Location ?? "") ?? "";
                string destFileName = SanitiseFileName(asset.Name ?? $"GameOS-Update-{tag}.zip");
                string destPath     = Path.Combine(exeDir, destFileName);

                // Skip download when the file is already present
                if (File.Exists(destPath))
                    return new UpdateCheckResult(UpdateCheckStatus.AlreadyDownloaded, tag, destPath);

                // Download
                await DownloadAssetAsync(asset.BrowserDownloadUrl!, destPath, ct)
                    .ConfigureAwait(false);

                DevLogService.Log(
                    $"[LauncherUpdate] Downloaded v{remoteVersion} to '{destPath}'.");

                return new UpdateCheckResult(UpdateCheckStatus.Downloaded, tag, destPath);
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

            // Prefer a zip that looks like the main launcher package
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

        private static bool TryParseVersion(string tag, out Version version)
        {
            version = new Version(0, 0, 0, 0);
            var clean = tag.TrimStart('v', 'V');
            return Version.TryParse(clean, out version!);
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
