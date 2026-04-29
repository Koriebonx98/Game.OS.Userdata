using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// Checks the GitHub releases API for a new version of Game.OS Launcher and,
    /// when the user confirms, downloads the OS-specific zip, extracts it in-place,
    /// and re-launches the updated application.
    ///
    /// Release asset naming convention expected in the repo:
    /// <list type="bullet">
    ///   <item><c>GameOS-Launcher-win-x64.zip</c>  — Windows</item>
    ///   <item><c>GameOS-Launcher-linux-x64.zip</c> — Linux</item>
    ///   <item><c>GameOS-Launcher-osx-x64.zip</c>   — macOS</item>
    /// </list>
    /// </summary>
    public static class AppUpdateService
    {
        // ── Constants ──────────────────────────────────────────────────────────

        /// <summary>
        /// The semantic version string of the currently running launcher.
        /// Bump this value in each release to allow the update checker to detect
        /// newer versions on GitHub.
        /// </summary>
        public const string CurrentVersion = "1.0.0";

        private const string GitHubOwner    = "Koriebonx98";
        private const string GitHubRepo     = "Game.OS.Userdata";
        private const string ReleasesApiUrl =
            $"https://api.github.com/repos/{GitHubOwner}/{GitHubRepo}/releases/latest";

        private static readonly HttpClient _http = new()
        {
            DefaultRequestHeaders =
            {
                { "User-Agent", "GameOS-Launcher/2.0" },
                { "Accept",     "application/vnd.github.v3+json" },
            },
        };

        // ── Public types ───────────────────────────────────────────────────────

        /// <summary>Information about the latest GitHub release.</summary>
        public record UpdateInfo(
            /// <summary>Git tag name, e.g. "v1.2.3".</summary>
            string TagName,
            /// <summary>Normalised semantic version, e.g. "1.2.3".</summary>
            string Version,
            /// <summary>Direct download URL for the OS-specific zip asset.</summary>
            string DownloadUrl,
            /// <summary>
            /// <see langword="true"/> when the remote version is strictly newer than
            /// <see cref="CurrentVersion"/>.
            /// </summary>
            bool IsNewer);

        // ── Check ──────────────────────────────────────────────────────────────

        /// <summary>
        /// Queries the GitHub releases API for the latest release tag and compares
        /// it with <see cref="CurrentVersion"/>.
        /// Returns <see langword="null"/> if the check fails (network error, no asset, etc.)
        /// </summary>
        public static async Task<UpdateInfo?> CheckForUpdateAsync(
            CancellationToken ct = default)
        {
            try
            {
                using var resp = await _http.GetAsync(ReleasesApiUrl, ct);
                if (!resp.IsSuccessStatusCode) return null;

                var json = await resp.Content.ReadAsStringAsync(ct);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("tag_name", out var tagEl)) return null;
                string tag     = tagEl.GetString() ?? "";
                string version = tag.TrimStart('v');

                // Find the OS-appropriate download asset
                string assetSuffix = GetAssetSuffix();
                string downloadUrl = "";

                if (root.TryGetProperty("assets", out var assetsEl))
                {
                    foreach (var asset in assetsEl.EnumerateArray())
                    {
                        if (!asset.TryGetProperty("name", out var nameEl)) continue;
                        string name = nameEl.GetString() ?? "";
                        if (name.Contains(assetSuffix, StringComparison.OrdinalIgnoreCase))
                        {
                            if (asset.TryGetProperty("browser_download_url", out var urlEl))
                                downloadUrl = urlEl.GetString() ?? "";
                            break;
                        }
                    }
                }

                bool isNewer = IsVersionNewer(version, CurrentVersion);
                return new UpdateInfo(tag, version, downloadUrl, isNewer);
            }
            catch
            {
                return null;
            }
        }

        // ── Download & install ─────────────────────────────────────────────────

        /// <summary>
        /// Downloads the release zip to a temp file, then closes the current app
        /// and starts a helper that extracts the archive over the running installation
        /// before re-launching the executable.
        ///
        /// <para>This method does not return — it calls <see cref="Environment.Exit"/>.</para>
        /// </summary>
        /// <param name="update">Update info returned by <see cref="CheckForUpdateAsync"/>.</param>
        /// <param name="progress">Optional progress callback (0.0 – 1.0).</param>
        public static async Task DownloadAndInstallAsync(
            UpdateInfo update,
            IProgress<double>? progress = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(update.DownloadUrl))
                throw new InvalidOperationException("No download URL is available for this platform.");

            // ── 1. Download to a temp file ─────────────────────────────────────
            string tempDir  = Path.Combine(Path.GetTempPath(), "GameOS_Update");
            Directory.CreateDirectory(tempDir);
            string zipPath  = Path.Combine(tempDir, "update.zip");

            using (var resp = await _http.GetAsync(update.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                resp.EnsureSuccessStatusCode();
                long? total   = resp.Content.Headers.ContentLength;
                long received = 0;

                await using var stream    = await resp.Content.ReadAsStreamAsync(ct);
                await using var fileStream = File.Create(zipPath);

                byte[] buffer = new byte[81920];
                int read;
                while ((read = await stream.ReadAsync(buffer, 0, buffer.Length, ct)) > 0)
                {
                    await fileStream.WriteAsync(buffer, 0, read, ct);
                    received += read;
                    if (total > 0)
                        progress?.Report((double)received / total.Value);
                }
            }

            progress?.Report(1.0);

            // ── 2. Determine install directory ─────────────────────────────────
            string? appExe  = Process.GetCurrentProcess().MainModule?.FileName;
            string  appDir  = string.IsNullOrEmpty(appExe)
                              ? AppContext.BaseDirectory
                              : Path.GetDirectoryName(appExe) ?? AppContext.BaseDirectory;

            // ── 3. Launch an out-of-process script that waits for us to exit,
            //       extracts the zip, and restarts the launcher ──────────────────
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                LaunchWindowsUpdater(zipPath, appDir, appExe ?? "");
            else
                LaunchUnixUpdater(zipPath, appDir, appExe ?? "");

            // ── 4. Exit this instance ─────────────────────────────────────────
            Environment.Exit(0);
        }

        // ── Private helpers ────────────────────────────────────────────────────

        /// <summary>
        /// Returns the asset file-name suffix for the current OS, used to pick the
        /// correct download from the GitHub release assets list.
        /// </summary>
        private static string GetAssetSuffix()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return "win-x64";
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))     return "osx-x64";
            return "linux-x64";
        }

        /// <summary>
        /// Compares two semantic version strings (<c>major.minor.patch</c>) and returns
        /// <see langword="true"/> when <paramref name="remote"/> is strictly newer than
        /// <paramref name="local"/>.
        /// </summary>
        private static bool IsVersionNewer(string remote, string local)
        {
            return Version.TryParse(remote, out var rv)
                && Version.TryParse(local,  out var lv)
                && rv > lv;
        }

        // ── Platform-specific updater launchers ───────────────────────────────

        /// <summary>
        /// Writes a minimal PowerShell script to temp and runs it detached.
        /// The script waits for the launcher PID to exit, extracts the zip, then
        /// re-launches the executable.
        /// </summary>
        private static void LaunchWindowsUpdater(string zipPath, string appDir, string appExe)
        {
            int pid = Environment.ProcessId;
            string script = $@"
$pid = {pid}
try {{ (Get-Process -Id $pid -ErrorAction Stop).WaitForExit(30000) }} catch {{}}
Add-Type -Assembly System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory('{zipPath.Replace("'", "''")}', '{appDir.Replace("'", "''")}', $true)
if (Test-Path '{appExe.Replace("'", "''")}') {{ Start-Process '{appExe.Replace("'", "''")}' }}
".Trim();

            string scriptPath = Path.Combine(Path.GetTempPath(), "gameos_update.ps1");
            File.WriteAllText(scriptPath, script);

            Process.Start(new ProcessStartInfo
            {
                FileName        = "powershell.exe",
                Arguments       = $"-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{scriptPath}\"",
                UseShellExecute = true,
                CreateNoWindow  = true,
            });
        }

        /// <summary>
        /// Writes a minimal shell script to temp and runs it detached.
        /// </summary>
        private static void LaunchUnixUpdater(string zipPath, string appDir, string appExe)
        {
            int pid = Environment.ProcessId;
            string script = $@"#!/bin/sh
tail --pid={pid} -f /dev/null 2>/dev/null || while kill -0 {pid} 2>/dev/null; do sleep 1; done
unzip -o '{zipPath.Replace("'", "'\\''")}' -d '{appDir.Replace("'", "'\\''")}'
chmod +x '{appExe.Replace("'", "'\\''")}' 2>/dev/null || true
'{appExe.Replace("'", "'\\''")}' &
".Trim();

            string scriptPath = Path.Combine(Path.GetTempPath(), "gameos_update.sh");
            File.WriteAllText(scriptPath, script);

            Process.Start(new ProcessStartInfo
            {
                FileName        = "/bin/sh",
                Arguments       = $"\"{scriptPath}\"",
                UseShellExecute = true,
            });
        }
    }
}
