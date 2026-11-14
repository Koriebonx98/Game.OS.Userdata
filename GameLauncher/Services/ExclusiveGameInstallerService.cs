using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>A Game OS exclusive (PC) that ships as a Windows installer attached to a GitHub release.</summary>
    /// <param name="Title">Store title, also the installed folder and exe name (e.g. "Snake Plus").</param>
    /// <param name="InstallerFileName">Release asset name, e.g. "SnakePlus-Setup.exe".</param>
    /// <param name="ReleaseTag">GitHub release tag the installer is published under.</param>
    public sealed record ExclusiveGame(string Title, string InstallerFileName, string ReleaseTag)
    {
        public string InstallerUrl =>
            $"https://github.com/Koriebonx98/Game.OS.Userdata/releases/download/{ReleaseTag}/{InstallerFileName}";
    }

    /// <summary>
    /// Installs Game OS exclusives (Digital Abyss, Snake Plus) by downloading each game's Windows installer from
    /// its GitHub release and running it silently, so the game is ready to play when it finishes.
    /// </summary>
    public static class ExclusiveGameInstallerService
    {
        public static readonly ExclusiveGame DigitalAbyss = new("Digital Abyss", "DigitalAbyss-Setup.exe", "digital-abyss-desktop");
        public static readonly ExclusiveGame SnakePlus = new("Snake Plus", "SnakePlus-Setup.exe", "snake-plus-desktop");

        public static readonly ExclusiveGame[] All = { DigitalAbyss, SnakePlus };

        private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(15) };

        /// <summary>Returns the exclusive matching a PC store entry, or null for any other game.</summary>
        public static ExclusiveGame? Find(string? platform, string? title) =>
            string.Equals(platform, "PC", StringComparison.OrdinalIgnoreCase)
                ? All.FirstOrDefault(g => string.Equals((title ?? "").Trim(), g.Title, StringComparison.OrdinalIgnoreCase))
                : null;

        /// <summary>Silent per-user NSIS install location (%LOCALAPPDATA%\Programs\&lt;Title&gt;).</summary>
        public static string InstallFolder(ExclusiveGame game) => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", game.Title);

        public static string ExePath(ExclusiveGame game) => Path.Combine(InstallFolder(game), game.Title + ".exe");

        /// <summary>Returns the installed exe: a "&lt;root&gt;/Games/&lt;Title&gt;" copy on any drive, else the legacy per-user location.</summary>
        public static string? FindInstalledExe(ExclusiveGame game)
        {
            try
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    if (!d.IsReady) continue;
                    var exe = Path.Combine(d.RootDirectory.FullName, "Games", game.Title, game.Title + ".exe");
                    if (File.Exists(exe)) return exe;
                }
            }
            catch { /* best-effort */ }
            var legacy = ExePath(game);
            return File.Exists(legacy) ? legacy : null;
        }

        public static bool IsInstalled(ExclusiveGame game) => FindInstalledExe(game) != null;

        /// <summary>Downloads and silently installs the game into <paramref name="installFolder"/>. Returns the installed exe path.</summary>
        public static async Task<string> InstallAsync(ExclusiveGame game, string installFolder, IProgress<double>? progress = null, CancellationToken ct = default)
        {
            var exePath = Path.Combine(installFolder, game.Title + ".exe");
            var setup = Path.Combine(Path.GetTempPath(), game.InstallerFileName);
            try
            {
                using (var resp = await Http.GetAsync(game.InstallerUrl, HttpCompletionOption.ResponseHeadersRead, ct))
                {
                    resp.EnsureSuccessStatusCode();
                    var total = resp.Content.Headers.ContentLength ?? -1;
                    await using var src = await resp.Content.ReadAsStreamAsync(ct);
                    await using var dst = File.Create(setup);
                    var buf = new byte[81920];
                    long done = 0;
                    int n;
                    while ((n = await src.ReadAsync(buf, ct)) > 0)
                    {
                        await dst.WriteAsync(buf.AsMemory(0, n), ct);
                        done += n;
                        if (total > 0) progress?.Report(done * 90.0 / total);
                    }
                }

                var psi = new ProcessStartInfo(setup, $"/S /D={installFolder}") { UseShellExecute = true };
                using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start the installer.");
                await proc.WaitForExitAsync(ct);
                if (proc.ExitCode != 0) throw new InvalidOperationException($"Installer exited with code {proc.ExitCode}.");
                if (!File.Exists(exePath)) throw new FileNotFoundException("Installation finished but the game was not found.", exePath);
                progress?.Report(100);
                return exePath;
            }
            finally
            {
                try { File.Delete(setup); } catch { /* best-effort */ }
            }
        }
    }
}
