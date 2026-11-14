using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// Installs the Game OS exclusive "Digital Abyss" (PC) by downloading its Windows installer from the
    /// latest GitHub release and running it silently, so the game is ready to play when it finishes.
    /// </summary>
    public static class DigitalAbyssInstallerService
    {
        public const string GameTitle = "Digital Abyss";
        public const string InstallerUrl =
            "https://github.com/Koriebonx98/Game.OS.Userdata/releases/download/digital-abyss-desktop/DigitalAbyss-Setup.exe";

        private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(15) };

        public static bool IsDigitalAbyss(string? platform, string? title) =>
            string.Equals(platform, "PC", StringComparison.OrdinalIgnoreCase)
            && string.Equals((title ?? "").Trim(), GameTitle, StringComparison.OrdinalIgnoreCase);

        /// <summary>Silent per-user NSIS install location (%LOCALAPPDATA%\Programs\Digital Abyss).</summary>
        public static string InstallFolder => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", GameTitle);

        public static string ExePath => Path.Combine(InstallFolder, GameTitle + ".exe");

        /// <summary>Returns the installed exe: a "&lt;root&gt;/Games/Digital Abyss" copy on any drive, else the legacy per-user location.</summary>
        public static string? FindInstalledExe()
        {
            try
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    if (!d.IsReady) continue;
                    var exe = Path.Combine(d.RootDirectory.FullName, "Games", GameTitle, GameTitle + ".exe");
                    if (File.Exists(exe)) return exe;
                }
            }
            catch { /* best-effort */ }
            return File.Exists(ExePath) ? ExePath : null;
        }

        public static bool IsInstalled => FindInstalledExe() != null;

        /// <summary>Downloads and silently installs the game into <paramref name="installFolder"/>. Returns the installed exe path.</summary>
        public static async Task<string> InstallAsync(string installFolder, IProgress<double>? progress = null, CancellationToken ct = default)
        {
            var exePath = Path.Combine(installFolder, GameTitle + ".exe");
            var setup = Path.Combine(Path.GetTempPath(), "DigitalAbyss-Setup.exe");
            try
            {
                using (var resp = await Http.GetAsync(InstallerUrl, HttpCompletionOption.ResponseHeadersRead, ct))
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
