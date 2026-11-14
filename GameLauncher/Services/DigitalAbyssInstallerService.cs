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

        public static bool IsInstalled => File.Exists(ExePath);

        /// <summary>Downloads and silently installs the game. Returns the installed exe path.</summary>
        public static async Task<string> InstallAsync(IProgress<double>? progress = null, CancellationToken ct = default)
        {
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

                var psi = new ProcessStartInfo(setup, "/S") { UseShellExecute = true };
                using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start the installer.");
                await proc.WaitForExitAsync(ct);
                if (proc.ExitCode != 0) throw new InvalidOperationException($"Installer exited with code {proc.ExitCode}.");
                if (!IsInstalled) throw new FileNotFoundException("Installation finished but the game was not found.", ExePath);
                progress?.Report(100);
                return ExePath;
            }
            finally
            {
                try { File.Delete(setup); } catch { /* best-effort */ }
            }
        }
    }
}
