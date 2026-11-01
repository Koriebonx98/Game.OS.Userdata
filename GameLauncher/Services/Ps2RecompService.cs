using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services;

/// <summary>A finished PS2 → native PC build that the launcher can start directly.</summary>
public sealed record Ps2RecompBuild(string ExePath, string Arguments, string WorkingDirectory);

/// <summary>
/// Turns a PS2 disc image into a native Windows program using
/// https://github.com/exoteric33/ps2-native-recomp. The toolkit is downloaded once, it fetches its own
/// build tools, and each build is copied into a standalone folder (<c>ps2run.exe</c> + its libraries)
/// that the launcher starts directly. The output goes in a folder next to the ROM, named after it
/// (e.g. "BMX XXX.iso" → "BMX XXX/BMX XXX.exe"). CHD images are converted to ISO first.
/// </summary>
public static class Ps2RecompService
{
    private const string ToolkitZipUrl = "https://github.com/exoteric33/ps2-native-recomp/archive/refs/heads/main.zip";

    public static string RootDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GameOS", "Ps2Recomp");
    private static string ToolkitDir => Path.Combine(RootDir, "toolkit");

    public static bool IsSupported => OperatingSystem.IsWindows();

    public static string Slug(string title)
    {
        var s = Regex.Replace(title ?? "", "[^A-Za-z0-9._-]+", "-").Trim('-', '.');
        if (s.Length > 48) s = s[..48].TrimEnd('-', '.');
        return s.Length == 0 ? "game" : s;
    }

    /// <summary>"…/BMX XXX.iso" → "…/BMX XXX" (a folder beside the ROM, named after it).</summary>
    public static string OutputDir(string romPath) => Path.Combine(
        Path.GetDirectoryName(Path.GetFullPath(romPath)) ?? "", Path.GetFileNameWithoutExtension(romPath));
    private static string RecordPath(string romPath) => Path.Combine(OutputDir(romPath), "recomp.json");

    /// <summary>Returns the built native program for <paramref name="romPath"/>, or null when none exists.</summary>
    public static Ps2RecompBuild? GetBuilt(string? romPath)
    {
        if (string.IsNullOrEmpty(romPath)) return null;
        try
        {
            var path = RecordPath(romPath);
            if (!File.Exists(path)) return null;
            var b = JsonSerializer.Deserialize<Ps2RecompBuild>(File.ReadAllText(path));
            return b != null && File.Exists(b.ExePath) ? b : null;
        }
        catch { return null; }
    }


    /// <summary>Builds the native version. Returns null on success or an error message.</summary>
    public static async Task<string?> BuildAsync(string romPath, Action<string> log, CancellationToken ct)
    {
        if (!IsSupported) return "PS2 Recomp builds are only supported on Windows.";
        if (!File.Exists(romPath)) return "Disc image not found: " + romPath;

        try
        {
            string title  = Path.GetFileNameWithoutExtension(romPath);
            string slug   = Slug(title);
            string outDir = OutputDir(romPath);
            string isoPath = romPath;
            Directory.CreateDirectory(RootDir);

            if (RomConvertService.IsChd(romPath))
            {
                // The built exe reads the disc at run time, so the converted ISO lives in its folder.
                log("Converting CHD to ISO…");
                if (Directory.Exists(outDir)) Directory.Delete(outDir, true);
                var (iso, convErr) = await RomConvertService.ChdToIsoAsync(romPath, outDir, false, log, ct);
                if (iso == null) return convErr;
                isoPath = iso;
            }
            else if (!RomConvertService.IsIso(romPath))
                return "Only .iso or .chd PS2 images can be recompiled.";

            await EnsureToolkitAsync(log, ct);

            string toolsDir = Path.Combine(ToolkitDir, "tools", "portable");
            string bash     = Path.Combine(toolsDir, "mingit", "usr", "bin", "bash.exe");
            string envPs1   = Path.Combine(toolsDir, "env.ps1");

            if (!File.Exists(bash))
            {
                log("Downloading build tools (once, a few hundred MB)…");
                int rc = await RunPowerShellAsync($"& '{Esc(Path.Combine(ToolkitDir, "scripts", "portable.ps1"))}'", log, ct);
                if (rc != 0 || !File.Exists(bash)) return "Could not download the build tools.";
            }

            string tools = Path.Combine(ToolkitDir, "build", "tools");
            if (!File.Exists(Path.Combine(tools, "eerecomp.exe")) && !File.Exists(Path.Combine(tools, "eerecomp")))
            {
                log("Preparing translator tools…");
                int rc = await RunBashAsync(envPs1, bash, new[] { Posix(Path.Combine(ToolkitDir, "scripts", "setup.sh")), "--native-only" }, log, ct);
                if (rc != 0) return "Tool setup failed (see log).";
            }

            log("Recompiling the game — this takes several minutes…");
            int prc = await RunBashAsync(envPs1, bash,
                new[] { Posix(Path.Combine(ToolkitDir, "scripts", "port.sh")), slug, Posix(isoPath), "--native-only" }, log, ct);
            if (prc != 0) return "Recompilation failed (see log).";

            string buildDir = Path.Combine(ToolkitDir, "build", "native-" + slug);
            string exe = Path.Combine(buildDir, "ps2run.exe");
            if (!File.Exists(exe)) return "Build finished but ps2run.exe was not produced.";

            string gameSrc = Path.Combine(ToolkitDir, "games", slug);
            string? program = null;
            var cnf = Path.Combine(gameSrc, "disc", "SYSTEM.CNF");
            if (File.Exists(cnf))
            {
                var m = Regex.Match(File.ReadAllText(cnf), @"BOOT2\s*=\s*.*\\([^\\;\r\n]+);");
                if (m.Success) program = m.Groups[1].Value;
            }
            string elf = Path.Combine(gameSrc, "core.elf");
            if (!File.Exists(elf) && program != null) elf = Path.Combine(gameSrc, "disc", program);
            if (!File.Exists(elf)) return "Build finished but the game's start file was not found.";

            // Standalone folder: the game's own exe, its libraries and its translated start file.
            string keepIso = isoPath != romPath ? isoPath : "";
            Directory.CreateDirectory(outDir);
            foreach (var old in Directory.EnumerateFiles(outDir).Where(f => !string.Equals(f, keepIso, StringComparison.OrdinalIgnoreCase)))
                try { File.Delete(old); } catch { }
            foreach (var f in Directory.EnumerateFiles(buildDir)
                         .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                                  || f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
                File.Copy(f, Path.Combine(outDir, Path.GetFileName(f)), true);
            string outElf = Path.Combine(outDir, Path.GetFileName(elf));
            File.Copy(elf, outElf, true);

            // The disc image stays where it is (it is large); the exe reads it from there.
            string gameExe = Path.Combine(outDir, title + ".exe");
            File.Move(Path.Combine(outDir, "ps2run.exe"), gameExe);
            string args = $"\"{outElf}\" --disc \"{isoPath}\" --window --memcard \"{Path.Combine(outDir, slug + ".ps2")}\"";
            File.WriteAllText(RecordPath(romPath),
                JsonSerializer.Serialize(new Ps2RecompBuild(gameExe, args, outDir)));
            log("Done: " + gameExe);
            return null;
        }
        catch (OperationCanceledException) { return "Cancelled."; }
        catch (Exception ex) { return ex.Message; }
    }

    private static async Task EnsureToolkitAsync(Action<string> log, CancellationToken ct)
    {
        if (File.Exists(Path.Combine(ToolkitDir, "scripts", "port.sh"))) return;
        log("Downloading ps2-native-recomp…");
        string zip = Path.Combine(RootDir, "toolkit.zip");
        using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) })
        {
            http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher");
            using var resp = await http.GetAsync(ToolkitZipUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            resp.EnsureSuccessStatusCode();
            await using var fs = File.Create(zip);
            await resp.Content.CopyToAsync(fs, ct);
        }
        string tmp = Path.Combine(RootDir, "toolkit_tmp");
        if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
        ZipFile.ExtractToDirectory(zip, tmp);
        var inner = Directory.GetDirectories(tmp).First();
        if (Directory.Exists(ToolkitDir)) Directory.Delete(ToolkitDir, true);
        Directory.Move(inner, ToolkitDir);
        Directory.Delete(tmp, true);
        File.Delete(zip);
    }

    private static string Esc(string s) => s.Replace("'", "''");
    private static string Posix(string p) => p.Replace('\\', '/');

    private static Task<int> RunBashAsync(string envPs1, string bash, string[] bashArgs, Action<string> log, CancellationToken ct)
        => RunPowerShellAsync($". '{Esc(envPs1)}' -Quiet; & '{Esc(bash)}' {string.Join(' ', bashArgs.Select(a => "'" + Esc(a) + "'"))}; exit $LASTEXITCODE", log, ct);

    private static async Task<int> RunPowerShellAsync(string command, Action<string> log, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            WorkingDirectory = ToolkitDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add(command);

        using var p = new Process { StartInfo = psi };
        p.OutputDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) log(e.Data); };
        p.ErrorDataReceived  += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) log(e.Data); };
        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        using var reg = ct.Register(() => { try { p.Kill(true); } catch { } });
        await p.WaitForExitAsync(CancellationToken.None);
        ct.ThrowIfCancellationRequested();
        return p.ExitCode;
    }
}
