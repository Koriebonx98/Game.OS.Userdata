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
public sealed record Ps2RecompBuild(string ExePath, string Arguments, string WorkingDirectory)
{
    /// <summary>Environment variables for the run (e.g. PS2_SCALE for the render resolution).</summary>
    public System.Collections.Generic.IReadOnlyDictionary<string, string> Environment { get; init; }
        = new System.Collections.Generic.Dictionary<string, string>();
}

/// <summary>User-chosen run options for a recompiled game (the toolkit has no in-game menu yet).</summary>
public sealed class Ps2RecompSettings
{
    /// <summary>Render resolution multiplier (1 = native, 2 = double, 3 = triple).</summary>
    public int Scale { get; set; } = 1;
    /// <summary>Shows the picture in 16:9.</summary>
    public bool Widescreen { get; set; }
}

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
            if (b == null || !File.Exists(b.ExePath)) return null;
            return WithRunOptions(b, romPath);
        }
        catch { return null; }
    }

    public static Ps2RecompSettings LoadSettings(string romPath)
    {
        try
        {
            var p = Path.Combine(OutputDir(romPath), "recomp-settings.json");
            if (File.Exists(p)) return JsonSerializer.Deserialize<Ps2RecompSettings>(File.ReadAllText(p)) ?? new();
        }
        catch { }
        return new();
    }

    public static void SaveSettings(string romPath, Ps2RecompSettings s)
    {
        try
        {
            Directory.CreateDirectory(OutputDir(romPath));
            File.WriteAllText(Path.Combine(OutputDir(romPath), "recomp-settings.json"), JsonSerializer.Serialize(s));
        }
        catch { }
    }

    /// <summary>
    /// PCSX2's memory card, so recompiled games read and write the same saves the emulator does (same 8 MB
    /// card format) and the launcher keeps tracking them. Null when PCSX2's card folder can't be found.
    /// </summary>
    public static string? FindPcsx2MemoryCard()
    {
        var candidates = new System.Collections.Generic.List<string>();
        try
        {
            var emu = EmulatorSettingsService.Load("PS2");
            if (!string.IsNullOrWhiteSpace(emu.SaveDataPath)) candidates.Add(emu.SaveDataPath);
            if (!string.IsNullOrWhiteSpace(emu.EmulatorPath))
                candidates.Add(Path.Combine(Path.GetDirectoryName(emu.EmulatorPath) ?? "", "memcards")); // portable install
        }
        catch { }
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        candidates.Add(Path.Combine(docs, "PCSX2", "memcards"));
        candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PCSX2", "memcards"));

        foreach (var c in candidates)
        {
            if (string.IsNullOrWhiteSpace(c)) continue;
            string dir = Path.GetFileName(c.TrimEnd('\\', '/')).Equals("memcards", StringComparison.OrdinalIgnoreCase)
                ? c : Path.Combine(c, "memcards");
            if (!Directory.Exists(dir)) continue;
            return Path.Combine(dir, "Mcd001.ps2");
        }
        return null;
    }

    private static Ps2RecompBuild WithRunOptions(Ps2RecompBuild b, string romPath)
    {
        // Drop flags older builds baked in; they are decided at launch time now.
        string args = Regex.Replace(b.Arguments, @"\s--(window|fullscreen|widescreen)\b|\s--memcard\s+""[^""]*""", "");
        var settings = LoadSettings(romPath);
        args += " --fullscreen";
        if (settings.Widescreen || args.Contains("--patches", StringComparison.Ordinal) && File.Exists(Path.Combine(b.WorkingDirectory, "wide.flag")))
            args += " --widescreen";
        string card = FindPcsx2MemoryCard() ?? Path.Combine(b.WorkingDirectory, Slug(Path.GetFileNameWithoutExtension(romPath)) + ".ps2");
        args += $" --memcard \"{card}\"";
        var env = new System.Collections.Generic.Dictionary<string, string>();
        if (settings.Scale > 1) env["PS2_SCALE"] = settings.Scale.ToString();
        return b with { Arguments = args, Environment = env };
    }

    /// <summary>Builds the native version. Returns null on success or an error message.</summary>
    public static async Task<string?> BuildAsync(string romPath, Action<string> log, Action<double> progress, CancellationToken ct)
    {
        // Overall progress: CHD 0-10, toolkit 10-15, build tools 15-35, translator tools 35-45, port.sh steps 1-6 45-97, finish 100.
        void Step(double pct) => progress(Math.Clamp(pct, 0, 100));
        Step(0);
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
                Step(2);
                if (Directory.Exists(outDir)) Directory.Delete(outDir, true);
                var (iso, convErr) = await RomConvertService.ChdToIsoAsync(romPath, outDir, false, log, ct);
                if (iso == null) return convErr;
                isoPath = iso;
            }
            else if (!RomConvertService.IsIso(romPath))
                return "Only .iso or .chd PS2 images can be recompiled.";
            Step(10);

            await EnsureToolkitAsync(log, ct);
            Step(15);

            string toolsDir = Path.Combine(ToolkitDir, "tools", "portable");
            string bash     = Path.Combine(toolsDir, "mingit", "usr", "bin", "bash.exe");
            string envPs1   = Path.Combine(toolsDir, "env.ps1");

            if (!File.Exists(bash))
            {
                log("Downloading build tools (once, a few hundred MB)…");
                int rc = await RunPowerShellAsync($"& '{Esc(Path.Combine(ToolkitDir, "scripts", "portable.ps1"))}'", log, ct);
                if (rc != 0 || !File.Exists(bash)) return "Could not download the build tools.";
            }
            Step(35);

            string tools = Path.Combine(ToolkitDir, "build", "tools");
            if (!File.Exists(Path.Combine(tools, "eerecomp.exe")) && !File.Exists(Path.Combine(tools, "eerecomp")))
            {
                log("Preparing translator tools…");
                int rc = await RunBashAsync(envPs1, bash, new[] { Posix(Path.Combine(ToolkitDir, "scripts", "setup.sh")), "--native-only" }, log, ct);
                if (rc != 0) return "Tool setup failed (see log).";
            }
            Step(45);

            // PCSX2's community patches (widescreen, fixes) for this exact game version, best-effort.
            var pnachArgs = new System.Collections.Generic.List<string>();
            try
            {
                log("Looking up PCSX2 patches…");
                var pnach = await FetchPnachAsync(isoPath, ToolkitDir, log, ct);
                if (pnach != null)
                {
                    pnachArgs.Add("--pnach"); pnachArgs.Add(Posix(pnach.Value.File));
                    foreach (var sec in pnach.Value.Sections) { pnachArgs.Add("--pnach-section"); pnachArgs.Add(sec); }
                    log($"Applying PCSX2 patches: {(pnach.Value.Sections.Count == 0 ? "(always-on lines)" : string.Join(", ", pnach.Value.Sections))}");
                }
                else log("No PCSX2 patch file for this game.");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { log("Patches skipped: " + ex.Message); }
            bool wide = false;
            void PortLog(string line)
            {
                log(line);
                if (line.Contains("meant for a 16:9 screen", StringComparison.Ordinal)) wide = true;
                var m = Regex.Match(line, @"==\s*\[(\d)/6\]");
                if (m.Success) Step(45 + (int.Parse(m.Groups[1].Value) - 1) * 52.0 / 6);
            }

            log("Recompiling the game — this takes several minutes…");
            int prc = await RunBashAsync(envPs1, bash,
                new[] { Posix(Path.Combine(ToolkitDir, "scripts", "port.sh")), slug, Posix(isoPath), "--native-only" }.Concat(pnachArgs).ToArray(), PortLog, ct);
            Step(97);
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
            string patchedElf = Path.Combine(gameSrc, "patched", Path.GetFileName(elf));
            if (File.Exists(patchedElf)) elf = patchedElf;
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
            string args = $"\"{outElf}\" --disc \"{isoPath}\"";
            string patchList = Path.Combine(gameSrc, "patches.txt");
            if (File.Exists(patchList))
            {
                string outPatches = Path.Combine(outDir, "patches.txt");
                File.Copy(patchList, outPatches, true);
                args += $" --patches \"{outPatches}\"";
            }
            if (wide) File.WriteAllText(Path.Combine(outDir, "wide.flag"), "");
            else File.Delete(Path.Combine(outDir, "wide.flag"));
            File.WriteAllText(RecordPath(romPath),
                JsonSerializer.Serialize(new Ps2RecompBuild(gameExe, args, outDir)));
            Step(100);
            log("Done: " + gameExe);
            return null;
        }
        catch (OperationCanceledException) { return "Cancelled."; }
        catch (Exception ex) { return ex.Message; }
    }

    /// <summary>The disc's start-file CRC the way PCSX2 names patch files: XOR of the file's little-endian 32-bit words.</summary>
    private static (string? Serial, uint Crc)? ReadDiscIdentity(string iso)
    {
        const int Sector = 2048;
        using var fs = new FileStream(iso, FileMode.Open, FileAccess.Read, FileShare.Read);
        byte[] Read(long lba, int len) { var b = new byte[len]; fs.Seek(lba * Sector, SeekOrigin.Begin); fs.ReadExactly(b, 0, len); return b; }
        var pvd = Read(16, Sector);
        if (pvd[0] != 1 || Encoding.ASCII.GetString(pvd, 1, 5) != "CD001") return null;
        (uint Lba, uint Size)? Find(uint dirLba, uint dirSize, string path)
        {
            uint lba = dirLba, size = dirSize;
            foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                var dir = Read(lba, (int)Math.Min(size, 1 << 20));
                (uint, uint)? hit = null;
                for (int o = 0; o < dir.Length;)
                {
                    int len = dir[o];
                    if (len == 0) { o = (o / Sector + 1) * Sector; continue; }
                    int nameLen = dir[o + 32];
                    var name = Encoding.ASCII.GetString(dir, o + 33, nameLen);
                    int semi = name.IndexOf(';'); if (semi >= 0) name = name[..semi];
                    if (name.Equals(part, StringComparison.OrdinalIgnoreCase))
                    { hit = (BitConverter.ToUInt32(dir, o + 2), BitConverter.ToUInt32(dir, o + 10)); break; }
                    o += len;
                }
                if (hit == null) return null;
                (lba, size) = hit.Value;
            }
            return (lba, size);
        }
        uint rootLba = BitConverter.ToUInt32(pvd, 156 + 2), rootSize = BitConverter.ToUInt32(pvd, 156 + 10);
        var cnfLoc = Find(rootLba, rootSize, "SYSTEM.CNF");
        if (cnfLoc == null) return null;
        var cnf = Encoding.ASCII.GetString(Read(cnfLoc.Value.Lba, (int)Math.Min(cnfLoc.Value.Size, 2048)));
        var m = Regex.Match(cnf, @"BOOT2\s*=\s*cdrom0:\\?([^;\r\n]+)");
        if (!m.Success) return null;
        string bootPath = m.Groups[1].Value.Trim().Replace('\\', '/');
        var boot = Find(rootLba, rootSize, bootPath);
        if (boot == null) return null;
        fs.Seek(boot.Value.Lba * Sector, SeekOrigin.Begin);
        var data = new byte[boot.Value.Size];
        fs.ReadExactly(data, 0, data.Length);
        uint crc = 0;
        for (int i = 0; i + 4 <= data.Length; i += 4) crc ^= BitConverter.ToUInt32(data, i);
        var sm = Regex.Match(bootPath, @"([A-Z]{4})[_-](\d{3})\.?(\d{2})");
        return (sm.Success ? $"{sm.Groups[1].Value}-{sm.Groups[2].Value}{sm.Groups[3].Value}" : null, crc);
    }

    private static readonly Regex AutoSection = new(@"widescreen|16\s*[:/x]\s*9|interlac|\bfix", RegexOptions.IgnoreCase);

    /// <summary>Downloads the matching PCSX2 .pnach and picks the widescreen / no-interlace / fix sections.</summary>
    private static async Task<(string File, System.Collections.Generic.List<string> Sections)?> FetchPnachAsync(
        string iso, string toolkitDir, Action<string> log, CancellationToken ct)
    {
        var id = ReadDiscIdentity(iso);
        if (id == null) return null;
        var (serial, crc) = id.Value;
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher");
        var names = new System.Collections.Generic.List<string>();
        foreach (var digits in new[] { crc.ToString("X8"), crc.ToString("X") })
        {
            if (serial != null) names.Add($"{serial}_{digits}.pnach");
            names.Add($"{digits}.pnach");
        }
        foreach (var name in names.Distinct())
        {
            using var resp = await http.GetAsync("https://raw.githubusercontent.com/PCSX2/pcsx2_patches/main/patches/" + Uri.EscapeDataString(name), ct);
            if (!resp.IsSuccessStatusCode) continue;
            string text = await resp.Content.ReadAsStringAsync(ct);
            string dir = Path.Combine(toolkitDir, "pnach");
            Directory.CreateDirectory(dir);
            string file = Path.Combine(dir, name);
            await File.WriteAllTextAsync(file, text, ct);
            var sections = Regex.Matches(text, @"^\s*\[([^\]]+)\]", RegexOptions.Multiline)
                .Select(x => x.Groups[1].Value.Trim()).Where(n => AutoSection.IsMatch(n)).Distinct().ToList();
            return (file, sections);
        }
        return null;
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
