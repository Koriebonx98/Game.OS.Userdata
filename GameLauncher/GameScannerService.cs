using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using GameLauncher.Models;

namespace GameLauncher;

/// <summary>
/// Scans all mounted drives for Games/$GameFolder and Repacks directories,
/// detects valid executables and repack archives, watches for live changes,
/// and caches results locally.
/// </summary>
public sealed class GameScannerService : IDisposable
{
    // ── Events ────────────────────────────────────────────────────────────────
    public event Action<List<LocalGame>>?   GamesUpdated;
    public event Action<List<LocalRepack>>? RepacksUpdated;
    public event Action<List<LocalRom>>?    RomsUpdated;

    // ── Internal state ────────────────────────────────────────────────────────
    private readonly List<LocalGame>          _games   = new();
    private readonly List<LocalRepack>        _repacks = new();
    private readonly List<LocalRom>           _roms    = new();
    private readonly List<FileSystemWatcher>  _watchers= new();
    private readonly SemaphoreSlim            _lock    = new(1, 1);
    private CancellationTokenSource?          _debounceCts;

    // ── Cache paths ───────────────────────────────────────────────────────────
    private static readonly string CacheDir  = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "GameOS");
    private static readonly string GameCache  = Path.Combine(CacheDir, "detected_games.json");
    private static readonly string RepackCache= Path.Combine(CacheDir, "detected_repacks.json");
    private static readonly string RomCache   = Path.Combine(CacheDir, "detected_roms.json");

    // ── Public snapshots ──────────────────────────────────────────────────────
    public IReadOnlyList<LocalGame>   Games   => _games;
    public IReadOnlyList<LocalRepack> Repacks => _repacks;
    public IReadOnlyList<LocalRom>    Roms    => _roms;

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Performs an initial scan (with cache fallback) and starts background watchers.
    /// </summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        // Try loading from cache first for faster startup
        if (TryLoadCache())
        {
            GamesUpdated?.Invoke(new List<LocalGame>(_games));
            RepacksUpdated?.Invoke(new List<LocalRepack>(_repacks));
            RomsUpdated?.Invoke(new List<LocalRom>(_roms));
        }

        // Always do a fresh scan to stay current
        await ScanAllDrivesAsync(ct);
        StartWatchers();
    }

    /// <summary>Re-scans all drives on demand.</summary>
    public async Task RescanAsync(CancellationToken ct = default)
    {
        await ScanAllDrivesAsync(ct);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Drive detection (cross-platform)
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>Returns all drive/volume root paths for the current OS.</summary>
    internal static IEnumerable<string> GetDriveRoots()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            foreach (var drive in DriveInfo.GetDrives())
                if (drive.IsReady)
                    yield return drive.RootDirectory.FullName; // e.g. C:\
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // macOS: volumes live under /Volumes
            yield return "/";
            if (Directory.Exists("/Volumes"))
                foreach (var v in Directory.EnumerateDirectories("/Volumes"))
                    yield return v;
        }
        else
        {
            // Linux: /mnt, /media, and home directory
            yield return "/";
            foreach (var mountRoot in new[] { "/mnt", "/media" })
                if (Directory.Exists(mountRoot))
                    foreach (var sub in Directory.EnumerateDirectories(mountRoot))
                        yield return sub;

            // Also scan user-level subdirs under /media/<username>
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(home) && Directory.Exists(home))
                yield return home;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scanning
    // ─────────────────────────────────────────────────────────────────────────

    private async Task ScanAllDrivesAsync(CancellationToken ct)
    {
        var foundGamesRaw = new List<LocalGame>();
        var foundRepacks  = new List<LocalRepack>();
        var foundRoms     = new List<LocalRom>();

        await Task.Run(() =>
        {
            foreach (var driveRoot in GetDriveRoots())
            {
                ct.ThrowIfCancellationRequested();
                ScanGamesDir(driveRoot, foundGamesRaw);
                ScanRepacksDir(driveRoot, foundRepacks);
                ScanRomsDir(driveRoot, foundRoms);
            }
        }, ct);

        // Group same-title games found on multiple drives into a single LocalGame
        var foundGames = new List<LocalGame>();
        foreach (var grp in foundGamesRaw.GroupBy(g => g.Title, System.StringComparer.OrdinalIgnoreCase))
        {
            var items = grp.ToList();
            var primary = items[0];
            primary.DriveInstances = items.Select(g => new Models.LocalGameDriveEntry
            {
                DriveRoot      = g.DriveRoot,
                FolderPath     = g.FolderPath,
                ExecutablePath = g.ExecutablePath,
                ExecutableType = g.ExecutableType,
            }).ToList();
            foundGames.Add(primary);
        }

        await _lock.WaitAsync(ct);
        try
        {
            _games.Clear();
            _games.AddRange(foundGames);
            _repacks.Clear();
            _repacks.AddRange(foundRepacks);
            _roms.Clear();
            _roms.AddRange(foundRoms);
        }
        finally
        {
            _lock.Release();
        }

        SaveCache();
        GamesUpdated?.Invoke(new List<LocalGame>(_games));
        RepacksUpdated?.Invoke(new List<LocalRepack>(_repacks));
        RomsUpdated?.Invoke(new List<LocalRom>(_roms));
    }

    /// <summary>Scan <paramref name="driveRoot"/>/Games for game folders.</summary>
    private static void ScanGamesDir(string driveRoot, List<LocalGame> results)
    {
        string gamesPath = Path.Combine(driveRoot, "Games");
        if (!Directory.Exists(gamesPath)) return;

        try
        {
            foreach (var gameFolder in Directory.EnumerateDirectories(gamesPath))
            {
                var exe = FindExecutable(gameFolder);
                if (exe is null) continue;

                results.Add(new LocalGame
                {
                    Title          = Path.GetFileName(gameFolder),
                    ExecutablePath = exe.FullPath,
                    ExecutableType = exe.Type,
                    FolderPath     = gameFolder,
                    DriveRoot      = driveRoot,
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }

    /// <summary>
    /// Scans <paramref name="driveRoot"/>/Roms for non-PC ROM files.
    /// Expected layout: Roms/{PlatformName}/Games/{RomFile}
    ///                   or Roms/{PlatformName}/Games/{GameName}/{RomFile}
    /// </summary>
    private static void ScanRomsDir(string driveRoot, List<LocalRom> results)
    {
        string romsPath = Path.Combine(driveRoot, "Roms");
        if (!Directory.Exists(romsPath)) return;

        try
        {
            foreach (var platformDir in Directory.EnumerateDirectories(romsPath))
            {
                string platform = Path.GetFileName(platformDir);
                string gamesDir = Path.Combine(platformDir, "Games");
                if (!Directory.Exists(gamesDir)) continue;

                try
                {
                    foreach (var entry in Directory.EnumerateFileSystemEntries(
                                 gamesDir, "*", SearchOption.AllDirectories))
                    {
                        if (Directory.Exists(entry)) continue; // skip sub-folders
                        string ext = Path.GetExtension(entry).ToLowerInvariant();
                        if (!IsRomFile(ext)) continue;

                        long size = 0;
                        try { size = new FileInfo(entry).Length; } catch { }

                        // Prefer the parent folder name as the title when the file
                        // is inside a named sub-directory; fall back to the filename.
                        string parent = Path.GetDirectoryName(entry) ?? gamesDir;
                        string title  = string.Equals(
                                            Path.GetFullPath(parent),
                                            Path.GetFullPath(gamesDir),
                                            StringComparison.OrdinalIgnoreCase)
                            ? Path.GetFileNameWithoutExtension(entry)
                            : Path.GetFileName(parent);

                        results.Add(new LocalRom
                        {
                            Title    = title,
                            Platform = platform,
                            FilePath = entry,
                            FileType = ext.TrimStart('.'),
                            SizeBytes= size,
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }

    // ── ROM extension list ─────────────────────────────────────────────────

    private static readonly HashSet<string> _romExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Generic archive / disc formats
        ".zip", ".7z", ".rar",
        // Sony / Microsoft
        ".iso", ".bin", ".cue", ".xex", ".xiso",
        // Nintendo
        ".gb", ".gbc", ".gba", ".nes", ".snes", ".ds", ".3ds",
        // Other
        ".elf", ".img", ".chd", ".pbp",
    };

    private static bool IsRomFile(string ext) => _romExtensions.Contains(ext);

    // ── Repack marker stripping ────────────────────────────────────────────

    // Matches "[Repack]", "[FitGirl Repack]", "[DODI Repack]", etc.
    private static readonly Regex _repackMarkerRegex =
        new(@"\[[\w\s]*[Rr]epack[\w\s]*\]", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Removes common repack annotation patterns from a folder/file name so
    /// the clean game title can be matched against the Games.Database.
    /// </summary>
    internal static string StripRepackMarkers(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;
        return _repackMarkerRegex.Replace(name, "").Trim();
    }

    /// <summary>Scan <paramref name="driveRoot"/>/Repacks recursively.</summary>
    private static void ScanRepacksDir(string driveRoot, List<LocalRepack> results)
    {
        string repacksPath = Path.Combine(driveRoot, "Repacks");
        if (!Directory.Exists(repacksPath)) return;

        try
        {
            // Top-level archive files
            foreach (var file in Directory.EnumerateFiles(repacksPath, "*", SearchOption.TopDirectoryOnly))
            {
                if (IsRepackArchive(file))
                    results.Add(MakeRepack(file, false));
            }

            // Sub-folders (e.g. Repacks/$RepackFolder)
            foreach (var sub in Directory.EnumerateDirectories(repacksPath))
            {
                bool foundAny = false;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(sub, "*", SearchOption.AllDirectories))
                    {
                        if (IsRepackArchive(file))
                        {
                            results.Add(MakeRepack(file, true));
                            foundAny = true;
                        }
                    }
                    // If the folder itself is a repack folder with no archive, add the folder
                    if (!foundAny)
                    {
                        // Check for an installer (Setup.exe) within the folder
                        string? setupExe = FindSetupExe(sub);
                        results.Add(new LocalRepack
                        {
                            Title     = StripRepackMarkers(Path.GetFileName(sub)),
                            FilePath  = setupExe ?? sub,
                            FileType  = setupExe != null ? "setup" : "folder",
                            SizeBytes = GetDirectorySize(sub),
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private sealed record ExeInfo(string FullPath, string Type);

    /// <summary>
    /// Looks for a setup/install executable inside a repack folder.
    /// Returns the full path of the first Setup*.exe found (case-insensitive),
    /// or null if none is found.
    /// </summary>
    private static string? FindSetupExe(string folder)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return null;
        try
        {
            return Directory.EnumerateFiles(folder, "setup*.exe", SearchOption.AllDirectories)
                            .FirstOrDefault()
                ?? Directory.EnumerateFiles(folder, "install*.exe", SearchOption.AllDirectories)
                            .FirstOrDefault();
        }
        catch { return null; }
    }

    private static ExeInfo? FindExecutable(string folder)
    {
        try
        {
            // .exe (Windows)
            var exe = Directory.EnumerateFiles(folder, "*.exe", SearchOption.TopDirectoryOnly).FirstOrDefault();
            if (exe != null) return new ExeInfo(exe, "exe");

            // .app bundle (macOS)
            var app = Directory.EnumerateDirectories(folder, "*.app", SearchOption.TopDirectoryOnly).FirstOrDefault();
            if (app != null) return new ExeInfo(app, "app");

            // ELF binary (Linux) — a file without extension that is marked executable
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                foreach (var f in Directory.EnumerateFiles(folder, "*", SearchOption.TopDirectoryOnly))
                {
                    if (Path.GetExtension(f) != "") continue;
                    try
                    {
                        var info = new FileInfo(f);
                        if (info.Exists && IsExecutable(f))
                            return new ExeInfo(f, "elf");
                    }
                    catch { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        return null;
    }

    private static bool IsExecutable(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return false;

        try
        {
            // Check ELF magic number
            using var fs = File.OpenRead(path);
            var header = new byte[4];
            int read = fs.Read(header, 0, 4);
            if (read == 4 && header[0] == 0x7f && header[1] == (byte)'E' &&
                header[2] == (byte)'L' && header[3] == (byte)'F')
                return true;
        }
        catch { }

        try
        {
            // Check Unix execute permission bits (File.GetUnixFileMode available since .NET 7;
            // this project targets .NET 8 so this is always supported)
            var mode = File.GetUnixFileMode(path);
            return (mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0;
        }
        catch { }

        return false;
    }

    private static bool IsRepackArchive(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".zip" or ".rar" or ".7z" or ".iso" or ".tar" or ".gz";
    }

    private static LocalRepack MakeRepack(string filePath, bool fromSubfolder)
    {
        long size = 0;
        try { size = new FileInfo(filePath).Length; } catch { }

        string rawTitle = fromSubfolder
            ? $"{Path.GetFileName(Path.GetDirectoryName(filePath))} / {Path.GetFileName(filePath)}"
            : Path.GetFileNameWithoutExtension(filePath);

        return new LocalRepack
        {
            Title    = StripRepackMarkers(rawTitle),
            FilePath = filePath,
            FileType = Path.GetExtension(filePath).TrimStart('.').ToLowerInvariant(),
            SizeBytes= size,
        };
    }

    private static long GetDirectorySize(string path)
    {
        try
        {
            return new DirectoryInfo(path)
                .EnumerateFiles("*", SearchOption.AllDirectories)
                .Sum(f => f.Length);
        }
        catch { return 0; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // File-system watchers
    // ─────────────────────────────────────────────────────────────────────────

    private void StartWatchers()
    {
        DisposeWatchers();

        foreach (var driveRoot in GetDriveRoots())
        {
            TryWatch(Path.Combine(driveRoot, "Games"));
            TryWatch(Path.Combine(driveRoot, "Repacks"));
            TryWatch(Path.Combine(driveRoot, "Roms"));
        }
    }

    private void TryWatch(string dir)
    {
        if (!Directory.Exists(dir)) return;
        try
        {
            var w = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                NotifyFilter          = NotifyFilters.FileName
                                      | NotifyFilters.DirectoryName,
                EnableRaisingEvents   = true,
            };
            w.Created += OnFileSystemChanged;
            w.Deleted += OnFileSystemChanged;
            w.Renamed += OnFileSystemChanged;
            _watchers.Add(w);
        }
        catch { /* Directory not accessible or not supported */ }
    }

    private void OnFileSystemChanged(object sender, FileSystemEventArgs e)
    {
        // Cancel any pending debounced scan and start a fresh one
        _debounceCts?.Cancel();
        _debounceCts?.Dispose();
        var cts = new CancellationTokenSource();
        _debounceCts = cts;
        _ = Task.Delay(500, cts.Token).ContinueWith(async t =>
        {
            if (t.IsCanceled) return;
            try { await ScanAllDrivesAsync(CancellationToken.None); }
            catch { }
        }, TaskScheduler.Default);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cache
    // ─────────────────────────────────────────────────────────────────────────

    private bool TryLoadCache()
    {
        try
        {
            if (!File.Exists(GameCache) && !File.Exists(RepackCache))
                return false;

            if (File.Exists(GameCache))
            {
                var g = JsonSerializer.Deserialize<List<LocalGame>>(File.ReadAllText(GameCache));
                if (g != null) { _games.Clear(); _games.AddRange(g); }
            }
            if (File.Exists(RepackCache))
            {
                var r = JsonSerializer.Deserialize<List<LocalRepack>>(File.ReadAllText(RepackCache));
                if (r != null) { _repacks.Clear(); _repacks.AddRange(r); }
            }
            if (File.Exists(RomCache))
            {
                var rom = JsonSerializer.Deserialize<List<LocalRom>>(File.ReadAllText(RomCache));
                if (rom != null) { _roms.Clear(); _roms.AddRange(rom); }
            }
            return _games.Count > 0 || _repacks.Count > 0 || _roms.Count > 0;
        }
        catch { return false; }
    }

    private void SaveCache()
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            var opts = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(GameCache,   JsonSerializer.Serialize(_games,   opts));
            File.WriteAllText(RepackCache, JsonSerializer.Serialize(_repacks, opts));
            File.WriteAllText(RomCache,    JsonSerializer.Serialize(_roms,    opts));
        }
        catch { }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IDisposable
    // ─────────────────────────────────────────────────────────────────────────

    private void DisposeWatchers()
    {
        foreach (var w in _watchers) { try { w.Dispose(); } catch { } }
        _watchers.Clear();
    }

    public void Dispose()
    {
        DisposeWatchers();
        _debounceCts?.Cancel();
        _debounceCts?.Dispose();
        _lock.Dispose();
    }
}
