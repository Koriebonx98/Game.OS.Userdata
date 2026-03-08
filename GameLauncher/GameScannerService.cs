using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
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

    // ── Internal state ────────────────────────────────────────────────────────
    private readonly List<LocalGame>          _games   = new();
    private readonly List<LocalRepack>        _repacks = new();
    private readonly List<FileSystemWatcher>  _watchers= new();
    private readonly SemaphoreSlim            _lock    = new(1, 1);

    // ── Cache paths ───────────────────────────────────────────────────────────
    private static readonly string CacheDir  = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "GameOS");
    private static readonly string GameCache  = Path.Combine(CacheDir, "detected_games.json");
    private static readonly string RepackCache= Path.Combine(CacheDir, "detected_repacks.json");

    // ── Public snapshots ──────────────────────────────────────────────────────
    public IReadOnlyList<LocalGame>   Games   => _games;
    public IReadOnlyList<LocalRepack> Repacks => _repacks;

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
        var foundGames   = new List<LocalGame>();
        var foundRepacks = new List<LocalRepack>();

        await Task.Run(() =>
        {
            foreach (var driveRoot in GetDriveRoots())
            {
                ct.ThrowIfCancellationRequested();
                ScanGamesDir(driveRoot, foundGames);
                ScanRepacksDir(driveRoot, foundRepacks);
            }
        }, ct);

        await _lock.WaitAsync(ct);
        try
        {
            _games.Clear();
            _games.AddRange(foundGames);
            _repacks.Clear();
            _repacks.AddRange(foundRepacks);
        }
        finally
        {
            _lock.Release();
        }

        SaveCache();
        GamesUpdated?.Invoke(new List<LocalGame>(_games));
        RepacksUpdated?.Invoke(new List<LocalRepack>(_repacks));
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
                        results.Add(new LocalRepack
                        {
                            Title    = Path.GetFileName(sub),
                            FilePath = sub,
                            FileType = "folder",
                            SizeBytes= GetDirectorySize(sub),
                        });
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
            // Check Unix execute permission bits (.NET 7+)
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
        return new LocalRepack
        {
            Title    = fromSubfolder
                         ? $"{Path.GetFileName(Path.GetDirectoryName(filePath))} / {Path.GetFileName(filePath)}"
                         : Path.GetFileNameWithoutExtension(filePath),
            FilePath = filePath,
            FileType = Path.GetExtension(filePath).TrimStart('.').ToLowerInvariant(),
            SizeBytes= size,
        };
    }

    private static long GetDirectorySize(string path)
    {
        try
        {
            return Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
                            .Sum(f => { try { return new FileInfo(f).Length; } catch { return 0L; } });
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
        // Debounce: fire a re-scan on a thread-pool thread
        Task.Delay(500).ContinueWith(async _ =>
        {
            try { await ScanAllDrivesAsync(CancellationToken.None); }
            catch { }
        });
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
            return _games.Count > 0 || _repacks.Count > 0;
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
        _lock.Dispose();
    }
}
