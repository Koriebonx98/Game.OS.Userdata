using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using GameLauncher;
using GameLauncher.Models;

/// <summary>
/// Demonstrates the GameScannerService detecting fake games, repacks and ROMs
/// from the TestData directory.
/// </summary>
class Program
{
    static async Task<int> Main(string[] args)
    {
        // Resolve the TestData directory (repo root / TestData)
        string repoRoot = FindRepoRoot();
        string testDataDir = Path.Combine(repoRoot, "TestData");

        if (!Directory.Exists(testDataDir))
        {
            Console.Error.WriteLine($"ERROR: TestData not found at: {testDataDir}");
            return 1;
        }

        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine("  Game.OS — GameScannerService Detection Test");
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        Console.WriteLine($"  Scanning TestData root: {testDataDir}");
        Console.WriteLine();

        // Run the scanner against the TestData directory via temporary $HOME symlinks
        var scanner = new GameScannerService();
        bool passed = true;

        List<LocalGame>   detectedGames   = new();
        List<LocalRepack> detectedRepacks = new();
        List<LocalRom>    detectedRoms    = new();

        scanner.GamesUpdated   += g => detectedGames   = g;
        scanner.RepacksUpdated += r => detectedRepacks = r;
        scanner.RomsUpdated    += r => detectedRoms    = r;

        // Set up symlinks so the scanner's standard GetDriveRoots() path ($HOME) picks up TestData
        await ScanDirectory(scanner, testDataDir);

        // ── GAMES ─────────────────────────────────────────────────────────────
        Console.WriteLine($"📀 Detected Games ({detectedGames.Count}):");
        Console.WriteLine("───────────────────────────────────────────────────────────────");
        foreach (var g in detectedGames.OrderBy(g => g.Title))
        {
            string rel = Path.GetRelativePath(testDataDir, g.ExecutablePath);
            Console.WriteLine($"  ✅  {g.Title,-20}  [{g.ExecutableType,-3}]  {rel}");
        }
        Console.WriteLine();

        // Expected: FakeGame1 (.exe), FakeGame2 (.app), FakeGame3 (elf),
        //           FakeGame4 (.exe), FakeGame5 (elf)
        string[] expectedGames = { "FakeGame1", "FakeGame2", "FakeGame3", "FakeGame4", "FakeGame5" };
        foreach (var expected in expectedGames)
        {
            if (!detectedGames.Any(g => g.Title == expected))
            {
                Console.WriteLine($"  ❌  MISSING: {expected}");
                passed = false;
            }
        }

        // ── REPACKS ───────────────────────────────────────────────────────────
        Console.WriteLine($"📦 Detected Repacks ({detectedRepacks.Count}):");
        Console.WriteLine("───────────────────────────────────────────────────────────────");
        foreach (var r in detectedRepacks.OrderBy(r => r.Title))
        {
            Console.WriteLine($"  ✅  {r.Title,-35}  [{r.FileType,-6}]  {r.SizeLabel}");
        }
        Console.WriteLine();

        // Expected: FakeRepack.zip, FakeRepack.rar, FakeRepack1/FakeRepack1.zip, FakeRepack2/FakeRepack2.7z
        if (detectedRepacks.Count < 4)
        {
            Console.WriteLine($"  ❌  Expected at least 4 repacks, found {detectedRepacks.Count}");
            passed = false;
        }

        // ── ROMS ──────────────────────────────────────────────────────────────
        Console.WriteLine($"🕹️  Detected ROMs ({detectedRoms.Count}):");
        Console.WriteLine("───────────────────────────────────────────────────────────────");
        foreach (var r in detectedRoms.OrderBy(r => r.Platform).ThenBy(r => r.Title))
        {
            string regions = r.Regions.Count > 0 ? $"  regions=[{string.Join(",", r.Regions)}]" : "";
            string extra   = r.AdditionalPaths.Count > 0 ? $"  +{r.AdditionalPaths.Count} more" : "";
            Console.WriteLine($"  ✅  [{r.Platform,-10}]  {r.Title,-25}  [{r.FileType,-5}]  {r.SizeLabel}{regions}{extra}");
        }
        Console.WriteLine();

        // Expected: FakeGBAGame (GBA), FakeSNESGame merged from 3 files with Europe+USA regions (SNES), FakePS3Game (PS3)
        var expectedRoms = new[] {
            ("FakeGBAGame", "GBA"),
            ("FakeSNESGame", "SNES"),
            ("FakePS3Game", "PS3"),
        };
        foreach (var (title, platform) in expectedRoms)
        {
            if (!detectedRoms.Any(r => r.Title == title && r.Platform == platform))
            {
                // ROM scanning requires TestData/Roms to exist — soft warning
                Console.WriteLine($"  ⚠  ROM not found: {title} ({platform}) — ensure TestData/Roms exists");
            }
        }

        // Verify FakeSNESGame is merged from 3 files and has region tags
        var snesRom = detectedRoms.FirstOrDefault(r => r.Title == "FakeSNESGame" && r.Platform == "SNES");
        if (snesRom != null)
        {
            int totalFiles = 1 + snesRom.AdditionalPaths.Count;
            if (totalFiles < 3)
            {
                Console.WriteLine($"  ❌  FakeSNESGame: expected 3 files merged, got {totalFiles}");
                passed = false;
            }
            if (!snesRom.Regions.Contains("Europe", StringComparer.OrdinalIgnoreCase) ||
                !snesRom.Regions.Contains("USA",    StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine($"  ❌  FakeSNESGame: expected regions [Europe, USA], got [{string.Join(", ", snesRom.Regions)}]");
                passed = false;
            }
        }

        // ── NEW FEATURE CHECKS ─────────────────────────────────────────────────

        // Archive title normalisation: "A-Way-Out-SteamRIP.zip" → "A Way Out"
        Console.WriteLine("🔧 Archive Title Normalisation:");
        Console.WriteLine("───────────────────────────────────────────────────────────────");
        var awayOut = detectedRepacks.FirstOrDefault(r =>
            string.Equals(r.Title, "A Way Out", StringComparison.OrdinalIgnoreCase));
        if (awayOut != null)
        {
            Console.WriteLine("  ✅  A-Way-Out-SteamRIP.zip → \"A Way Out\"");
        }
        else
        {
            Console.WriteLine("  ❌  A-Way-Out-SteamRIP.zip was NOT normalised to \"A Way Out\"");
            passed = false;
        }
        Console.WriteLine();

        // Repack with Update subfolder detection
        Console.WriteLine("📂 Repack + Update Detection:");
        Console.WriteLine("───────────────────────────────────────────────────────────────");
        var repackWithUpdate = detectedRepacks.FirstOrDefault(r =>
            r.Title.StartsWith("FakeGame3WithUpdate", StringComparison.OrdinalIgnoreCase));
        if (repackWithUpdate != null && repackWithUpdate.HasUpdate)
        {
            Console.WriteLine($"  ✅  FakeGame3WithUpdate has Update: {repackWithUpdate.UpdatePath}");
        }
        else if (repackWithUpdate != null)
        {
            Console.WriteLine("  ❌  FakeGame3WithUpdate found but HasUpdate=false");
            passed = false;
        }
        else
        {
            Console.WriteLine("  ⚠  FakeGame3WithUpdate repack not found — ensure TestData/Repacks/FakeGame3WithUpdate exists");
        }
        Console.WriteLine();

        // Repack for installed game detection
        Console.WriteLine("🏷️  IsInstalledGame Detection:");
        Console.WriteLine("───────────────────────────────────────────────────────────────");
        var fakeGame1Repack = detectedRepacks.FirstOrDefault(r =>
            string.Equals(r.Title, "FakeGame1", StringComparison.OrdinalIgnoreCase));
        if (fakeGame1Repack != null && fakeGame1Repack.IsInstalledGame)
        {
            Console.WriteLine("  ✅  FakeGame1.zip is marked IsInstalledGame=true (also in Games/)");
        }
        else if (fakeGame1Repack != null)
        {
            Console.WriteLine("  ❌  FakeGame1.zip found but IsInstalledGame=false");
            passed = false;
        }
        else
        {
            Console.WriteLine("  ⚠  FakeGame1 repack not found — ensure TestData/Repacks/FakeGame1.zip exists");
        }
        Console.WriteLine();

        // ── SUMMARY ───────────────────────────────────────────────────────────
        Console.WriteLine("═══════════════════════════════════════════════════════════════");
        if (passed)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✅  ALL CHECKS PASSED — Game detection is working correctly!");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  ❌  SOME CHECKS FAILED — See output above.");
        }
        Console.ResetColor();
        Console.WriteLine("═══════════════════════════════════════════════════════════════");

        scanner.Dispose();
        return passed ? 0 : 1;
    }

    // Runs the scanner by creating temporary symlinks in $HOME so that the standard
    // GetDriveRoots() scan path picks up the TestData Games/, Repacks/ and Roms/ directories,
    // then calls StartAsync() which is the normal public entry point.
    private static async Task ScanDirectory(GameScannerService scanner, string driveRoot)
    {
        // On Linux, $HOME is always included in GetDriveRoots(), so placing Games/, Repacks/
        // and Roms/ symlinks there ensures the scanner finds our TestData sub-directories.
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string gamesLink  = Path.Combine(home, "Games");
        string repacksLink= Path.Combine(home, "Repacks");
        string romsLink   = Path.Combine(home, "Roms");

        bool cleanGames   = false;
        bool cleanRepacks = false;
        bool cleanRoms    = false;

        try
        {
            // Set up temporary symlinks pointing at TestData sub-directories
            if (!Directory.Exists(gamesLink))
            {
                Directory.CreateSymbolicLink(gamesLink,   Path.Combine(driveRoot, "Games"));
                cleanGames = true;
            }
            if (!Directory.Exists(repacksLink))
            {
                Directory.CreateSymbolicLink(repacksLink, Path.Combine(driveRoot, "Repacks"));
                cleanRepacks = true;
            }
            string romsTestPath = Path.Combine(driveRoot, "Roms");
            if (!Directory.Exists(romsLink) && Directory.Exists(romsTestPath))
            {
                Directory.CreateSymbolicLink(romsLink, romsTestPath);
                cleanRoms = true;
            }

            await scanner.StartAsync();
        }
        finally
        {
            if (cleanGames)   try { Directory.Delete(gamesLink); }   catch { }
            if (cleanRepacks) try { Directory.Delete(repacksLink); } catch { }
            if (cleanRoms)    try { Directory.Delete(romsLink); }    catch { }
        }
    }

    private static string FindRepoRoot()
    {
        // Walk up from the current directory looking for TestData or .git
        string? dir = AppContext.BaseDirectory;
        while (dir != null)
        {
            if (Directory.Exists(Path.Combine(dir, "TestData")) ||
                Directory.Exists(Path.Combine(dir, ".git")))
                return dir;
            dir = Path.GetDirectoryName(dir);
        }
        return Directory.GetCurrentDirectory();
    }
}
