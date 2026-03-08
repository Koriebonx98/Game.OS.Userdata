using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using GameLauncher;
using GameLauncher.Models;

/// <summary>
/// Demonstrates the GameScannerService detecting fake games and repacks
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

        scanner.GamesUpdated   += g => detectedGames   = g;
        scanner.RepacksUpdated += r => detectedRepacks = r;

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
    // GetDriveRoots() scan path picks up the TestData Games/ and Repacks/ directories,
    // then calls StartAsync() which is the normal public entry point.
    private static async Task ScanDirectory(GameScannerService scanner, string driveRoot)
    {
        // On Linux, $HOME is always included in GetDriveRoots(), so placing Games/ and
        // Repacks/ symlinks there ensures the scanner finds our TestData sub-directories.
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string gamesLink  = Path.Combine(home, "Games");
        string repacksLink= Path.Combine(home, "Repacks");

        bool cleanGames   = false;
        bool cleanRepacks = false;

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

            await scanner.StartAsync();
        }
        finally
        {
            if (cleanGames)   try { Directory.Delete(gamesLink); }   catch { }
            if (cleanRepacks) try { Directory.Delete(repacksLink); } catch { }
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
