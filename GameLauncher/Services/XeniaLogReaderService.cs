using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace GameLauncher.Services;

/// <summary>
/// Reads Xenia emulator log files and extracts achievement-unlock events.
///
/// <para>Xenia outputs lines like:</para>
/// <code>Achievement unlocked: 1234 My Achievement Name</code>
///
/// <para>This service:</para>
/// <list type="number">
///   <item>Locates and optionally clears stale Xenia log files before a session.</item>
///   <item>After the emulator exits, reads the freshly-written log and extracts
///         every achievement-unlock line.</item>
///   <item>Cross-references against the per-game achievements cache so that
///         achievements already recorded are skipped (Xenia replays all unlocks
///         on every emulator restart).</item>
///   <item>Returns only newly unlocked achievements that are not yet cached.</item>
/// </list>
/// </summary>
public static class XeniaLogReaderService
{
    // ── Pattern matching ────────────────────────────────────────────────────

    /// <summary>
    /// Matches Xenia achievement-unlock log lines:
    ///   Achievement unlocked: &lt;id&gt; &lt;name&gt;
    /// Groups: 1 = achievement ID (numeric), 2 = achievement name (rest of line).
    /// </summary>
    private static readonly Regex _unlockPattern =
        new(@"(?i)achievement\s+unlocked[:\s]+(\d+)\s+(.*)", RegexOptions.Compiled);

    // ── Log directory discovery ─────────────────────────────────────────────

    /// <summary>
    /// Returns the Xenia log directory for the given emulator path.
    /// Checks portable mode first (<c>{xeniaDir}\Logs\</c>), then falls back
    /// to the standard AppData location (<c>%APPDATA%\Xenia\Logs\</c>).
    /// Returns <see langword="null"/> when the emulator path is empty.
    /// </summary>
    public static string? FindLogDirectory(string xeniaExePath)
    {
        if (string.IsNullOrEmpty(xeniaExePath)) return null;

        string xeniaDir = Path.GetDirectoryName(xeniaExePath) ?? "";

        // Portable mode: logs next to the exe
        string portableLogs = Path.Combine(xeniaDir, "Logs");
        if (Directory.Exists(portableLogs)) return portableLogs;

        // Standard AppData mode
        string appDataLogs = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Xenia", "Logs");
        if (Directory.Exists(appDataLogs)) return appDataLogs;

        // Return the AppData path even if it doesn't exist yet — it may be
        // created by the emulator during the session.
        return appDataLogs;
    }

    /// <summary>
    /// Deletes all <c>*.log</c> files found in the Xenia log directory so the
    /// next session starts with a clean log.
    /// Silently skips files that are locked or otherwise undeletable.
    /// </summary>
    public static void DeleteOldLogs(string xeniaExePath)
    {
        string? logDir = FindLogDirectory(xeniaExePath);
        if (logDir == null || !Directory.Exists(logDir)) return;

        foreach (string file in Directory.EnumerateFiles(logDir, "*.log"))
        {
            try { File.Delete(file); }
            catch { /* file in use or access denied — skip */ }
        }
    }

    /// <summary>
    /// Returns the path of the most-recently-written <c>*.log</c> file in the
    /// Xenia log directory, or <see langword="null"/> when none is found.
    /// </summary>
    public static string? FindLatestLog(string xeniaExePath)
    {
        string? logDir = FindLogDirectory(xeniaExePath);
        if (logDir == null || !Directory.Exists(logDir)) return null;

        return Directory.EnumerateFiles(logDir, "*.log")
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    // ── Achievement extraction ──────────────────────────────────────────────

    /// <summary>
    /// Reads the most recent Xenia log file and returns a list of all achievement-unlock
    /// entries found in it.  Each entry is a tuple of (id, name).
    /// Returns an empty list when the log file does not exist or contains no unlocks.
    /// </summary>
    public static IReadOnlyList<(string Id, string Name)> ReadUnlocks(string xeniaExePath)
    {
        string? logPath = FindLatestLog(xeniaExePath);
        if (logPath == null || !File.Exists(logPath)) return [];

        var unlocks = new List<(string, string)>();
        try
        {
            foreach (string line in File.ReadLines(logPath))
            {
                var m = _unlockPattern.Match(line);
                if (!m.Success) continue;
                string id   = m.Groups[1].Value.Trim();
                string name = m.Groups[2].Value.Trim();
                if (!string.IsNullOrEmpty(id))
                    unlocks.Add((id, name));
            }
        }
        catch { /* best-effort — log may still be open by the emulator */ }

        // Deduplicate by id (Xenia may log the same unlock multiple times)
        return unlocks
            .GroupBy(u => u.Item1)
            .Select(g => g.First())
            .ToList();
    }

    /// <summary>
    /// Returns only the achievement-unlock entries that are NOT already present
    /// in the supplied cached achievement set.
    ///
    /// <para>Xenia re-replays all achievement unlocks on every emulator restart,
    /// so this method is necessary to avoid double-counting.</para>
    /// </summary>
    /// <param name="xeniaExePath">Path to the Xenia executable.</param>
    /// <param name="alreadyUnlockedIds">
    /// Set of achievement IDs already recorded in the local cache (achievements.json).
    /// May be <see langword="null"/> to treat all entries as new.
    /// </param>
    public static IReadOnlyList<(string Id, string Name)> GetNewUnlocks(
        string xeniaExePath,
        IReadOnlySet<string>? alreadyUnlockedIds)
    {
        var all = ReadUnlocks(xeniaExePath);
        if (alreadyUnlockedIds == null || alreadyUnlockedIds.Count == 0) return all;

        return all
            .Where(u => !alreadyUnlockedIds.Contains(u.Id))
            .ToList();
    }
}
