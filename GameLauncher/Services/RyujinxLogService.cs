using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace GameLauncher.Services
{
    /// <summary>
    /// Helpers for managing Ryujinx log files around a Switch game session.
    ///
    /// Log directory resolution:
    /// <list type="bullet">
    ///   <item>Portable mode — <c>{ryujinxDir}\portable\Logs</c></item>
    ///   <item>Standard mode — <c>%APPDATA%\Ryujinx\Logs</c></item>
    /// </list>
    ///
    /// Usage:
    /// <list type="number">
    ///   <item>Call <see cref="DeleteLogs"/> before starting the emulator to clear stale logs.</item>
    ///   <item>After the emulator exits, call <see cref="ScanForRoomEntries"/> to extract
    ///         "Room: " achievement-data blocks from the new log file.</item>
    /// </list>
    /// </summary>
    public static class RyujinxLogService
    {
        // ── Directory resolution ───────────────────────────────────────────────

        /// <summary>
        /// Returns the Ryujinx Logs directory for the given emulator executable.
        /// Portable mode is checked first; falls back to the standard AppData location.
        /// Always returns a non-null path (the portable candidate) even when the
        /// directory does not yet exist.
        /// </summary>
        public static string FindLogsDirectory(string ryujinxExePath)
        {
            string ryujinxDir = Path.GetDirectoryName(ryujinxExePath) ?? "";

            // Portable mode
            string portableLogs = Path.Combine(ryujinxDir, "portable", "Logs");
            if (Directory.Exists(portableLogs)) return portableLogs;

            // Standard AppData mode
            string appDataLogs = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Ryujinx", "Logs");
            if (Directory.Exists(appDataLogs)) return appDataLogs;

            // Return the portable candidate as a default (may be created by first Ryujinx run)
            return portableLogs;
        }

        // ── Pre-launch log cleanup ─────────────────────────────────────────────

        /// <summary>
        /// Deletes all <c>*.log</c> files in the Ryujinx Logs directory so the
        /// post-session scan only sees logs created during the current play session.
        /// </summary>
        public static void DeleteLogs(string ryujinxExePath)
        {
            if (string.IsNullOrEmpty(ryujinxExePath)) return;
            try
            {
                string logsDir = FindLogsDirectory(ryujinxExePath);
                if (!Directory.Exists(logsDir)) return;

                foreach (var file in Directory.GetFiles(logsDir, "*.log"))
                {
                    try { File.Delete(file); }
                    catch { /* individual file deletion is best-effort */ }
                }
            }
            catch { /* best-effort — do not block game launch */ }
        }

        // ── Post-session log scanning ──────────────────────────────────────────

        /// <summary>
        /// Scans every <c>*.log</c> file in the Ryujinx Logs directory for
        /// <c>Room: </c> entries and returns the raw text of each block found.
        ///
        /// Each returned string contains the text starting at "Room: " and ending
        /// at (and including) the closing brace of the JSON "Report" object.
        /// </summary>
        public static List<string> ScanForRoomEntries(string ryujinxExePath)
        {
            var results = new List<string>();
            if (string.IsNullOrEmpty(ryujinxExePath)) return results;

            try
            {
                string logsDir = FindLogsDirectory(ryujinxExePath);
                if (!Directory.Exists(logsDir)) return results;

                // Process the most recently modified log first
                var logFiles = Directory.GetFiles(logsDir, "*.log")
                    .OrderByDescending(f => File.GetLastWriteTimeUtc(f));

                foreach (var logFile in logFiles)
                {
                    try
                    {
                        string text = File.ReadAllText(logFile);
                        results.AddRange(ExtractRoomEntries(text));
                    }
                    catch { /* best-effort per file */ }
                }
            }
            catch { /* best-effort */ }

            return results;
        }

        // ── Private helpers ────────────────────────────────────────────────────

        /// <summary>
        /// Extracts all "Room: … Report: { … }" blocks from <paramref name="logText"/>.
        /// Each returned entry spans from the "Room: " marker to the closing brace of
        /// the Report JSON object (depth-aware brace matching).
        /// </summary>
        private static List<string> ExtractRoomEntries(string logText)
        {
            var entries = new List<string>();
            int searchFrom = 0;

            while (true)
            {
                // Find next "Room: " marker
                int roomIdx = logText.IndexOf("Room: ", searchFrom, StringComparison.Ordinal);
                if (roomIdx < 0) break;

                // Find "Report: {" after the Room marker
                int reportIdx = logText.IndexOf("Report: {", roomIdx, StringComparison.Ordinal);
                if (reportIdx < 0)
                {
                    searchFrom = roomIdx + 1;
                    continue;
                }

                // Depth-aware scan to find the matching closing brace of the JSON block
                int braceStart = reportIdx + "Report: ".Length; // points at '{'
                int depth = 0;
                int endIdx = -1;

                for (int i = braceStart; i < logText.Length; i++)
                {
                    if (logText[i] == '{')       depth++;
                    else if (logText[i] == '}')
                    {
                        depth--;
                        if (depth == 0)
                        {
                            endIdx = i;
                            break;
                        }
                    }
                }

                if (endIdx >= 0)
                    entries.Add(logText.Substring(roomIdx, endIdx - roomIdx + 1));

                searchFrom = endIdx >= 0 ? endIdx + 1 : roomIdx + 1;
            }

            return entries;
        }
    }
}
