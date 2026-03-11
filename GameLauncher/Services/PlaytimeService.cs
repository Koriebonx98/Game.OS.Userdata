using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using GameLauncher.Models;

namespace GameLauncher.Services
{
    /// <summary>
    /// Tracks how long the user plays each game.
    /// Records a play session when a game process is launched and detects its exit,
    /// then persists the accumulated minutes to a local JSON file.
    /// Also updates <see cref="Game.PlaytimeMinutes"/> and <see cref="Game.LastPlayedAt"/>
    /// on the in-memory library list.
    /// </summary>
    public sealed class PlaytimeService : IDisposable
    {
        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "GameOS", "Playtime");

        private static readonly string SessionsFile = Path.Combine(DataDir, "sessions.json");

        private static readonly JsonSerializerOptions _jsonOpts =
            new JsonSerializerOptions { WriteIndented = true };

        // Active watch record: process + metadata
        private sealed class WatchEntry
        {
            public Process  Proc      { get; init; } = null!;
            public string   Title     { get; init; } = "";
            public string   Platform  { get; init; } = "";
            public DateTime StartedAt { get; init; }
        }

        private readonly List<WatchEntry> _watching = new();

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Called after a game process has been started.
        /// The service monitors the process and records the session on exit.
        /// </summary>
        public void TrackProcess(Process proc, string title, string platform,
                                 List<Game>? libraryToUpdate = null)
        {
            if (proc == null || proc.HasExited) return;

            var entry = new WatchEntry
            {
                Proc      = proc,
                Title     = title,
                Platform  = platform,
                StartedAt = DateTime.UtcNow,
            };
            _watching.Add(entry);

            proc.EnableRaisingEvents = true;
            proc.Exited += (_, _) =>
            {
                _watching.Remove(entry);
                var minutes = (int)(DateTime.UtcNow - entry.StartedAt).TotalMinutes;
                if (minutes < 1) minutes = 1; // round up to at least 1 minute

                var session = new PlaySession
                {
                    Platform  = platform,
                    Title     = title,
                    StartedAt = entry.StartedAt.ToString("o"),
                    EndedAt   = DateTime.UtcNow.ToString("o"),
                    Minutes   = minutes,
                };

                AppendSession(session);

                if (libraryToUpdate != null)
                    UpdateLibraryEntry(libraryToUpdate, platform, title, minutes);
            };
        }

        /// <summary>
        /// Loads the accumulated playtime totals from disk and applies them to
        /// the given library list (updating <see cref="Game.PlaytimeMinutes"/> and
        /// <see cref="Game.LastPlayedAt"/> for each matching game).
        /// Call this once at login so the dashboard shows accurate totals.
        /// </summary>
        public static void ApplyStoredPlaytime(List<Game> library)
        {
            try
            {
                var sessions = LoadSessions();
                if (sessions.Count == 0) return;

                // Group sessions by (platform, title) and sum minutes / find latest session
                var grouped = sessions
                    .GroupBy(s => $"{s.Platform.ToLowerInvariant()}||{s.Title.ToLowerInvariant()}")
                    .ToDictionary(
                        g => g.Key,
                        g => (TotalMinutes: g.Sum(s => s.Minutes),
                              LastPlayed:   g.Max(s => s.EndedAt)));

                foreach (var game in library)
                {
                    var key = $"{game.Platform.ToLowerInvariant()}||{game.Title.ToLowerInvariant()}";
                    if (grouped.TryGetValue(key, out var agg))
                    {
                        game.PlaytimeMinutes = agg.TotalMinutes;
                        if (!string.IsNullOrEmpty(agg.LastPlayed))
                            game.LastPlayedAt = agg.LastPlayed;
                    }
                }
            }
            catch { /* best-effort */ }
        }

        /// <summary>Returns total minutes played for a given game.</summary>
        public static int GetTotalMinutes(string platform, string title)
        {
            try
            {
                return LoadSessions()
                    .Where(s => string.Equals(s.Platform, platform, StringComparison.OrdinalIgnoreCase)
                             && string.Equals(s.Title, title, StringComparison.OrdinalIgnoreCase))
                    .Sum(s => s.Minutes);
            }
            catch { return 0; }
        }

        public void Dispose()
        {
            // Nothing to dispose — process exit events are unmanaged
        }

        // ── Private helpers ────────────────────────────────────────────────────

        private static void AppendSession(PlaySession session)
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                var sessions = LoadSessions();
                sessions.Add(session);
                File.WriteAllText(SessionsFile,
                    JsonSerializer.Serialize(sessions, _jsonOpts));
            }
            catch { /* best-effort */ }
        }

        private static List<PlaySession> LoadSessions()
        {
            try
            {
                if (!File.Exists(SessionsFile)) return new List<PlaySession>();
                var json = File.ReadAllText(SessionsFile);
                return JsonSerializer.Deserialize<List<PlaySession>>(json)
                       ?? new List<PlaySession>();
            }
            catch { return new List<PlaySession>(); }
        }

        private static void UpdateLibraryEntry(List<Game> library,
                                               string platform, string title, int newMinutes)
        {
            var game = library.FirstOrDefault(g =>
                string.Equals(g.Platform, platform, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.Title,    title,    StringComparison.OrdinalIgnoreCase));

            if (game == null) return;

            game.PlaytimeMinutes += newMinutes;
            game.LastPlayedAt    = DateTime.UtcNow.ToString("o");
        }
    }
}
