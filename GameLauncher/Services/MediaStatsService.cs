using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace GameLauncher.Services
{
    /// <summary>Per-file play statistics for movies, TV episodes and songs.</summary>
    public sealed class MediaStat
    {
        public int PlayCount { get; set; }
        public double TotalSeconds { get; set; }
        public DateTime? LastPlayedUtc { get; set; }
        /// <summary>0 = unrated, 1-5 stars.</summary>
        public int Rating { get; set; }
        public bool Favourite { get; set; }
        public bool Watched { get; set; }
        /// <summary>Where video playback stopped, so it can resume.</summary>
        public long ResumeMs { get; set; }
        public long DurationMs { get; set; }
    }

    /// <summary>One finished listening / watching session (the media counterpart of a game play session).</summary>
    public sealed class MediaSession
    {
        public string Path { get; set; } = "";
        public string Title { get; set; } = "";
        /// <summary>"movie", "tv" or "music".</summary>
        public string Kind { get; set; } = "";
        public DateTime StartUtc { get; set; }
        public double Seconds { get; set; }
    }

    /// <summary>
    /// Stores play counts, ratings, favourites, resume points and session history for media files,
    /// per user, under <c>Data\{user}\Media\</c>.
    /// </summary>
    public static class MediaStatsService
    {
        private static readonly object Lock = new();
        private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
        private const int MaxSessions = 2000;

        private static string? _user;
        private static Dictionary<string, MediaStat>? _stats;
        private static List<MediaSession>? _sessions;

        public static void SetCurrentUser(string? username)
        {
            lock (Lock)
            {
                _user = string.IsNullOrWhiteSpace(username) ? null : username;
                _stats = null;
                _sessions = null;
            }
        }

        private static string Dir
        {
            get
            {
                string user = new string((_user ?? "_shared").Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c).ToArray());
                return Path.Combine(UserDataService.DataRoot, user, "Media");
            }
        }

        private static string StatsFile => Path.Combine(Dir, "stats.json");
        private static string SessionsFile => Path.Combine(Dir, "sessions.json");

        private static Dictionary<string, MediaStat> Stats => _stats ??= Read<Dictionary<string, MediaStat>>(StatsFile)
            is { } d ? new Dictionary<string, MediaStat>(d, StringComparer.OrdinalIgnoreCase) : new(StringComparer.OrdinalIgnoreCase);

        private static List<MediaSession> Sessions => _sessions ??= Read<List<MediaSession>>(SessionsFile) ?? new();

        private static T? Read<T>(string file) where T : class
        {
            try { return File.Exists(file) ? JsonSerializer.Deserialize<T>(File.ReadAllText(file)) : null; }
            catch (Exception ex) { DevLogService.Log($"[MediaStats] Read {Path.GetFileName(file)} failed: {ex.Message}"); return null; }
        }

        private static void Write(string file, object data)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                var tmp = file + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(data, Json));
                File.Move(tmp, file, overwrite: true);
            }
            catch (Exception ex) { DevLogService.Log($"[MediaStats] Write {Path.GetFileName(file)} failed: {ex.Message}"); }
        }

        /// <summary>A copy of the stored stats for a file (empty stats when never played).</summary>
        public static MediaStat Get(string path)
        {
            lock (Lock)
            {
                if (!Stats.TryGetValue(path, out var s)) return new MediaStat();
                return new MediaStat
                {
                    PlayCount = s.PlayCount, TotalSeconds = s.TotalSeconds, LastPlayedUtc = s.LastPlayedUtc, Rating = s.Rating,
                    Favourite = s.Favourite, Watched = s.Watched, ResumeMs = s.ResumeMs, DurationMs = s.DurationMs,
                };
            }
        }

        /// <summary>Applies <paramref name="change"/> to the file's stats and saves; returns the updated copy.</summary>
        public static MediaStat Update(string path, Action<MediaStat> change)
        {
            lock (Lock)
            {
                if (!Stats.TryGetValue(path, out var s)) Stats[path] = s = new MediaStat();
                change(s);
                Write(StatsFile, Stats);
            }
            return Get(path);
        }

        public static void AddSession(MediaSession session)
        {
            if (session.Seconds < 5) return;
            lock (Lock)
            {
                Sessions.Add(session);
                if (Sessions.Count > MaxSessions) Sessions.RemoveRange(0, Sessions.Count - MaxSessions);
                Write(SessionsFile, Sessions);
                if (Stats.TryGetValue(session.Path, out var s)) s.TotalSeconds += session.Seconds;
                else Stats[session.Path] = new MediaStat { TotalSeconds = session.Seconds };
                Write(StatsFile, Stats);
            }
        }

        /// <summary>Totals per kind for the Settings → Media page.</summary>
        public static string Summary()
        {
            lock (Lock)
            {
                string Part(string kind, string verb)
                {
                    var list = Sessions.Where(x => x.Kind == kind).ToList();
                    double h = list.Sum(x => x.Seconds) / 3600.0;
                    return $"{verb} {h:0.#} h in {list.Count} session(s)";
                }
                return $"{Part("movie", "Movies:")}  ·  {Part("tv", "TV:")}  ·  {Part("music", "Music:")}";
            }
        }
    }
}
