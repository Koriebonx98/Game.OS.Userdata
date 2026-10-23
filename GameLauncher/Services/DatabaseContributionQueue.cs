using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// Persistent, de-duplicated queue of contributions (new Steam games, achievements,
    /// descriptions, trailers …) destined for the public Games.Database repository.
    /// Instead of writing to GitHub on every user action, entries are queued locally and a
    /// background task flushes them in one batch every <see cref="FlushInterval"/>, which
    /// reduces upload traffic and avoids adding the same item twice.
    /// Stored at <c>%APPDATA%\GameOS\db-contribution-queue.json</c>.
    /// </summary>
    public static class DatabaseContributionQueue
    {
        public static readonly TimeSpan FlushInterval = TimeSpan.FromMinutes(10);
        /// <summary>ROM contributions are batched and uploaded at most this often.</summary>
        public static readonly TimeSpan RomFlushInterval = TimeSpan.FromHours(1);
        private const int MaxQueueSize = 500;
        private static DateTime _lastRomFlushUtc = DateTime.UtcNow;

        public class Item
        {
            /// <summary>"file" (create-only JSON file) or "steamgame".</summary>
            public string Kind { get; set; } = "file";
            public string Key { get; set; } = "";
            public string Path { get; set; } = "";
            public string ContentJson { get; set; } = "";
            public string Message { get; set; } = "";
            public long AppId { get; set; }
            public string Name { get; set; } = "";
            /// <summary>Platform name for "rom" items (e.g. "PS2").</summary>
            public string Platform { get; set; } = "";
            public string? TitleId { get; set; }
        }

        private static readonly string QueuePath = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "GameOS", "db-contribution-queue.json");

        private static readonly object _lock = new();
        private static List<Item>? _items;
        private static CancellationTokenSource? _cts;

        private static List<Item> Items()
        {
            if (_items != null) return _items;
            try
            {
                _items = File.Exists(QueuePath)
                    ? JsonSerializer.Deserialize<List<Item>>(File.ReadAllText(QueuePath)) ?? new()
                    : new();
            }
            catch { _items = new(); }
            return _items;
        }

        private static void Save()
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(QueuePath)!);
                File.WriteAllText(QueuePath, JsonSerializer.Serialize(_items));
            }
            catch { /* best-effort */ }
        }

        /// <summary>Queues a JSON file to be created in Games.Database if it does not already exist.</summary>
        public static bool EnqueueFile(string path, object content, string message)
        {
            string key = "file:" + path.ToLowerInvariant();
            lock (_lock)
            {
                var items = Items();
                if (items.Count >= MaxQueueSize || items.Any(i => i.Key == key)) return false;
                items.Add(new Item
                {
                    Kind = "file", Key = key, Path = path, Message = message,
                    ContentJson = JsonSerializer.Serialize(content),
                });
                Save();
                return true;
            }
        }

        /// <summary>Queues a Steam game (AppId + name) for the PC games list.</summary>
        public static bool EnqueueSteamGame(long appId, string name)
        {
            if (appId <= 0) return false;
            string key = "steamgame:" + appId;
            lock (_lock)
            {
                var items = Items();
                if (items.Count >= MaxQueueSize || items.Any(i => i.Key == key)) return false;
                items.Add(new Item { Kind = "steamgame", Key = key, AppId = appId, Name = name });
                Save();
                return true;
            }
        }

        /// <summary>Queues a locally found ROM that is missing from the platform games database.</summary>
        public static bool EnqueueRom(string platform, string title, string? titleId)
        {
            if (string.IsNullOrWhiteSpace(platform) || string.IsNullOrWhiteSpace(title)) return false;
            string key = "rom:" + platform.ToLowerInvariant() + ":" +
                         (string.IsNullOrWhiteSpace(titleId) ? title : titleId).ToLowerInvariant();
            lock (_lock)
            {
                var items = Items();
                if (items.Count >= MaxQueueSize || items.Any(i => i.Key == key)) return false;
                items.Add(new Item { Kind = "rom", Key = key, Platform = platform, Name = title, TitleId = titleId });
                Save();
                return true;
            }
        }

        public static int Count { get { lock (_lock) return Items().Count; } }

        /// <summary>Starts the periodic background flush (idempotent).</summary>
        public static void Start()
        {
            lock (_lock)
            {
                if (_cts != null) return;
                _cts = new CancellationTokenSource();
            }
            var ct = _cts.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
                    while (!ct.IsCancellationRequested)
                    {
                        await FlushAsync(ct).ConfigureAwait(false);
                        await Task.Delay(FlushInterval, ct).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex) { DevLogService.Log($"[DbQueue] Stopped: {ex.Message}"); }
            });
        }

        public static void Stop()
        {
            lock (_lock) { _cts?.Cancel(); _cts = null; }
        }

        /// <summary>Uploads all queued items in one batch; failed items stay queued for the next run.</summary>
        public static async Task FlushAsync(CancellationToken ct = default)
        {
            if (GitHubDataService.GitHubToken == null) return;
            List<Item> snapshot;
            lock (_lock) snapshot = Items().ToList();
            if (snapshot.Count == 0) return;

            DevLogService.Log($"[DbQueue] Flushing {snapshot.Count} queued contribution(s)…");
            var done = new List<Item>();
            using var svc = new GitHubDataService();

            var games = snapshot.Where(i => i.Kind == "steamgame").ToList();
            if (games.Count > 0)
            {
                try
                {
                    await svc.ContributeSteamGamesToDatabaseAsync(
                        games.Select(g => new SteamOwnedGame { AppId = (int)g.AppId, Name = g.Name }).ToList(), ct)
                        .ConfigureAwait(false);
                    done.AddRange(games);
                }
                catch (Exception ex) { DevLogService.Log($"[DbQueue] Steam games batch failed: {ex.Message}"); }
            }

            var roms = snapshot.Where(i => i.Kind == "rom").ToList();
            if (roms.Count > 0 && DateTime.UtcNow - _lastRomFlushUtc >= RomFlushInterval)
            {
                try
                {
                    var handled = await svc.ContributeRomsToDatabaseAsync(
                        roms.Select(r => (r.Platform, r.Name, r.TitleId)).ToList(), ct).ConfigureAwait(false);
                    done.AddRange(roms.Where(r => handled.Contains(r.Platform)));
                    if (handled.Count == roms.Select(r => r.Platform).Distinct().Count())
                        _lastRomFlushUtc = DateTime.UtcNow;
                }
                catch (Exception ex) { DevLogService.Log($"[DbQueue] ROM batch failed: {ex.Message}"); }
            }

            foreach (var item in snapshot.Where(i => i.Kind == "file"))
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var (existing, sha) = await svc.ReadGamesDatabaseFileAsync<object>(item.Path, ct)
                        .ConfigureAwait(false);
                    if (existing == null)
                    {
                        using var doc = JsonDocument.Parse(item.ContentJson);
                        await svc.WriteGamesDatabaseFileAsync(
                            item.Path, doc.RootElement.Clone(), item.Message, sha, ct).ConfigureAwait(false);
                    }
                    done.Add(item);
                    await Task.Delay(500, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { DevLogService.Log($"[DbQueue] '{item.Path}' failed, will retry: {ex.Message}"); }
            }

            lock (_lock)
            {
                var keys = done.Select(d => d.Key).ToHashSet();
                Items().RemoveAll(i => keys.Contains(i.Key));
                Save();
            }
        }
    }
}
