using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using GameLauncher.Models;
using MonoTorrent;
using MonoTorrent.Client;

namespace GameLauncher.Services
{
    /// <summary>
    /// Built-in download manager: segmented, resumable direct downloads (HTTP/HTTPS) and BitTorrent
    /// (magnet links and .torrent files via MonoTorrent), with queueing, speed limits, auto-extract,
    /// toast notifications and a persistent list in <c>%APPDATA%/GameOS/Downloads.json</c>.
    /// </summary>
    public sealed class DownloadManagerService
    {
        public static DownloadManagerService Instance { get; } = new();

        private static readonly string ListPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameOS", "Downloads.json");

        private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

        private static readonly HttpClient Http = CreateHttp();

        public ObservableCollection<DownloadItem> Items { get; } = new();

        private readonly object _gate = new();
        private readonly ConcurrentDictionary<string, CancellationTokenSource> _running = new();
        private readonly ConcurrentDictionary<string, long> _tickBytes = new();
        private readonly Dictionary<string, TorrentManager> _torrents = new();
        private ClientEngine? _engine;
        private string _engineKey = "";
        private Timer? _timer;
        private bool _loaded;
        private long _bucketTokens;
        private DateTime _bucketStamp = DateTime.UtcNow;

        private DownloadSettings _settingsCache = new();
        private long _settingsStamp;

        // Settings are read from disk; cache briefly so the per-chunk hot path never touches the file system.
        private DownloadSettings Settings
        {
            get
            {
                long now = Environment.TickCount64;
                if (now - Interlocked.Read(ref _settingsStamp) > 1500 || _settingsStamp == 0)
                {
                    _settingsCache = AppSettingsService.Load().Downloads;
                    Interlocked.Exchange(ref _settingsStamp, now == 0 ? 1 : now);
                }
                return _settingsCache;
            }
        }

        private static HttpClient CreateHttp()
        {
            var h = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10, EnableMultipleHttp2Connections = true,
                MaxConnectionsPerServer = 64, ConnectTimeout = TimeSpan.FromSeconds(30), PooledConnectionLifetime = TimeSpan.FromMinutes(10),
                AutomaticDecompression = DecompressionMethods.None }) { Timeout = Timeout.InfiniteTimeSpan };
            h.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36");
            return h;
        }

        // ── Public API ────────────────────────────────────────────────────────

        public static bool IsMagnet(string url) => url.StartsWith("magnet:", StringComparison.OrdinalIgnoreCase);

        public static bool IsTorrentUrl(string url)
        {
            if (IsMagnet(url)) return true;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
            return u.AbsolutePath.EndsWith(".torrent", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>True if the URL looks like a file download (archive, installer, disc image, torrent, magnet).</summary>
        public static bool LooksLikeDownload(string url)
        {
            if (IsMagnet(url)) return true;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "http" && u.Scheme != "https")) return false;
            string ext = Path.GetExtension(u.AbsolutePath).ToLowerInvariant();
            return ext is ".zip" or ".rar" or ".7z" or ".iso" or ".torrent" or ".exe" or ".msi" or ".bin" or ".cue"
                or ".nsp" or ".xci" or ".pkg" or ".rvz" or ".wbfs" or ".gcm" or ".img" or ".tar" or ".gz" or ".tgz"
                or ".001" or ".z01";
        }

        private static HttpRequestMessage NewRequest(DownloadItem item, bool range = false)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, item.Url);
            if (!string.IsNullOrEmpty(item.Referer)) { try { req.Headers.Referrer = new Uri(item.Referer); } catch { } }
            if (!string.IsNullOrEmpty(item.Cookie)) req.Headers.TryAddWithoutValidation("Cookie", item.Cookie);
            return req;
        }

        /// <summary>
        /// Asks the server what <paramref name="url"/> is. True when it is a file (attachment or non-web content type),
        /// so the built-in browser can hand extension-less links (gofile, buzzheavier, ...) to the downloader.
        /// </summary>
        public static async Task<bool> ProbeIsDownloadAsync(string url, string referer, string cookie, CancellationToken ct = default)
        {
            try
            {
                using var req = NewRequest(new DownloadItem { Url = url, Referer = referer, Cookie = cookie });
                using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!resp.IsSuccessStatusCode) return false;
                if (resp.Content.Headers.ContentDisposition?.DispositionType?.Equals("attachment", StringComparison.OrdinalIgnoreCase) == true) return true;
                string? mt = resp.Content.Headers.ContentType?.MediaType?.ToLowerInvariant();
                if (mt == null) return false;
                if (mt.StartsWith("text/") || mt is "application/json" or "application/xhtml+xml" or "application/javascript"
                    || mt.StartsWith("image/") || mt.StartsWith("video/") || mt.StartsWith("audio/") || mt.StartsWith("font/")) return false;
                return true;
            }
            catch { return false; }
        }

        /// <summary>True for links that usually serve a file without a file extension in the URL.</summary>
        public static bool LooksLikeDownloadEndpoint(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "http" && u.Scheme != "https")) return false;
            string p = u.AbsolutePath.ToLowerInvariant();
            string q = u.Query.ToLowerInvariant();
            return p.Contains("/download") || p.EndsWith("/dl") || p.Contains("/dl/") || p.Contains("/getfile") || p.Contains("/get_file")
                   || q.Contains("download=") || q.Contains("attachment") || q.Contains("dl=1");
        }

        private static string NameFromHeaders(HttpResponseMessage resp, DownloadItem item)
        {
            var cd = resp.Content.Headers.ContentDisposition;
            string? fn = cd?.FileNameStar;
            if (string.IsNullOrWhiteSpace(fn) && !string.IsNullOrWhiteSpace(cd?.FileName))
            {
                fn = cd!.FileName!.Trim('"');
                try
                {
                    if (fn.Contains('%')) fn = Uri.UnescapeDataString(fn);
                    else if (fn.Any(c => c > 127 && c < 256)) // UTF-8 bytes read as Latin-1
                    {
                        var decoded = System.Text.Encoding.UTF8.GetString(System.Text.Encoding.Latin1.GetBytes(fn));
                        if (!decoded.Contains('\uFFFD')) fn = decoded;
                    }
                }
                catch { }
            }
            if (string.IsNullOrWhiteSpace(fn))
                fn = GuessName(resp.RequestMessage?.RequestUri?.ToString() ?? item.Url);
            return fn!;
        }

        private static string? ExtensionForContentType(string? mt) => mt?.ToLowerInvariant() switch
        {
            "application/zip" or "application/x-zip-compressed" => ".zip",
            "application/x-rar-compressed" or "application/vnd.rar" or "application/x-rar" => ".rar",
            "application/x-7z-compressed" => ".7z",
            "application/x-bittorrent" => ".torrent",
            "application/x-iso9660-image" => ".iso",
            "application/x-msdownload" or "application/vnd.microsoft.portable-executable" => ".exe",
            "application/gzip" or "application/x-gzip" => ".gz",
            "application/x-tar" => ".tar",
            _ => null,
        };

        public static string GuessName(string url)
        {
            try
            {
                if (IsMagnet(url))
                {
                    var dn = System.Web.HttpUtility.ParseQueryString(url.Substring(url.IndexOf('?') + 1))["dn"];
                    return string.IsNullOrWhiteSpace(dn) ? "Magnet download" : dn;
                }
                if (Uri.TryCreate(url, UriKind.Absolute, out var u))
                {
                    string f = Path.GetFileName(Uri.UnescapeDataString(u.AbsolutePath));
                    if (!string.IsNullOrWhiteSpace(f)) return f;
                    return u.Host;
                }
            }
            catch { /* fall through */ }
            return "download";
        }

        public void Load()
        {
            lock (_gate)
            {
                if (_loaded) return;
                _loaded = true;
            }
            try
            {
                if (File.Exists(ListPath))
                {
                    var items = JsonSerializer.Deserialize<List<DownloadItem>>(File.ReadAllText(ListPath)) ?? new();
                    foreach (var it in items)
                    {
                        // Nothing survives a restart in-flight; interrupted items wait to be resumed by the user.
                        if (it.State is DownloadState.Downloading or DownloadState.Queued or DownloadState.Extracting or DownloadState.Seeding)
                            it.State = it.State == DownloadState.Seeding ? DownloadState.Completed : DownloadState.Paused;
                        it.SpeedBytesPerSec = 0;
                        Items.Add(it);
                    }
                }
            }
            catch (Exception ex) { DevLogService.Log($"[Downloads] load failed: {ex.Message}"); }
            _timer ??= new Timer(_ => Tick(), null, 1000, 1000);
        }

        /// <summary>Queues a new download into <c>&lt;Root&gt;/...</c> per category/platform and starts it when a slot is free.</summary>
        public DownloadItem Add(string url, string name, string category, string platform, string referer = "", string cookie = "", string game = "")
        {
            Load();
            var s = Settings;
            string root = DownloadPathResolver.ResolveRoot(s.RootFolder);
            var item = new DownloadItem
            {
                Url = url.Trim(),
                Kind = IsTorrentUrl(url) ? DownloadKind.Torrent : DownloadKind.Direct,
                Name = string.IsNullOrWhiteSpace(name) ? GuessName(url) : name,
                CustomName = !string.IsNullOrWhiteSpace(name) && name != GuessName(url),
                GameTitle = game ?? "",
                Referer = referer ?? "",
                Cookie = cookie ?? "",
                Category = category,
                Platform = platform,
                Folder = DownloadPathResolver.Resolve(root, platform, category),
            };
            Ui(() => { Items.Insert(0, item); });
            Save();
            Pump();
            return item;
        }

        public void Pause(DownloadItem item)
        {
            StopRunning(item);
            Ui(() => { if (item.State != DownloadState.Completed) item.State = DownloadState.Paused; item.SpeedBytesPerSec = 0; });
            Save();
            if (Settings.NotifyOnPause) Notify("Download paused", item.Name);
            Pump();
        }

        public void Resume(DownloadItem item)
        {
            if (!item.CanResume) return;
            Ui(() => { item.Error = ""; item.State = DownloadState.Queued; });
            Pump();
        }

        public void Cancel(DownloadItem item)
        {
            StopRunning(item);
            Ui(() => { item.State = DownloadState.Cancelled; item.SpeedBytesPerSec = 0; });
            Save();
            Pump();
        }

        public void Remove(DownloadItem item, bool deleteFiles)
        {
            StopRunning(item);
            if (deleteFiles)
            {
                try { if (item.Kind == DownloadKind.Direct && File.Exists(item.FilePath)) File.Delete(item.FilePath); } catch { }
                try { if (File.Exists(item.FilePath + ".part")) File.Delete(item.FilePath + ".part"); } catch { }
            }
            Ui(() => Items.Remove(item));
            Save();
            Pump();
        }

        public void ClearFinished()
        {
            Ui(() =>
            {
                foreach (var it in Items.Where(i => i.State is DownloadState.Completed or DownloadState.Cancelled or DownloadState.Failed).ToList())
                    Items.Remove(it);
            });
            Save();
        }

        public void OpenFolder(DownloadItem item)
        {
            try
            {
                string path = Directory.Exists(item.Folder) ? item.Folder : (Path.GetDirectoryName(item.FilePath) ?? item.Folder);
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true });
            }
            catch { /* best-effort */ }
        }

        // ── Scheduling ────────────────────────────────────────────────────────

        private void Pump()
        {
            List<DownloadItem> toStart = new();
            var snapshot = Snapshot();
            lock (_gate)
            {
                int max = Math.Max(1, Settings.MaxConcurrent);
                int active = _running.Count;
                foreach (var it in snapshot.AsEnumerable().Reverse().Where(i => i.State == DownloadState.Queued && !_running.ContainsKey(i.Id)))
                {
                    if (active >= max) break;
                    var cts = new CancellationTokenSource();
                    _running[it.Id] = cts;
                    active++;
                    toStart.Add(it);
                }
            }
            foreach (var it in toStart)
                _ = Task.Run(() => RunAsync(it, _running[it.Id]));
        }

        private void StopRunning(DownloadItem item)
        {
            if (_running.TryRemove(item.Id, out var cts))
            {
                try { cts.Cancel(); } catch { }
            }
            TorrentManager? m;
            lock (_gate) { _torrents.TryGetValue(item.Id, out m); _torrents.Remove(item.Id); }
            if (m != null && _engine != null)
                _ = Task.Run(async () => { try { await m.StopAsync(); await _engine.RemoveAsync(m); } catch { } });
        }

        private async Task RunAsync(DownloadItem item, CancellationTokenSource cts)
        {
            try
            {
                Ui(() => { item.State = DownloadState.Downloading; item.Error = ""; });
                if (Settings.NotifyOnStart) Notify("Download started", $"{item.Name}  ({item.Category} · {item.Platform})");

                if (item.Kind == DownloadKind.Torrent)
                    await RunTorrentAsync(item, cts.Token);
                else
                    await RunDirectAsync(item, cts.Token);

                if (cts.IsCancellationRequested) return;

                await FinishAsync(item, cts.Token);
            }
            catch (OperationCanceledException) { /* paused or cancelled by the user */ }
            catch (Exception ex)
            {
                DevLogService.Log($"[Downloads] '{item.Name}' failed: {ex}");
                if (cts.IsCancellationRequested) return;
                Ui(() => { item.Error = ex.Message; item.State = DownloadState.Failed; item.SpeedBytesPerSec = 0; });
                if (Settings.NotifyOnFail) Notify("Download failed", $"{item.Name}: {ex.Message}");
            }
            finally
            {
                _running.TryRemove(item.Id, out _);
                Save();
                Pump();
            }
        }

        private async Task FinishAsync(DownloadItem item, CancellationToken ct)
        {
            var s = Settings;
            if (s.AutoExtract && !item.Extracted)
            {
                var archives = FindArchivesToExtract(item);
                if (archives.Count > 0)
                {
                    Ui(() => { item.State = DownloadState.Extracting; item.ExtractProgress = 0; });
                    try
                    {
                        for (int i = 0; i < archives.Count; i++)
                        {
                            string archive = archives[i];
                            string dest = Path.Combine(Path.GetDirectoryName(archive)!,
                                DownloadPathResolver.SanitizeFileName(Path.GetFileNameWithoutExtension(archive)));
                            int idx = i;
                            var progress = new Progress<double>(p => item.ExtractProgress = (idx * 100.0 + p) / archives.Count);
                            await ArchiveExtractor.ExtractAsync(archive, dest, progress, ct);
                            if (s.DeleteArchiveAfterExtract) DeleteArchiveVolumes(archive);
                        }
                        item.Extracted = true;
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        DevLogService.Log($"[Downloads] extract failed for '{item.Name}': {ex}");
                        Ui(() => { item.Error = $"Extraction failed: {ex.Message}"; item.State = DownloadState.Failed; });
                        if (s.NotifyOnFail) Notify("Extraction failed", $"{item.Name}: {ex.Message}");
                        return;
                    }
                }
            }

            bool seed = item.Kind == DownloadKind.Torrent && s.TorrentSeedAfterComplete && !item.Extracted;
            Ui(() =>
            {
                item.CompletedUtc = DateTime.UtcNow;
                item.SpeedBytesPerSec = 0;
                item.State = DownloadState.Completed;
            });
            if (s.NotifyOnComplete) Notify("Download complete", item.Name);
            _ = seed; // seeding is handled by the torrent loop itself
        }

        private static List<string> FindArchivesToExtract(DownloadItem item)
        {
            var result = new List<string>();
            try
            {
                if (item.Kind == DownloadKind.Direct)
                {
                    if (ArchiveExtractor.IsArchive(item.FilePath) && File.Exists(item.FilePath)) result.Add(item.FilePath);
                    return result;
                }
                string root = !string.IsNullOrEmpty(item.FilePath) ? item.FilePath : Path.Combine(item.Folder, item.Name);
                if (File.Exists(root)) { if (ArchiveExtractor.IsArchive(root)) result.Add(root); return result; }
                if (!Directory.Exists(root)) return result;
                foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    if (!ArchiveExtractor.IsArchive(f)) continue;
                    string name = Path.GetFileName(f);
                    // Only the first volume of a multi-part RAR set; the others are read automatically.
                    if (System.Text.RegularExpressions.Regex.IsMatch(name, @"\.part0*([2-9]|\d{2,})\.rar$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) continue;
                    result.Add(f);
                }
            }
            catch { /* best-effort */ }
            return result;
        }

        private static void DeleteArchiveVolumes(string archive)
        {
            try
            {
                string dir = Path.GetDirectoryName(archive)!;
                string name = Path.GetFileName(archive);
                var m = System.Text.RegularExpressions.Regex.Match(name, @"^(?<n>.+)\.part0*\d+\.rar$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success)
                    foreach (var f in Directory.EnumerateFiles(dir, m.Groups["n"].Value + ".part*.rar")) File.Delete(f);
                else
                    File.Delete(archive);
            }
            catch { /* best-effort */ }
        }

        // ── Direct download ───────────────────────────────────────────────────

        private async Task RunDirectAsync(DownloadItem item, CancellationToken ct)
        {
            Directory.CreateDirectory(item.Folder);

            using var probe = NewRequest(item);
            probe.Headers.Range = new RangeHeaderValue(0, 0);
            var head = await Http.SendAsync(probe, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!head.IsSuccessStatusCode && head.StatusCode != HttpStatusCode.PartialContent)
            {
                // Some hosts reject Range probes; retry as a plain request.
                head.Dispose();
                using var plain = NewRequest(item);
                head = await Http.SendAsync(plain, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            using var _ = head;
            if (!head.IsSuccessStatusCode)
                throw new HttpRequestException($"Server answered {(int)head.StatusCode} {head.ReasonPhrase}. The link may have expired or need you to be signed in.");

            string? mediaType = head.Content.Headers.ContentType?.MediaType;
            if (string.Equals(mediaType, "text/html", StringComparison.OrdinalIgnoreCase)
                && head.Content.Headers.ContentDisposition?.DispositionType?.Equals("attachment", StringComparison.OrdinalIgnoreCase) != true)
                throw new IOException("The link opened a web page instead of a file. Open it in the browser and start the download from the page.");

            bool ranges = head.StatusCode == HttpStatusCode.PartialContent;
            long total = ranges ? (head.Content.Headers.ContentRange?.Length ?? 0) : (head.Content.Headers.ContentLength ?? 0);
            if (ranges && total <= 0) ranges = false;

            if (string.IsNullOrEmpty(item.FilePath))
            {
                string fn = item.CustomName ? item.Name : NameFromHeaders(head, item);
                fn = DownloadPathResolver.SanitizeFileName(fn);
                if (string.IsNullOrEmpty(Path.GetExtension(fn)) && ExtensionForContentType(mediaType) is { } ext) fn += ext;
                string path = Path.Combine(item.Folder, fn);
                Ui(() => { item.Name = fn; item.FilePath = path; });
            }
            Ui(() => item.TotalBytes = total);

            string part = item.FilePath + ".part";
            int connections = ranges && total > 1024 * 1024 ? Math.Clamp(Settings.ConnectionsPerDownload == 4 ? 8 : Settings.ConnectionsPerDownload, 1, 32) : 1;

            if (connections > 1 && item.SegmentProgress.Count != connections)
                item.SegmentProgress = new List<long>(Enumerable.Repeat(0L, connections));
            if (connections == 1)
            {
                long have = File.Exists(part) ? new FileInfo(part).Length : 0;
                if (!ranges) have = 0;
                item.SegmentProgress = new List<long> { have };
            }

            using (var fs = new FileStream(part, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite))
            {
                if (total > 0 && fs.Length != total && connections > 1) fs.SetLength(total);
                if (connections == 1 && !ranges) fs.SetLength(0);
            }

            long segSize = connections > 1 ? (total + connections - 1) / connections : total;
            var tasks = new List<Task>();
            for (int i = 0; i < connections; i++)
            {
                int seg = i;
                long start = connections > 1 ? seg * segSize : 0;
                long end = connections > 1 ? Math.Min(total, start + segSize) - 1 : total - 1; // -1 = unknown length
                tasks.Add(DownloadSegmentAsync(item, part, seg, start, end, ranges, ct));
            }
            await Task.WhenAll(tasks);

            if (total > 0 && new FileInfo(part).Length < total)
                throw new IOException("Download ended before the whole file was received.");

            if (File.Exists(item.FilePath)) File.Delete(item.FilePath);
            File.Move(part, item.FilePath);
            long finalSize = new FileInfo(item.FilePath).Length;
            Ui(() => { item.TotalBytes = finalSize; item.DownloadedBytes = finalSize; });
        }

        private async Task DownloadSegmentAsync(DownloadItem item, string partPath, int seg, long start, long end, bool ranges, CancellationToken ct)
        {
            long done = item.SegmentProgress[seg];
            long segLen = end >= start ? end - start + 1 : -1;
            if (segLen > 0 && done >= segLen) return;

            using var req = NewRequest(item);
            if (ranges) req.Headers.Range = new RangeHeaderValue(start + done, end >= start ? end : null);
            using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            resp.EnsureSuccessStatusCode();
            if (ranges && resp.StatusCode != HttpStatusCode.PartialContent)
                throw new IOException("Server stopped honouring range requests; restart the download.");

            await using var src = await resp.Content.ReadAsStreamAsync(ct);
            await using var dst = new FileStream(partPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite, 1024 * 1024, FileOptions.Asynchronous);
            dst.Seek(start + done, SeekOrigin.Begin);

            var buf = new byte[256 * 1024];
            int n;
            while ((n = await src.ReadAsync(buf, ct)) > 0)
            {
                if (segLen > 0 && done + n > segLen) n = (int)(segLen - done);
                await ThrottleAsync(n, ct);
                await dst.WriteAsync(buf.AsMemory(0, n), ct);
                done += n;
                item.SegmentProgress[seg] = done;
                _tickBytes.AddOrUpdate(item.Id, n, (_, v) => v + n);
                if (segLen > 0 && done >= segLen) break;
            }
        }

        private async Task ThrottleAsync(int bytes, CancellationToken ct)
        {
            int limit = Settings.SpeedLimitKBps * 1024;
            if (limit <= 0) return;
            while (true)
            {
                long wait;
                lock (_gate)
                {
                    var now = DateTime.UtcNow;
                    _bucketTokens = Math.Min(limit, _bucketTokens + (long)((now - _bucketStamp).TotalSeconds * limit));
                    _bucketStamp = now;
                    if (_bucketTokens >= bytes || _bucketTokens >= limit) { _bucketTokens -= bytes; return; }
                    wait = (long)((bytes - _bucketTokens) * 1000.0 / limit);
                }
                await Task.Delay((int)Math.Clamp(wait, 5, 500), ct);
            }
        }

        // ── Torrent ───────────────────────────────────────────────────────────

        private ClientEngine GetEngine()
        {
            var s = Settings;
            string key = $"{s.TorrentPort}|{s.TorrentDht}|{s.TorrentPortForwarding}|{s.TorrentMaxConnections}|{s.TorrentMaxDownloadKBps}|{s.TorrentMaxUploadKBps}";
            lock (_gate)
            {
                if (_engine != null && key == _engineKey) return _engine;
                if (_engine != null && _torrents.Count > 0) return _engine; // keep the live engine while torrents run

                var cache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameOS", "TorrentCache");
                Directory.CreateDirectory(cache);
                var b = new EngineSettingsBuilder
                {
                    CacheDirectory = cache,
                    AllowPortForwarding = s.TorrentPortForwarding,
                    MaximumConnections = Math.Max(10, s.TorrentMaxConnections),
                    MaximumDownloadRate = Math.Max(0, s.TorrentMaxDownloadKBps) * 1024,
                    MaximumUploadRate = Math.Max(0, s.TorrentMaxUploadKBps) * 1024,
                    DhtEndPoint = s.TorrentDht ? new System.Net.IPEndPoint(IPAddress.Any, s.TorrentPort) : null,
                };
                b.ListenEndPoints = new Dictionary<string, System.Net.IPEndPoint> { ["ipv4"] = new(IPAddress.Any, s.TorrentPort) };
                _engine = new ClientEngine(b.ToSettings());
                _engineKey = key;
                return _engine;
            }
        }

        private async Task RunTorrentAsync(DownloadItem item, CancellationToken ct)
        {
            if (!Settings.EnableTorrents) throw new InvalidOperationException("Torrents are disabled in Settings → Downloads.");
            Directory.CreateDirectory(item.Folder);
            var engine = GetEngine();

            TorrentManager manager;
            if (IsMagnet(item.Url))
            {
                manager = await engine.AddAsync(MagnetLink.Parse(item.Url), item.Folder);
            }
            else
            {
                string tmp = Path.Combine(Path.GetTempPath(), $"gameos-{item.Id}.torrent");
                using (var resp = await Http.SendAsync(NewRequest(item), ct))
                {
                    resp.EnsureSuccessStatusCode();
                    await File.WriteAllBytesAsync(tmp, await resp.Content.ReadAsByteArrayAsync(ct), ct);
                }
                var torrent = await Torrent.LoadAsync(tmp);
                manager = await engine.AddAsync(torrent, item.Folder);
            }

            lock (_gate) _torrents[item.Id] = manager;

            await manager.StartAsync();
            if (!manager.HasMetadata)
                await manager.WaitForMetadataAsync(ct);

            string name = manager.Torrent!.Name;
            Ui(() =>
            {
                item.Name = name;
                item.TotalBytes = manager.Torrent.Size;
                item.InfoHash = manager.InfoHashes.V1OrV2.ToHex();
                item.FilePath = Path.Combine(item.Folder, name);
            });

            while (!ct.IsCancellationRequested)
            {
                long done = (long)(manager.Torrent.Size * manager.Progress / 100.0);
                long speed = manager.Monitor.DownloadRate;
                Ui(() => { item.DownloadedBytes = done; item.SpeedBytesPerSec = speed; });
                if (manager.Complete || manager.State == TorrentState.Seeding) break;
                if (manager.State == TorrentState.Error)
                    throw new IOException(manager.Error?.Exception?.Message ?? "Torrent error");
                await Task.Delay(500, ct);
            }
            ct.ThrowIfCancellationRequested();
            Ui(() => item.DownloadedBytes = item.TotalBytes);

            var s = Settings;
            if (s.TorrentSeedAfterComplete)
            {
                // Extraction happens while the torrent keeps seeding; stop once the ratio limit is reached.
                _ = Task.Run(async () =>
                {
                    try
                    {
                        while (!ct.IsCancellationRequested)
                        {
                            await Task.Delay(2000, ct);
                            lock (_gate) { if (!_torrents.ContainsKey(item.Id)) return; }
                            double limit = Settings.TorrentSeedRatioLimit;
                            if (limit > 0 && manager.Torrent != null &&
                                manager.Monitor.DataBytesSent >= limit * Math.Max(1, manager.Torrent.Size)) break;
                        }
                    }
                    catch (OperationCanceledException) { return; }
                    try { await manager.StopAsync(); await engine.RemoveAsync(manager); } catch { }
                    lock (_gate) _torrents.Remove(item.Id);
                });
            }
            else
            {
                await manager.StopAsync();
                await engine.RemoveAsync(manager);
                lock (_gate) _torrents.Remove(item.Id);
            }
        }

        // ── Housekeeping ──────────────────────────────────────────────────────

        private void Tick()
        {
            try
            {
                var snapshot = Snapshot();
                foreach (var it in snapshot)
                {
                    if (it.Kind == DownloadKind.Direct && it.State == DownloadState.Downloading)
                    {
                        long bytes = _tickBytes.TryRemove(it.Id, out var b) ? b : 0;
                        long done = it.SegmentProgress.Sum();
                        Ui(() => { it.SpeedBytesPerSec = bytes; it.DownloadedBytes = done; });
                    }
                }
                Save();
            }
            catch { /* timer must never throw */ }
        }

        private int _savePending;

        public void Save()
        {
            if (Interlocked.Exchange(ref _savePending, 1) == 1) return;
            _ = Task.Run(() =>
            {
                try
                {
                    Thread.Sleep(200);
                    Interlocked.Exchange(ref _savePending, 0);
                    List<DownloadItem> copy;
                    copy = Snapshot();
                    Directory.CreateDirectory(Path.GetDirectoryName(ListPath)!);
                    string tmp = ListPath + ".tmp";
                    File.WriteAllText(tmp, JsonSerializer.Serialize(copy, JsonOpts));
                    File.Move(tmp, ListPath, true);
                }
                catch (Exception ex) { Interlocked.Exchange(ref _savePending, 0); DevLogService.Log($"[Downloads] save failed: {ex.Message}"); }
            });
        }

        private List<DownloadItem> Snapshot()
        {
            if (Dispatcher.UIThread.CheckAccess()) return Items.ToList();
            return Dispatcher.UIThread.InvokeAsync(() => Items.ToList()).GetAwaiter().GetResult();
        }

        private static void Notify(string title, string body) => NotificationService.ShowDownloadNotification(title, body);

        private static void Ui(Action a)
        {
            if (Dispatcher.UIThread.CheckAccess()) a();
            else Dispatcher.UIThread.Post(a);
        }
    }
}
