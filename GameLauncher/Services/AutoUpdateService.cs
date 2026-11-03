using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// Checks every link marked "auto update" (see <see cref="GameLink.AutoUpdate"/>) at start-up and then every
    /// <see cref="Interval"/>. GitHub repositories use the latest release; other pages are scraped for the first magnet
    /// link (never an ad / redirect host). Pages that need real clicking through file hosts (SteamRip-style) are reported
    /// so the user can finish them in the built-in browser. The first check only records a baseline.
    /// </summary>
    public static class AutoUpdateService
    {
        public static readonly TimeSpan Interval = TimeSpan.FromHours(4);

        private sealed class State
        {
            public string Fingerprint { get; set; } = "";
            public DateTime CheckedUtc { get; set; }
        }

        public static event Action<GameLink, string>? UpdateFound;      // download queued
        public static event Action<GameLink, string>? UpdateAvailable;   // notify-only mode
        public static event Action<GameLink, string>? ManualUpdateNeeded; // needs the browser

        private static readonly HttpClient Http = CreateHttp();
        private static readonly Regex Magnet = new(@"magnet:\?xt=urn:[a-z0-9]+:[^""'\s<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex GitHubRepo = new(@"^https?://(www\.)?github\.com/([^/\s]+)/([^/\s#?]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex TitleTag = new(@"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
        private static readonly Regex VersionText = new(@"\bv?\d+(\.\d+){1,3}[a-z]?\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly string StateFile = Path.Combine(UserDataService.DataRoot, "GameLinks", "autoupdate-state.json");
        private static readonly object Gate = new();
        private static Dictionary<string, State>? _state;
        private static CancellationTokenSource? _cts;

        private static HttpClient CreateHttp()
        {
            var h = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
            h.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 GameOS-AutoUpdate");
            return h;
        }

        public static void Start()
        {
            lock (Gate)
            {
                if (_cts != null) return;
                _cts = new CancellationTokenSource();
            }
            var ct = _cts.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                    while (!ct.IsCancellationRequested)
                    {
                        await CheckAllAsync(ct).ConfigureAwait(false);
                        await Task.Delay(Interval, ct).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex) { DevLogService.Log($"[AutoUpdate] stopped: {ex.Message}"); }
            });
        }

        public static void Stop() { lock (Gate) { _cts?.Cancel(); _cts = null; } }

        public static async Task CheckAllAsync(CancellationToken ct = default)
        {
            var links = GameLinksService.AutoUpdateLinks();
            if (links.Count == 0) return;
            DevLogService.Log($"[AutoUpdate] Checking {links.Count} link(s)…");
            foreach (var link in links)
            {
                if (ct.IsCancellationRequested) break;
                try { await CheckAsync(link, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { DevLogService.Log($"[AutoUpdate] '{link.Name}' failed: {ex.Message}"); }
            }
        }

        private static async Task CheckAsync(GameLink link, CancellationToken ct)
        {
            string? fingerprint, downloadUrl;
            var gh = GitHubRepo.Match(link.Url);
            if (gh.Success) (fingerprint, downloadUrl) = await LatestGitHubReleaseAsync(gh.Groups[2].Value, gh.Groups[3].Value.Replace(".git", ""), ct).ConfigureAwait(false);
            else (fingerprint, downloadUrl) = await ScrapePageAsync(link.Url, ct).ConfigureAwait(false);
            if (string.IsNullOrEmpty(fingerprint)) return;

            string? previous;
            lock (Gate)
            {
                var st = LoadState();
                st.TryGetValue(link.Id, out var prev);
                previous = prev?.Fingerprint;
                st[link.Id] = new State { Fingerprint = fingerprint, CheckedUtc = DateTime.UtcNow };
                SaveState();
            }
            if (string.IsNullOrEmpty(previous) || previous == fingerprint) return;

            string label = $"{link.Game} – {link.Name}";
            if (!string.IsNullOrEmpty(downloadUrl) && !AppSettingsService.Load().Downloads.AutoUpdateDownload)
            {
                DevLogService.Log($"[AutoUpdate] New version for {label}; notifying (auto-download is off).");
                UpdateAvailable?.Invoke(link, downloadUrl);
            }
            else if (!string.IsNullOrEmpty(downloadUrl))
            {
                DownloadManagerService.Instance.Add(downloadUrl, "", DownloadPathResolver.CategoryGame, link.Platform, link.Url, "", link.Game);
                DevLogService.Log($"[AutoUpdate] New version for {label}, download queued.");
                UpdateFound?.Invoke(link, downloadUrl);
            }
            else
            {
                DevLogService.Log($"[AutoUpdate] New version for {label}; needs the browser to resolve the download.");
                ManualUpdateNeeded?.Invoke(link, link.Url);
            }
        }

        private static async Task<(string?, string?)> LatestGitHubReleaseAsync(string owner, string repo, CancellationToken ct)
        {
            using var resp = await Http.GetAsync($"https://api.github.com/repos/{owner}/{repo}/releases/latest", ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return (null, null);
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var root = doc.RootElement;
            string tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
            string? url = null;
            if (root.TryGetProperty("assets", out var assets))
                foreach (var a in assets.EnumerateArray())
                {
                    string name = a.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                    if (Regex.IsMatch(name, @"\.(zip|7z|rar|exe|msi|torrent)$", RegexOptions.IgnoreCase))
                    { url = a.GetProperty("browser_download_url").GetString(); break; }
                }
            url ??= root.TryGetProperty("zipball_url", out var z) ? z.GetString() : null;
            return (tag.Length == 0 ? null : tag, url);
        }

        private static async Task<(string?, string?)> ScrapePageAsync(string url, CancellationToken ct)
        {
            string html = await Http.GetStringAsync(url, ct).ConfigureAwait(false);
            string? magnet = Magnet.Matches(html).Select(m => System.Net.WebUtility.HtmlDecode(m.Value)).FirstOrDefault();
            string title = System.Net.WebUtility.HtmlDecode(TitleTag.Match(html).Groups[1].Value.Trim());
            string versions = string.Join(",", VersionText.Matches(title).Select(m => m.Value));
            // A magnet's info-hash changes with every new upload; otherwise fall back to title + version text.
            string basis = magnet != null ? MagnetHash(magnet) : title + "|" + versions;
            if (string.IsNullOrWhiteSpace(basis)) return (null, null);
            string fp = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(basis)));

            // Without a magnet the host needs click-through resolving, which is left to the browser.
            return (fp, magnet);
        }

        private static string MagnetHash(string magnet)
        {
            var m = Regex.Match(magnet, @"xt=urn:[a-z0-9]+:([a-z0-9]+)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.ToLowerInvariant() : magnet;
        }

        private static Dictionary<string, State> LoadState()
        {
            if (_state != null) return _state;
            try { _state = File.Exists(StateFile) ? JsonSerializer.Deserialize<Dictionary<string, State>>(File.ReadAllText(StateFile)) : null; }
            catch { }
            return _state ??= new();
        }

        private static void SaveState()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(StateFile)!);
                File.WriteAllText(StateFile, JsonSerializer.Serialize(_state));
            }
            catch { }
        }
    }
}
