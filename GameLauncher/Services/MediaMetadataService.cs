using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>Online info for a movie, TV show or song, cached on disk for offline use.</summary>
    public sealed class MediaMetadata
    {
        public string Title { get; set; } = "";
        public int Year { get; set; }
        public string Overview { get; set; } = "";
        public List<string> Genres { get; set; } = new();
        /// <summary>Community score out of 10 (0 = unknown).</summary>
        public double Score { get; set; }
        public string Certification { get; set; } = "";
        public int RuntimeMinutes { get; set; }
        public string Source { get; set; } = "";
        public string PosterFile { get; set; } = "";
        /// <summary>When the lookup ran; a lookup that found nothing is retried after <see cref="MediaMetadataService.RetryAfter"/>.</summary>
        public DateTime FetchedUtc { get; set; }
        public bool Found { get; set; }
    }

    /// <summary>
    /// Looks up movie / TV / music info online (TVmaze for TV shows, the iTunes Search API for movies and songs –
    /// neither needs an API key) and caches the JSON plus poster under <c>Data\MediaCache\</c>, shared by all users.
    /// Cached entries are always served without touching the network, so the library works offline.
    /// </summary>
    public static class MediaMetadataService
    {
        public static readonly TimeSpan RetryAfter = TimeSpan.FromDays(7);

        private static readonly HttpClient Http = CreateClient();
        private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
        private static string CacheRoot => Path.Combine(UserDataService.DataRoot, "MediaCache");

        private static HttpClient CreateClient()
        {
            var c = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            c.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher/1.0");
            return c;
        }

        /// <summary>"The.Matrix.1999.1080p.BluRay.x264" → "The Matrix".</summary>
        public static string CleanQuery(string title, out int year)
        {
            year = 0;
            // An explicit "(Year)" / "[Year]" wins, so "Blade Runner 2049 (2017)" resolves to 2017.
            var m = Regex.Match(title, @"[\(\[]\s*((?:19|20)\d{2})\s*[\)\]]");
            if (!m.Success) m = Regex.Match(title, @"[\(\[\. _-]((?:19|20)\d{2})(?!\d)");
            if (m.Success) { year = int.Parse(m.Groups[1].Value); title = title[..m.Index]; }
            title = Regex.Replace(title, @"\b(2160p|1080p|720p|480p|4k|uhd|hdr|bluray|brrip|bdrip|web-?dl|webrip|dvdrip|x26[45]|h\.?26[45]|hevc|aac|ac3|dts|remux|extended|unrated|proper)\b.*$",
                "", RegexOptions.IgnoreCase);
            title = Regex.Replace(title, @"\bS\d{1,2}\s*E\d{1,3}\b.*$", "", RegexOptions.IgnoreCase);
            title = Regex.Replace(title, @"[\._]+", " ");
            return Regex.Replace(title, @"\s+", " ").Trim(' ', '-', '(', '[');
        }

        private static string KeyFor(string kind, string query, int year)
        {
            using var sha = SHA1.Create();
            var hash = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes($"{kind}|{query.ToLowerInvariant()}|{year}")))[..16];
            return Path.Combine(CacheRoot, kind, hash);
        }

        /// <summary>Cached info only – never touches the network. Null when nothing usable is cached.</summary>
        public static MediaMetadata? GetCached(string kind, string title)
        {
            string q = CleanQuery(title, out int year);
            if (q.Length == 0) return null;
            var meta = Load(KeyFor(kind, q, year) + ".json");
            return meta is { Found: true } ? meta : null;
        }

        /// <summary>Returns cached info, otherwise looks it up online (kind = "movie" | "tv" | "music").</summary>
        public static async Task<MediaMetadata?> GetAsync(string kind, string title, string? artist = null, bool force = false)
        {
            string q = CleanQuery(title, out int year);
            if (q.Length == 0) return null;
            string keyBase = KeyFor(kind, kind == "music" ? $"{artist} {q}" : q, year);
            string jsonFile = keyBase + ".json";

            var cached = Load(jsonFile);
            if (!force && cached != null && (cached.Found || DateTime.UtcNow - cached.FetchedUtc < RetryAfter))
                return cached.Found ? cached : null;

            try
            {
                var meta = kind switch
                {
                    "tv" => await FetchTvAsync(q, keyBase),
                    "movie" => await FetchItunesAsync(q, year, "movie", "movie", keyBase),
                    _ => await FetchItunesAsync($"{artist} {q}".Trim(), 0, "music", "song", keyBase),
                };
                meta.FetchedUtc = DateTime.UtcNow;
                Save(jsonFile, meta);
                return meta.Found ? meta : null;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IOException)
            {
                // Offline or service down: keep whatever we had and try again next time.
                DevLogService.Log($"[MediaMetadata] Lookup '{q}' failed: {ex.Message}");
                return cached is { Found: true } ? cached : null;
            }
        }

        private static async Task<MediaMetadata> FetchTvAsync(string query, string keyBase)
        {
            var meta = new MediaMetadata { Source = "TVmaze" };
            using var resp = await Http.GetAsync($"https://api.tvmaze.com/singlesearch/shows?q={Uri.EscapeDataString(query)}");
            if (resp.StatusCode == HttpStatusCode.NotFound) return meta;
            resp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var r = doc.RootElement;
            meta.Found = true;
            meta.Title = Str(r, "name");
            if (DateTime.TryParse(Str(r, "premiered"), out var d)) meta.Year = d.Year;
            meta.Overview = StripHtml(Str(r, "summary"));
            if (r.TryGetProperty("genres", out var g) && g.ValueKind == JsonValueKind.Array)
                meta.Genres = g.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList();
            if (r.TryGetProperty("rating", out var rating) && rating.TryGetProperty("average", out var avg) && avg.ValueKind == JsonValueKind.Number)
                meta.Score = avg.GetDouble();
            if (r.TryGetProperty("runtime", out var rt) && rt.ValueKind == JsonValueKind.Number) meta.RuntimeMinutes = rt.GetInt32();
            if (r.TryGetProperty("image", out var img) && img.ValueKind == JsonValueKind.Object)
                meta.PosterFile = await DownloadPosterAsync(Str(img, "original").Length > 0 ? Str(img, "original") : Str(img, "medium"), keyBase);
            return meta;
        }

        private static async Task<MediaMetadata> FetchItunesAsync(string query, int year, string media, string entity, string keyBase)
        {
            var meta = new MediaMetadata { Source = "iTunes" };
            string url = $"https://itunes.apple.com/search?term={Uri.EscapeDataString(query)}&media={media}&entity={entity}&limit={(year > 0 ? 15 : 5)}";
            using var doc = JsonDocument.Parse(await Http.GetStringAsync(url));
            if (!doc.RootElement.TryGetProperty("results", out var results) || results.GetArrayLength() == 0) return meta;

            // Prefer the result released in the year found in the file name.
            JsonElement pick = results[0];
            if (year > 0)
                foreach (var cand in results.EnumerateArray())
                    if (DateTime.TryParse(Str(cand, "releaseDate"), out var rd) && rd.Year == year) { pick = cand; break; }

            meta.Found = true;
            meta.Title = media == "music" ? Str(pick, "trackName") : Str(pick, "trackName");
            if (DateTime.TryParse(Str(pick, "releaseDate"), out var d)) meta.Year = d.Year;
            meta.Overview = Str(pick, "longDescription").Length > 0 ? Str(pick, "longDescription") : Str(pick, "shortDescription");
            if (media == "music") meta.Overview = $"{Str(pick, "artistName")} · {Str(pick, "collectionName")}".Trim(' ', '·');
            if (Str(pick, "primaryGenreName") is { Length: > 0 } genre) meta.Genres.Add(genre);
            meta.Certification = Str(pick, "contentAdvisoryRating");
            if (pick.TryGetProperty("trackTimeMillis", out var ms) && ms.ValueKind == JsonValueKind.Number) meta.RuntimeMinutes = (int)(ms.GetInt64() / 60000);
            string art = Str(pick, "artworkUrl100");
            if (art.Length > 0) meta.PosterFile = await DownloadPosterAsync(Regex.Replace(art, @"/\d+x\d+bb", "/600x600bb"), keyBase);
            return meta;
        }

        private static async Task<string> DownloadPosterAsync(string url, string keyBase)
        {
            if (string.IsNullOrWhiteSpace(url)) return "";
            try
            {
                var bytes = await Http.GetByteArrayAsync(url.Replace("http://", "https://"));
                string file = keyBase + (url.Contains(".png", StringComparison.OrdinalIgnoreCase) ? ".png" : ".jpg");
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                await File.WriteAllBytesAsync(file, bytes);
                return file;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
            {
                return "";
            }
        }

        private static string Str(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

        private static string StripHtml(string html) =>
            WebUtility.HtmlDecode(Regex.Replace(html, "<.*?>", " ")).Replace("  ", " ").Trim();

        private static MediaMetadata? Load(string file)
        {
            try
            {
                var meta = File.Exists(file) ? JsonSerializer.Deserialize<MediaMetadata>(File.ReadAllText(file), Json) : null;
                if (meta != null && meta.PosterFile.Length > 0 && !File.Exists(meta.PosterFile)) meta.PosterFile = "";
                return meta;
            }
            catch { return null; }
        }

        private static void Save(string file, MediaMetadata meta)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                File.WriteAllText(file, JsonSerializer.Serialize(meta, Json));
            }
            catch (Exception ex) { DevLogService.Log($"[MediaMetadata] Save failed: {ex.Message}"); }
        }
    }
}
