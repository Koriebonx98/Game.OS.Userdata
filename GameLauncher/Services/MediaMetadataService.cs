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

    /// <summary>One possible match for a title, shown in the "pick the correct one" list.</summary>
    public sealed class MediaCandidate
    {
        public MediaMetadata Meta { get; set; } = new();
        public string PosterUrl { get; set; } = "";
        /// <summary>Provider id used to fetch the full record when the pick is confirmed.</summary>
        public string Id { get; set; } = "";
        public string Label => Meta.Title + (Meta.Year > 0 ? $" ({Meta.Year})" : "") + (Meta.Source.Length > 0 ? $"  ·  {Meta.Source}" : "");
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
                MediaMetadata? meta = null;
                Exception? error = null;
                foreach (var source in SourcesFor(kind))
                {
                    try
                    {
                        var found = await FetchFromAsync(source, kind, q, year, artist, keyBase);
                        if (found.Found) { meta = found; break; }
                    }
                    catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IOException)
                    {
                        error = ex;
                        DevLogService.Log($"[MediaMetadata] {source} lookup '{q}' failed: {ex.Message}");
                    }
                }
                // Every source failed (offline / down): do not cache a "not found", so the lookup is retried later.
                if (meta == null && error != null) throw error;
                meta ??= new MediaMetadata();
                meta.FetchedUtc = DateTime.UtcNow;
                Save(jsonFile, meta);
                return meta.Found ? meta : null;
            }
            catch (Exception ex)
            {
                // Offline, service down or an unexpected reply: keep whatever we had and try again next time.
                DevLogService.Log($"[MediaMetadata] Lookup '{q}' failed: {ex.Message}");
                return cached is { Found: true } ? cached : null;
            }
        }

        /// <summary>Several possible matches for a title, so the user can pick the right one (like Kodi's scraper dialog).</summary>
        public static async Task<List<MediaCandidate>> SearchAsync(string kind, string query)
        {
            var list = new List<MediaCandidate>();
            string q = CleanQuery(query, out int year);
            if (q.Length == 0 || kind == "music") return list;
            foreach (var source in SourcesFor(kind))
            {
                try
                {
                    var found = source switch
                    {
                        "TMDB" => await SearchTmdbAsync(kind, q, year),
                        "TVmaze" => await SearchTvmazeAsync(q),
                        "Cinemeta" => await SearchCinemetaAsync(kind, q),
                        "iTunes" => await SearchItunesAsync(q),
                        _ => new List<MediaCandidate>(),
                    };
                    foreach (var c in found)
                        if (!list.Any(x => x.Meta.Title.Equals(c.Meta.Title, StringComparison.OrdinalIgnoreCase) && x.Meta.Year == c.Meta.Year))
                            list.Add(c);
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IOException)
                {
                    DevLogService.Log($"[MediaMetadata] {source} search '{q}' failed: {ex.Message}");
                }
                if (list.Count >= 12) break;
            }
            return list.Take(12).ToList();
        }

        /// <summary>Stores the chosen match as the info for <paramref name="title"/>, so later lookups return it from the cache.</summary>
        public static async Task<MediaMetadata> ConfirmAsync(string kind, string title, MediaCandidate pick)
        {
            string q = CleanQuery(title, out int year);
            string keyBase = KeyFor(kind, q, year);
            var meta = pick.Meta;
            if (pick.Meta.Source == "Cinemeta" && pick.Id.Length > 0)
            {
                try
                {
                    string type = kind == "tv" ? "series" : "movie";
                    using var full = JsonDocument.Parse(await Http.GetStringAsync($"https://v3-cinemeta.strem.io/meta/{type}/{Uri.EscapeDataString(pick.Id)}.json"));
                    if (full.RootElement.TryGetProperty("meta", out var r) && r.ValueKind == JsonValueKind.Object)
                    {
                        if (Str(r, "description").Length > 0) meta.Overview = Str(r, "description");
                        var rt = Regex.Match(Str(r, "runtime"), @"\d+");
                        if (rt.Success) meta.RuntimeMinutes = int.Parse(rt.Value);
                    }
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException) { /* the search hit is enough */ }
            }
            meta.PosterFile = await DownloadPosterAsync(pick.PosterUrl, keyBase);
            meta.Found = true;
            meta.FetchedUtc = DateTime.UtcNow;
            Save(keyBase + ".json", meta);
            return meta;
        }

        private static async Task<List<MediaCandidate>> SearchCinemetaAsync(string kind, string query)
        {
            var list = new List<MediaCandidate>();
            string type = kind == "tv" ? "series" : "movie";
            using var doc = JsonDocument.Parse(await Http.GetStringAsync($"https://v3-cinemeta.strem.io/catalog/{type}/top/search={Uri.EscapeDataString(query)}.json"));
            if (!doc.RootElement.TryGetProperty("metas", out var metas) || metas.ValueKind != JsonValueKind.Array) return list;
            foreach (var r in metas.EnumerateArray().Take(10))
            {
                var m = new MediaMetadata { Source = "Cinemeta", Title = Str(r, "name"), Year = YearOf(r), Overview = Str(r, "description") };
                if (r.TryGetProperty("genres", out var g) && g.ValueKind == JsonValueKind.Array)
                    m.Genres = g.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList();
                if (double.TryParse(Str(r, "imdbRating"), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var score)) m.Score = Math.Round(score, 1);
                var rt = Regex.Match(Str(r, "runtime"), @"\d+");
                if (rt.Success) m.RuntimeMinutes = int.Parse(rt.Value);
                if (m.Title.Length == 0) continue;
                list.Add(new MediaCandidate { Meta = m, PosterUrl = Str(r, "poster"), Id = Str(r, "imdb_id").Length > 0 ? Str(r, "imdb_id") : Str(r, "id") });
            }
            return list;
        }

        private static async Task<List<MediaCandidate>> SearchTvmazeAsync(string query)
        {
            var list = new List<MediaCandidate>();
            using var doc = JsonDocument.Parse(await Http.GetStringAsync($"https://api.tvmaze.com/search/shows?q={Uri.EscapeDataString(query)}"));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return list;
            foreach (var hit in doc.RootElement.EnumerateArray().Take(10))
            {
                if (!hit.TryGetProperty("show", out var r)) continue;
                var m = new MediaMetadata { Source = "TVmaze", Title = Str(r, "name"), Overview = StripHtml(Str(r, "summary")) };
                if (DateTime.TryParse(Str(r, "premiered"), out var d)) m.Year = d.Year;
                if (r.TryGetProperty("genres", out var g) && g.ValueKind == JsonValueKind.Array)
                    m.Genres = g.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList();
                if (r.TryGetProperty("rating", out var rating) && rating.TryGetProperty("average", out var avg) && avg.ValueKind == JsonValueKind.Number) m.Score = avg.GetDouble();
                if (r.TryGetProperty("runtime", out var rt) && rt.ValueKind == JsonValueKind.Number) m.RuntimeMinutes = rt.GetInt32();
                string poster = r.TryGetProperty("image", out var img) && img.ValueKind == JsonValueKind.Object
                    ? (Str(img, "original").Length > 0 ? Str(img, "original") : Str(img, "medium")) : "";
                list.Add(new MediaCandidate { Meta = m, PosterUrl = poster });
            }
            return list;
        }

        private static async Task<List<MediaCandidate>> SearchTmdbAsync(string kind, string query, int year)
        {
            var list = new List<MediaCandidate>();
            bool tv = kind == "tv", bearer = TmdbApiKey.StartsWith("eyJ", StringComparison.Ordinal);
            string url = $"https://api.themoviedb.org/3/search/{(tv ? "tv" : "movie")}?query={Uri.EscapeDataString(query)}"
                         + (bearer ? "" : $"&api_key={Uri.EscapeDataString(TmdbApiKey)}");
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (bearer) req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", TmdbApiKey);
            using var resp = await Http.SendAsync(req);
            resp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array) return list;
            foreach (var r in results.EnumerateArray().Take(10))
            {
                var m = new MediaMetadata { Source = "TMDB", Title = Str(r, tv ? "name" : "title"), Overview = Str(r, "overview") };
                if (DateTime.TryParse(Str(r, tv ? "first_air_date" : "release_date"), out var d)) m.Year = d.Year;
                if (r.TryGetProperty("vote_average", out var va) && va.ValueKind == JsonValueKind.Number) m.Score = Math.Round(va.GetDouble(), 1);
                string poster = Str(r, "poster_path");
                list.Add(new MediaCandidate { Meta = m, PosterUrl = poster.Length > 0 ? "https://image.tmdb.org/t/p/w500" + poster : "" });
            }
            return list;
        }

        private static async Task<List<MediaCandidate>> SearchItunesAsync(string query)
        {
            var list = new List<MediaCandidate>();
            using var doc = JsonDocument.Parse(await Http.GetStringAsync($"https://itunes.apple.com/search?term={Uri.EscapeDataString(query)}&media=movie&entity=movie&limit=10"));
            if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array) return list;
            foreach (var r in results.EnumerateArray())
            {
                var m = new MediaMetadata
                {
                    Source = "iTunes", Title = Str(r, "trackName"),
                    Overview = Str(r, "longDescription").Length > 0 ? Str(r, "longDescription") : Str(r, "shortDescription"),
                    Certification = Str(r, "contentAdvisoryRating"),
                };
                if (DateTime.TryParse(Str(r, "releaseDate"), out var d)) m.Year = d.Year;
                if (Str(r, "primaryGenreName") is { Length: > 0 } genre) m.Genres.Add(genre);
                if (r.TryGetProperty("trackTimeMillis", out var ms) && ms.ValueKind == JsonValueKind.Number) m.RuntimeMinutes = (int)(ms.GetInt64() / 60000);
                string art = Str(r, "artworkUrl100");
                if (m.Title.Length > 0) list.Add(new MediaCandidate { Meta = m, PosterUrl = art.Length > 0 ? Regex.Replace(art, @"/\d+x\d+bb", "/600x600bb") : "" });
            }
            return list;
        }

        // ── Sources ──────────────────────────────────────────────────────────────
        /// <summary>Preferred source ("Auto" = built-in order) and optional API keys; set from Settings → Media.</summary>
        private static readonly Dictionary<string, string> Preferred = new() { ["movie"] = "Auto", ["tv"] = "Auto", ["music"] = "Auto" };
        private static string TmdbApiKey = "";
        private static string OmdbApiKey = "";

        public static void Configure(string? movieSource, string? tvSource, string? musicSource, string? tmdbKey, string? omdbKey)
        {
            Preferred["movie"] = string.IsNullOrWhiteSpace(movieSource) ? "Auto" : movieSource.Trim();
            Preferred["tv"] = string.IsNullOrWhiteSpace(tvSource) ? "Auto" : tvSource.Trim();
            Preferred["music"] = string.IsNullOrWhiteSpace(musicSource) ? "Auto" : musicSource.Trim();
            TmdbApiKey = tmdbKey?.Trim() ?? "";
            OmdbApiKey = omdbKey?.Trim() ?? "";
        }

        /// <summary>Sources to try, in order. Key-based sources are only used when a key is set; the chosen source goes first.</summary>
        private static IEnumerable<string> SourcesFor(string kind)
        {
            var order = kind switch
            {
                "tv" => new[] { "TMDB", "TVmaze", "Cinemeta", "OMDb" },
                "movie" => new[] { "TMDB", "Cinemeta", "OMDb", "iTunes" },
                _ => new[] { "iTunes", "Deezer", "MusicBrainz" },
            };
            var list = new List<string>(order);
            var preferred = list.FirstOrDefault(x => x.Equals(Preferred.GetValueOrDefault(kind, "Auto"), StringComparison.OrdinalIgnoreCase));
            if (preferred != null) { list.Remove(preferred); list.Insert(0, preferred); }
            return list.Where(x => (x != "TMDB" || TmdbApiKey.Length > 0) && (x != "OMDb" || OmdbApiKey.Length > 0));
        }

        private static Task<MediaMetadata> FetchFromAsync(string source, string kind, string q, int year, string? artist, string keyBase) =>
            source switch
            {
                "TMDB" => FetchTmdbAsync(kind, q, year, keyBase),
                "OMDb" => FetchOmdbAsync(kind, q, year, keyBase),
                "TVmaze" => FetchTvAsync(q, keyBase),
                "Cinemeta" => FetchCinemetaAsync(kind, q, year, keyBase),
                "Deezer" => FetchDeezerAsync($"{artist} {q}".Trim(), keyBase),
                "MusicBrainz" => FetchMusicBrainzAsync(q, artist, keyBase),
                _ => kind == "music" ? FetchItunesAsync($"{artist} {q}".Trim(), 0, "music", "song", keyBase)
                                      : FetchItunesAsync(q, year, "movie", "movie", keyBase),
            };

        private static async Task<MediaMetadata> FetchTmdbAsync(string kind, string query, int year, string keyBase)
        {
            var meta = new MediaMetadata { Source = "TMDB" };
            bool tv = kind == "tv";
            string key = TmdbApiKey;
            // A v4 read-access token (starts with "eyJ") goes in a header, a v3 key in the query string.
            bool bearer = key.StartsWith("eyJ", StringComparison.Ordinal);
            async Task<JsonDocument> Get(string path, string args)
            {
                string url = $"https://api.themoviedb.org/3/{path}?{args}" + (bearer ? "" : $"&api_key={Uri.EscapeDataString(key)}");
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                if (bearer) req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", key);
                using var resp = await Http.SendAsync(req);
                resp.EnsureSuccessStatusCode();
                return JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            }

            string yearArg = year > 0 ? (tv ? $"&first_air_date_year={year}" : $"&year={year}") : "";
            using var search = await Get(tv ? "search/tv" : "search/movie", $"query={Uri.EscapeDataString(query)}{yearArg}");
            if (!search.RootElement.TryGetProperty("results", out var results) || results.GetArrayLength() == 0) return meta;
            if (!results[0].TryGetProperty("id", out var idEl) || idEl.ValueKind != JsonValueKind.Number) return meta;

            using var detail = await Get($"{(tv ? "tv" : "movie")}/{idEl.GetInt32()}", tv ? "append_to_response=content_ratings" : "append_to_response=release_dates");
            var d = detail.RootElement;
            meta.Found = true;
            meta.Title = Str(d, tv ? "name" : "title");
            if (DateTime.TryParse(Str(d, tv ? "first_air_date" : "release_date"), out var date)) meta.Year = date.Year;
            meta.Overview = Str(d, "overview");
            if (d.TryGetProperty("vote_average", out var va) && va.ValueKind == JsonValueKind.Number) meta.Score = Math.Round(va.GetDouble(), 1);
            if (d.TryGetProperty("genres", out var g) && g.ValueKind == JsonValueKind.Array)
                meta.Genres = g.EnumerateArray().Select(x => Str(x, "name")).Where(x => x.Length > 0).ToList();
            if (tv)
            {
                if (d.TryGetProperty("episode_run_time", out var ert) && ert.ValueKind == JsonValueKind.Array && ert.GetArrayLength() > 0 && ert[0].ValueKind == JsonValueKind.Number)
                    meta.RuntimeMinutes = ert[0].GetInt32();
                if (d.TryGetProperty("content_ratings", out var cr) && cr.TryGetProperty("results", out var crr) && crr.ValueKind == JsonValueKind.Array)
                    foreach (var r in crr.EnumerateArray())
                        if (Str(r, "iso_3166_1") == "US") { meta.Certification = Str(r, "rating"); break; }
            }
            else
            {
                if (d.TryGetProperty("runtime", out var rt) && rt.ValueKind == JsonValueKind.Number) meta.RuntimeMinutes = rt.GetInt32();
                if (d.TryGetProperty("release_dates", out var rd) && rd.TryGetProperty("results", out var rdr) && rdr.ValueKind == JsonValueKind.Array)
                    foreach (var c in rdr.EnumerateArray())
                        if (Str(c, "iso_3166_1") == "US" && c.TryGetProperty("release_dates", out var rl) && rl.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var r in rl.EnumerateArray())
                                if (Str(r, "certification") is { Length: > 0 } cert) { meta.Certification = cert; break; }
                            break;
                        }
            }
            string poster = Str(d, "poster_path");
            if (poster.Length > 0) meta.PosterFile = await DownloadPosterAsync("https://image.tmdb.org/t/p/w500" + poster, keyBase);
            return meta;
        }

        private static async Task<MediaMetadata> FetchOmdbAsync(string kind, string query, int year, string keyBase)
        {
            var meta = new MediaMetadata { Source = "OMDb" };
            string url = $"https://www.omdbapi.com/?apikey={Uri.EscapeDataString(OmdbApiKey)}&t={Uri.EscapeDataString(query)}&type={(kind == "tv" ? "series" : "movie")}"
                         + (year > 0 ? $"&y={year}" : "");
            using var doc = JsonDocument.Parse(await Http.GetStringAsync(url));
            var r = doc.RootElement;
            if (!string.Equals(Str(r, "Response"), "True", StringComparison.OrdinalIgnoreCase)) return meta;
            meta.Found = true;
            meta.Title = Str(r, "Title");
            var ym = Regex.Match(Str(r, "Year"), @"\d{4}");
            if (ym.Success) meta.Year = int.Parse(ym.Value);
            string plot = Str(r, "Plot");
            meta.Overview = plot == "N/A" ? "" : plot;
            meta.Genres = Str(r, "Genre").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Where(x => x != "N/A").ToList();
            if (double.TryParse(Str(r, "imdbRating"), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var score)) meta.Score = score;
            string rated = Str(r, "Rated");
            if (rated.Length > 0 && rated != "N/A") meta.Certification = rated;
            var rm = Regex.Match(Str(r, "Runtime"), @"\d+");
            if (rm.Success) meta.RuntimeMinutes = int.Parse(rm.Value);
            string poster = Str(r, "Poster");
            if (poster.StartsWith("http", StringComparison.OrdinalIgnoreCase)) meta.PosterFile = await DownloadPosterAsync(poster, keyBase);
            return meta;
        }

        private static async Task<MediaMetadata> FetchDeezerAsync(string query, string keyBase)
        {
            var meta = new MediaMetadata { Source = "Deezer" };
            using var doc = JsonDocument.Parse(await Http.GetStringAsync($"https://api.deezer.com/search?q={Uri.EscapeDataString(query)}&limit=3"));
            if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array || data.GetArrayLength() == 0) return meta;
            var t = data[0];
            meta.Found = true;
            meta.Title = Str(t, "title");
            string artistName = t.TryGetProperty("artist", out var a) ? Str(a, "name") : "";
            string album = "", cover = "";
            if (t.TryGetProperty("album", out var al) && al.ValueKind == JsonValueKind.Object)
            {
                album = Str(al, "title");
                cover = Str(al, "cover_xl").Length > 0 ? Str(al, "cover_xl") : Str(al, "cover_big");
            }
            meta.Overview = $"{artistName} · {album}".Trim(' ', '·');
            if (t.TryGetProperty("duration", out var du) && du.ValueKind == JsonValueKind.Number) meta.RuntimeMinutes = du.GetInt32() / 60;
            if (cover.Length > 0) meta.PosterFile = await DownloadPosterAsync(cover, keyBase);
            return meta;
        }

        // MusicBrainz for the facts and the Cover Art Archive for the artwork (both free; the client already sends a User-Agent).
        private static async Task<MediaMetadata> FetchMusicBrainzAsync(string title, string? artist, string keyBase)
        {
            var meta = new MediaMetadata { Source = "MusicBrainz" };
            static string Lucene(string v) => v.Replace("\"", " ").Replace("\\", " ");
            string query = $"recording:\"{Lucene(title)}\"" + (string.IsNullOrWhiteSpace(artist) ? "" : $" AND artist:\"{Lucene(artist)}\"");
            using var doc = JsonDocument.Parse(await Http.GetStringAsync($"https://musicbrainz.org/ws/2/recording/?query={Uri.EscapeDataString(query)}&fmt=json&limit=3"));
            if (!doc.RootElement.TryGetProperty("recordings", out var recs) || recs.ValueKind != JsonValueKind.Array || recs.GetArrayLength() == 0) return meta;
            var rec = recs[0];
            meta.Found = true;
            meta.Title = Str(rec, "title");
            if (rec.TryGetProperty("length", out var len) && len.ValueKind == JsonValueKind.Number) meta.RuntimeMinutes = (int)(len.GetInt64() / 60000);
            if (DateTime.TryParse(Str(rec, "first-release-date"), out var d)) meta.Year = d.Year;
            string artistName = rec.TryGetProperty("artist-credit", out var ac) && ac.ValueKind == JsonValueKind.Array && ac.GetArrayLength() > 0 ? Str(ac[0], "name") : "";
            string album = "", releaseId = "";
            if (rec.TryGetProperty("releases", out var rels) && rels.ValueKind == JsonValueKind.Array && rels.GetArrayLength() > 0)
            {
                album = Str(rels[0], "title");
                releaseId = Str(rels[0], "id");
            }
            meta.Overview = $"{artistName} · {album}".Trim(' ', '·');
            if (rec.TryGetProperty("tags", out var tags) && tags.ValueKind == JsonValueKind.Array)
                meta.Genres = tags.EnumerateArray().Select(x => Str(x, "name")).Where(x => x.Length > 0).Take(3).ToList();
            if (releaseId.Length > 0)
                meta.PosterFile = await DownloadPosterAsync($"https://coverartarchive.org/release/{releaseId}/front-500", keyBase);
            return meta;
        }

        /// <summary>Keyless IMDb-backed lookup (Stremio Cinemeta) – covers movies as well as TV shows.</summary>
        private static async Task<MediaMetadata> FetchCinemetaAsync(string kind, string query, int year, string keyBase)
        {
            var meta = new MediaMetadata { Source = "Cinemeta" };
            string type = kind == "tv" ? "series" : "movie";
            using var search = JsonDocument.Parse(await Http.GetStringAsync(
                $"https://v3-cinemeta.strem.io/catalog/{type}/top/search={Uri.EscapeDataString(query)}.json"));
            if (!search.RootElement.TryGetProperty("metas", out var metas) || metas.ValueKind != JsonValueKind.Array || metas.GetArrayLength() == 0) return meta;

            JsonElement pick = metas[0];
            if (year > 0)
                foreach (var cand in metas.EnumerateArray())
                    if (YearOf(cand) == year) { pick = cand; break; }

            // The search hit is thin; the full record has the description and runtime.
            JsonElement r = pick;
            JsonDocument? full = null;
            string id = Str(pick, "imdb_id").Length > 0 ? Str(pick, "imdb_id") : Str(pick, "id");
            if (id.Length > 0)
            {
                try
                {
                    full = JsonDocument.Parse(await Http.GetStringAsync($"https://v3-cinemeta.strem.io/meta/{type}/{Uri.EscapeDataString(id)}.json"));
                    if (full.RootElement.TryGetProperty("meta", out var m) && m.ValueKind == JsonValueKind.Object) r = m;
                }
                catch (HttpRequestException) { /* fall back to the search hit */ }
            }
            using (full)
            {
                meta.Found = true;
                meta.Title = Str(r, "name");
                meta.Year = YearOf(r);
                meta.Overview = Str(r, "description");
                if (r.TryGetProperty("genres", out var g) && g.ValueKind == JsonValueKind.Array)
                    meta.Genres = g.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList();
                if (double.TryParse(Str(r, "imdbRating"), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var score))
                    meta.Score = Math.Round(score, 1);
                var rt = Regex.Match(Str(r, "runtime"), @"\d+");
                if (rt.Success) meta.RuntimeMinutes = int.Parse(rt.Value);
                string poster = Str(r, "poster");
                if (poster.StartsWith("http", StringComparison.OrdinalIgnoreCase)) meta.PosterFile = await DownloadPosterAsync(poster, keyBase);
            }
            return meta;
        }

        private static int YearOf(JsonElement e)
        {
            var m = Regex.Match(Str(e, "year") + " " + Str(e, "releaseInfo"), @"(?:19|20)\d{2}");
            return m.Success ? int.Parse(m.Value) : 0;
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
