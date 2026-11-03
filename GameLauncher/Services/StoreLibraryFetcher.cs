using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace GameLauncher.Services
{
    /// <summary>
    /// Reads a user's owned library from a store using the credentials saved for the signed-in account and feeds it
    /// to <see cref="StoreLibraryService"/>. Supported: itch.io (API key), GOG (session cookie), Xbox (OpenXBL key) and
    /// Epic (bearer token). EA, Ubisoft and Battle.net have no usable public library API, so they only keep credentials.
    /// </summary>
    public static class StoreLibraryFetcher
    {
        private static readonly HttpClient Http = CreateHttp();

        private static HttpClient CreateHttp()
        {
            var h = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            h.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 GameOS");
            return h;
        }

        public static bool IsSupported(string store) => store is "itch.io" or "GOG" or "Xbox" or "Epic Games";

        /// <summary>Fetches every supported store that has credentials and queues the games. Returns one status line per store.</summary>
        public static async Task<List<string>> SyncAllAsync(CancellationToken ct = default)
        {
            var lines = new List<string>();
            foreach (var acct in StoreAccountsService.All().Where(a => IsSupported(a.Store)))
            {
                try
                {
                    var games = await FetchAsync(acct, ct).ConfigureAwait(false);
                    OwnedStoreGamesService.ReplaceStore(StoreAccountsService.CurrentUser, acct.Store,
                        games.Select(g => new OwnedStoreGame { Store = acct.Store, Id = g.Id, Title = g.Title, LaunchId = g.LaunchId, Url = g.Url }));
                    var r = StoreLibraryService.Submit(acct.Store, games);
                    lines.Add($"{acct.Store}: {games.Count} games – {r.NewGames} new, {r.StoreMerges} store links added, {r.AlreadyComplete} already complete, {r.Duplicates} already queued");
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    DevLogService.Log($"[StoreLibrary] {acct.Store} failed: {ex.Message}");
                    lines.Add($"{acct.Store}: failed – {ex.Message}");
                }
            }
            if (lines.Count == 0) lines.Add("No store with a supported login is configured.");
            return lines;
        }

        public static Task<List<StoreLibraryService.StoreGame>> FetchAsync(StoreAccount a, CancellationToken ct) => a.Store switch
        {
            "itch.io" => FetchItchAsync(a, ct),
            "GOG" => FetchGogAsync(a, ct),
            "Xbox" => FetchXboxAsync(a, ct),
            "Epic Games" => FetchEpicAsync(a, ct),
            _ => throw new NotSupportedException($"{a.Store} has no library API"),
        };

        private static async Task<JsonDocument> GetJsonAsync(HttpRequestMessage req, CancellationToken ct)
        {
            using var resp = await Http.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"HTTP {(int)resp.StatusCode} from {req.RequestUri?.Host}");
            return JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        }

        private static string Str(JsonElement e, string name) =>
            e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

        private static async Task<List<StoreLibraryService.StoreGame>> FetchItchAsync(StoreAccount a, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(a.ApiKey)) throw new InvalidOperationException("itch.io API key missing");
            var games = new List<StoreLibraryService.StoreGame>();
            for (int page = 1; page <= 50; page++)
            {
                using var doc = await GetJsonAsync(new HttpRequestMessage(HttpMethod.Get,
                    $"https://itch.io/api/1/{Uri.EscapeDataString(a.ApiKey)}/my-owned-keys?page={page}"), ct).ConfigureAwait(false);
                if (!doc.RootElement.TryGetProperty("owned_keys", out var keys) || keys.GetArrayLength() == 0) break;
                foreach (var k in keys.EnumerateArray())
                {
                    if (!k.TryGetProperty("game", out var g)) continue;
                    games.Add(new(g.TryGetProperty("id", out var id) ? id.ToString() : "", Str(g, "title"), Str(g, "url")));
                }
            }
            return games;
        }

        private static async Task<List<StoreLibraryService.StoreGame>> FetchGogAsync(StoreAccount a, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(a.Token)) throw new InvalidOperationException("GOG session cookie missing (use 'Capture login' in the browser)");
            var req = new HttpRequestMessage(HttpMethod.Get, "https://embed.gog.com/user/data/games");
            req.Headers.TryAddWithoutValidation("Cookie", a.Token);
            using var owned = await GetJsonAsync(req, ct).ConfigureAwait(false);
            var ids = owned.RootElement.TryGetProperty("owned", out var o) ? o.EnumerateArray().Select(x => x.ToString()).ToList() : new();

            var games = new List<StoreLibraryService.StoreGame>();
            using var gate = new SemaphoreSlim(4);
            var tasks = ids.Take(1000).Select(async id =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    using var p = await GetJsonAsync(new HttpRequestMessage(HttpMethod.Get, $"https://api.gog.com/products/{id}"), ct).ConfigureAwait(false);
                    string title = Str(p.RootElement, "title");
                    string url = p.RootElement.TryGetProperty("links", out var l) ? Str(l, "product_card") : "";
                    if (title.Length > 0) lock (games) games.Add(new(id, title, url));
                }
                catch (OperationCanceledException) { throw; }
                catch { /* delisted products return 404 */ }
                finally { gate.Release(); }
            });
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return games;
        }

        private static async Task<List<StoreLibraryService.StoreGame>> FetchXboxAsync(StoreAccount a, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(a.ApiKey)) throw new InvalidOperationException("OpenXBL API key missing");
            var req = new HttpRequestMessage(HttpMethod.Get, "https://xbl.io/api/v2/player/titleHistory");
            req.Headers.TryAddWithoutValidation("X-Authorization", a.ApiKey);
            using var doc = await GetJsonAsync(req, ct).ConfigureAwait(false);
            var games = new List<StoreLibraryService.StoreGame>();
            if (doc.RootElement.TryGetProperty("titles", out var titles))
                foreach (var t in titles.EnumerateArray())
                {
                    string name = Str(t, "name");
                    string type = Str(t, "type");
                    if (name.Length > 0 && (type.Length == 0 || type.Equals("Game", StringComparison.OrdinalIgnoreCase)))
                        games.Add(new(Str(t, "titleId"), name));
                }
            return games;
        }

        /// <summary>
        /// Epic's library API needs an OAuth bearer token, not website cookies. Accepts a 32-char authorization code
        /// (from https://www.epicgames.com/id/api/redirect?clientId=34a02cf8f4414e29b15921876da36f9a&amp;responseType=code)
        /// which is exchanged for an access token, or an existing bearer/JWT token which is used as-is.
        /// </summary>
        private static async Task<string> GetEpicBearerAsync(string token, CancellationToken ct)
        {
            token = token.Trim('"', '{', '}');
            if (token.Contains("authorizationCode", StringComparison.OrdinalIgnoreCase))
            {
                try { using var d = JsonDocument.Parse(token.StartsWith("{") ? token : "{" + token + "}"); token = Str(d.RootElement, "authorizationCode"); } catch { }
            }
            if (token.Contains('=') || token.Contains(';'))
                throw new InvalidOperationException("Epic needs an authorization code, not browser cookies. Sign in to Epic, open https://www.epicgames.com/id/api/redirect?clientId=34a02cf8f4414e29b15921876da36f9a&responseType=code and paste the authorizationCode into the token field");
            if (token.Length != 32 || !token.All(Uri.IsHexDigit)) return token;

            var req = new HttpRequestMessage(HttpMethod.Post, "https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code", ["code"] = token, ["token_type"] = "eg1",
                }),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("34a02cf8f4414e29b15921876da36f9a:daafbccc737745039dffe53d94fc76cf")));
            using var resp = await Http.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"Epic code rejected (HTTP {(int)resp.StatusCode}) – codes are single-use and expire in minutes; get a fresh one");
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            return Str(doc.RootElement, "access_token");
        }

        private static async Task<List<StoreLibraryService.StoreGame>> FetchEpicAsync(StoreAccount a, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(a.Token)) throw new InvalidOperationException("Epic authorization code missing");
            string bearer = await GetEpicBearerAsync(a.Token.Trim(), ct).ConfigureAwait(false);
            a = new StoreAccount { Store = a.Store, ApiKey = a.ApiKey, UserId = a.UserId, Token = bearer };
            var items = new List<(string CatalogId, string Ns)>();
            var appNames = new Dictionary<string, string>();
            string cursor = "";
            for (int page = 0; page < 40; page++)
            {
                string url = "https://library-service.live.use1a.on.epicgames.com/library/api/public/items?includeMetadata=true&platform=Windows"
                             + (cursor.Length > 0 ? "&cursor=" + Uri.EscapeDataString(cursor) : "");
                var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", a.Token);
                using var doc = await GetJsonAsync(req, ct).ConfigureAwait(false);
                if (doc.RootElement.TryGetProperty("records", out var recs))
                    foreach (var r in recs.EnumerateArray())
                    {
                        string ns = Str(r, "namespace");
                        if (ns == "ue") continue; // Unreal Engine marketplace assets, not games
                        string cid = Str(r, "catalogItemId");
                        items.Add((cid, ns));
                        if (cid.Length > 0 && Str(r, "appName").Length > 0) appNames[cid] = Str(r, "appName");
                    }
                cursor = doc.RootElement.TryGetProperty("responseMetadata", out var m) ? Str(m, "nextCursor") : "";
                if (cursor.Length == 0) break;
            }

            var games = new List<StoreLibraryService.StoreGame>();
            foreach (var chunk in items.Where(i => i.CatalogId.Length > 0).Chunk(50))
            {
                var req = new HttpRequestMessage(HttpMethod.Get,
                    "https://catalog-public-service-prod06.ol.epicgames.com/catalog/api/shared/bulk/items?country=US&locale=en-US&" +
                    string.Join("&", chunk.Select(c => "id=" + Uri.EscapeDataString(c.CatalogId))));
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", a.Token);
                using var doc = await GetJsonAsync(req, ct).ConfigureAwait(false);
                foreach (var p in doc.RootElement.EnumerateObject())
                {
                    string title = Str(p.Value, "title");
                    var cats = p.Value.TryGetProperty("categories", out var c) ? c.EnumerateArray().Select(x => Str(x, "path")).ToList() : new();
                    if (title.Length > 0 && cats.Any(x => x is "games" or "applications")) games.Add(new(p.Name, title, null, null, appNames.GetValueOrDefault(p.Name)));
                }
            }
            return games;
        }
    }
}
