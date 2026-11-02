using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace GameLauncher.Services;

/// <summary>Merged metadata for one game. Empty fields are filled by later providers.</summary>
public sealed class GameMetadata
{
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string CoverUrl { get; set; } = "";
    public string BackgroundUrl { get; set; } = "";
    public string LogoUrl { get; set; } = "";
    public string IconUrl { get; set; } = "";
    public string Developer { get; set; } = "";
    public string Publisher { get; set; } = "";
    public int ReleaseYear { get; set; }
    public double Rating { get; set; }
    public long SteamAppId { get; set; }
    public List<string> Genres { get; set; } = new();
    /// <summary>Providers that contributed, in order (e.g. "Steam, SteamGridDB").</summary>
    public string Sources { get; set; } = "";

    public bool IsEmpty => Description == "" && CoverUrl == "" && SteamAppId == 0;

    /// <summary>Copies only the fields that are still empty here; returns true if anything changed.</summary>
    public bool FillFrom(GameMetadata o, string source)
    {
        bool changed = false;
        string Pick(string mine, string theirs) { if (mine == "" && theirs != "") { changed = true; return theirs; } return mine; }
        Title = Pick(Title, o.Title);
        Description = Pick(Description, o.Description);
        CoverUrl = Pick(CoverUrl, o.CoverUrl);
        BackgroundUrl = Pick(BackgroundUrl, o.BackgroundUrl);
        LogoUrl = Pick(LogoUrl, o.LogoUrl);
        IconUrl = Pick(IconUrl, o.IconUrl);
        Developer = Pick(Developer, o.Developer);
        Publisher = Pick(Publisher, o.Publisher);
        if (ReleaseYear == 0 && o.ReleaseYear > 0) { ReleaseYear = o.ReleaseYear; changed = true; }
        if (Rating == 0 && o.Rating > 0) { Rating = o.Rating; changed = true; }
        if (SteamAppId == 0 && o.SteamAppId > 0) { SteamAppId = o.SteamAppId; changed = true; }
        if (Genres.Count == 0 && o.Genres.Count > 0) { Genres = o.Genres; changed = true; }
        if (changed) Sources = Sources == "" ? source : Sources + ", " + source;
        return changed;
    }
}

/// <summary>
/// Playnite-style free metadata: works for games that are not from Steam (e.g. cracked/offline copies) by matching
/// the title — or a <c>steam_appid.txt</c> left in the install folder — against Steam's public store, then optionally
/// SteamGridDB, TheGamesDB and IGDB when API keys are configured. Results are cached locally and queued for the
/// Game OS games database.
/// </summary>
public static class GameMetadataResolver
{
    private static readonly HttpClient Http = CreateHttp();

    private static HttpClient CreateHttp()
    {
        var h = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        h.DefaultRequestHeaders.UserAgent.ParseAdd("GameOS-Launcher/1.0");
        return h;
    }

    // ── Title helpers ─────────────────────────────────────────────────────────

    private static readonly Regex NoiseRx = new(
        @"(\[[^\]]*\]|\([^)]*\)|\bv?\d+(\.\d+){1,}\w*|\bbuild\s*\d+|[-_.]\s*(codex|plaza|skidrow|cpy|fitgirl|dodi|gog|goldberg|rune|tenoke|razor1911|flt|darksiders|elamigos)\b.*$|\b(repack|multi\d*|proper|incl\.?.*dlc|portable)\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Strips release-group tags, versions and brackets so a folder name becomes a searchable title.</summary>
    public static string CleanTitle(string raw)
    {
        string t = NoiseRx.Replace(raw ?? "", " ").Replace('_', ' ').Replace('.', ' ');
        return Regex.Replace(t, @"\s+", " ").Trim(' ', '-');
    }

    public static string Normalize(string s) => Regex.Replace(CleanTitle(s).ToLowerInvariant(), @"[^a-z0-9]", "");

    /// <summary>Index of the candidate whose name equals the title, else one that starts with / is a prefix of it; -1 if none is close.</summary>
    public static int BestIndex(string title, IReadOnlyList<string> names)
    {
        string n = Normalize(title);
        if (n == "") return -1;
        for (int i = 0; i < names.Count; i++) if (Normalize(names[i]) == n) return i;
        for (int i = 0; i < names.Count; i++)
        {
            var m = Normalize(names[i]);
            if (m.Length >= 4 && (m.StartsWith(n) || n.StartsWith(m))) return i;
        }
        return -1;
    }

    // ── Local metadata (install folder) ───────────────────────────────────────

    /// <summary>Reads a Steam AppId left next to a cracked game (steam_appid.txt / steam_settings), or 0.</summary>
    public static long ReadLocalSteamAppId(string? installDir)
    {
        if (string.IsNullOrWhiteSpace(installDir) || !Directory.Exists(installDir)) return 0;
        string[] candidates =
        {
            Path.Combine(installDir, "steam_appid.txt"),
            Path.Combine(installDir, "steam_settings", "steam_appid.txt"),
            Path.Combine(installDir, "steam_api", "steam_appid.txt"),
        };
        foreach (var f in candidates)
        {
            try { if (File.Exists(f) && long.TryParse(File.ReadAllText(f).Trim(), out var id) && id > 0) return id; }
            catch { /* unreadable file – try next */ }
        }
        return 0;
    }

    /// <summary>Finds a cover/icon/banner image shipped inside the game folder.</summary>
    public static GameMetadata ReadLocalMetadata(string title, string? installDir)
    {
        var m = new GameMetadata { Title = title, SteamAppId = ReadLocalSteamAppId(installDir) };
        if (string.IsNullOrWhiteSpace(installDir) || !Directory.Exists(installDir)) return m;
        try
        {
            string? Find(params string[] names) => names
                .SelectMany(n => new[] { ".jpg", ".jpeg", ".png" }.Select(e => Path.Combine(installDir, n + e)))
                .FirstOrDefault(File.Exists);
            if (Find("cover", "folder", "poster", "boxart") is { } c) m.CoverUrl = new Uri(c).AbsoluteUri;
            if (Find("background", "backdrop", "fanart", "hero") is { } b) m.BackgroundUrl = new Uri(b).AbsoluteUri;
            if (Find("logo") is { } l) m.LogoUrl = new Uri(l).AbsoluteUri;
        }
        catch { /* best-effort */ }
        return m;
    }

    // ── Providers ─────────────────────────────────────────────────────────────

    /// <summary>Steam artwork that exists for any AppId without an API key.</summary>
    public static GameMetadata SteamArt(long appId) => new()
    {
        SteamAppId = appId,
        CoverUrl = $"https://cdn.cloudflare.steamstatic.com/steam/apps/{appId}/library_600x900.jpg",
        BackgroundUrl = $"https://cdn.cloudflare.steamstatic.com/steam/apps/{appId}/library_hero.jpg",
        LogoUrl = $"https://cdn.cloudflare.steamstatic.com/steam/apps/{appId}/logo.png",
        IconUrl = $"https://cdn.cloudflare.steamstatic.com/steam/apps/{appId}/capsule_184x69.jpg",
    };

    public static long ParseSteamSearch(string json, string title)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("items", out var items)) return 0;
        var hits = items.EnumerateArray()
            .Select(i => (id: i.TryGetProperty("id", out var x) ? x.GetInt64() : 0, name: i.TryGetProperty("name", out var n) ? n.GetString() ?? "" : ""))
            .ToList();
        int idx = BestIndex(title, hits.Select(h => h.name).ToList());
        return idx < 0 ? 0 : hits[idx].id;
    }

    public static GameMetadata? ParseSteamDetails(string json, long appId)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty(appId.ToString(), out var e) || !e.TryGetProperty("success", out var ok) || !ok.GetBoolean()
            || !e.TryGetProperty("data", out var d)) return null;
        string Str(string n) => d.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        List<string> Arr(string n) => d.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() ?? "" : "").Where(x => x != "").ToList() : new();
        var m = SteamArt(appId);
        m.Title = Str("name");
        m.Description = Str("short_description");
        m.Developer = string.Join(", ", Arr("developers"));
        m.Publisher = string.Join(", ", Arr("publishers"));
        if (d.TryGetProperty("genres", out var g) && g.ValueKind == JsonValueKind.Array)
            m.Genres = g.EnumerateArray().Select(x => x.TryGetProperty("description", out var s) ? s.GetString() ?? "" : "").Where(x => x != "").ToList();
        if (d.TryGetProperty("release_date", out var rd) && rd.TryGetProperty("date", out var ds)
            && Regex.Match(ds.GetString() ?? "", @"\b(19|20)\d{2}\b") is { Success: true } y) m.ReleaseYear = int.Parse(y.Value);
        if (d.TryGetProperty("metacritic", out var mc) && mc.TryGetProperty("score", out var sc) && sc.ValueKind == JsonValueKind.Number)
            m.Rating = sc.GetDouble() / 20.0;
        return m;
    }

    private static async Task<string?> GetAsync(string url, string? bearer = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (bearer != null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        using var resp = await Http.SendAsync(req);
        return resp.IsSuccessStatusCode ? await resp.Content.ReadAsStringAsync() : null;
    }

    private static async Task<GameMetadata?> SteamStoreAsync(string title, long knownAppId)
    {
        long id = knownAppId;
        if (id == 0)
        {
            string? s = await GetAsync($"https://store.steampowered.com/api/storesearch/?term={Uri.EscapeDataString(title)}&l=english&cc=us");
            if (s != null) id = ParseSteamSearch(s, title);
        }
        if (id == 0) return null;
        string? details = await GetAsync($"https://store.steampowered.com/api/appdetails?appids={id}&l=english");
        return (details != null ? ParseSteamDetails(details, id) : null) ?? SteamArt(id);
    }

    public static GameMetadata? ParseSteamGridDb(string gridsJson, string heroesJson, string logosJson, string iconsJson)
    {
        static string First(string json)
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("data", out var a) && a.ValueKind == JsonValueKind.Array && a.GetArrayLength() > 0
                && a[0].TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        }
        var m = new GameMetadata { CoverUrl = First(gridsJson), BackgroundUrl = First(heroesJson), LogoUrl = First(logosJson), IconUrl = First(iconsJson) };
        return m.CoverUrl == "" && m.BackgroundUrl == "" && m.LogoUrl == "" && m.IconUrl == "" ? null : m;
    }

    private static async Task<GameMetadata?> SteamGridDbAsync(string title, string apiKey)
    {
        string? s = await GetAsync($"https://www.steamgriddb.com/api/v2/search/autocomplete/{Uri.EscapeDataString(title)}", apiKey);
        if (s == null) return null;
        using var doc = JsonDocument.Parse(s);
        if (!doc.RootElement.TryGetProperty("data", out var data)) return null;
        var hits = data.EnumerateArray().Select(x => (id: x.GetProperty("id").GetInt64(), name: x.GetProperty("name").GetString() ?? "")).ToList();
        int bi = BestIndex(title, hits.Select(h => h.name).ToList());
        if (bi < 0) return null;
        string Ep(string kind, string q = "") => $"https://www.steamgriddb.com/api/v2/{kind}/game/{hits[bi].id}{q}";
        var grids = GetAsync(Ep("grids", "?dimensions=600x900"), apiKey);
        var heroes = GetAsync(Ep("heroes"), apiKey);
        var logos = GetAsync(Ep("logos"), apiKey);
        var icons = GetAsync(Ep("icons"), apiKey);
        await Task.WhenAll(grids, heroes, logos, icons);
        return ParseSteamGridDb(grids.Result ?? "{}", heroes.Result ?? "{}", logos.Result ?? "{}", icons.Result ?? "{}");
    }

    public static GameMetadata? ParseTheGamesDb(string json, string title)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("data", out var data) || !data.TryGetProperty("games", out var games)) return null;
        var list = games.EnumerateArray().ToList();
        int mi = BestIndex(title, list.Select(g => g.TryGetProperty("game_name", out var n) ? n.GetString() ?? "" : "").ToList());
        if (mi < 0) return null;
        var g0 = list[mi];
        var m = new GameMetadata
        {
            Title = g0.TryGetProperty("game_name", out var gn) ? gn.GetString() ?? "" : "",
            Description = g0.TryGetProperty("overview", out var ov) && ov.ValueKind == JsonValueKind.String ? ov.GetString() ?? "" : "",
        };
        if (g0.TryGetProperty("release_date", out var rd) && Regex.Match(rd.GetString() ?? "", @"^(19|20)\d{2}") is { Success: true } y) m.ReleaseYear = int.Parse(y.Value);
        string id = g0.TryGetProperty("id", out var idEl) ? idEl.ToString() : "";
        if (doc.RootElement.TryGetProperty("include", out var inc) && inc.TryGetProperty("boxart", out var box)
            && box.TryGetProperty("base_url", out var bu) && bu.TryGetProperty("original", out var orig)
            && box.TryGetProperty("data", out var bd) && bd.TryGetProperty(id, out var arts))
        {
            var front = arts.EnumerateArray().FirstOrDefault(a => a.TryGetProperty("side", out var s) && s.GetString() == "front");
            if (front.ValueKind == JsonValueKind.Object && front.TryGetProperty("filename", out var fn))
                m.CoverUrl = (orig.GetString() ?? "") + fn.GetString();
        }
        return m;
    }

    private static async Task<GameMetadata?> TheGamesDbAsync(string title, string apiKey)
    {
        string? s = await GetAsync($"https://api.thegamesdb.net/v1/Games/ByGameName?apikey={Uri.EscapeDataString(apiKey)}&name={Uri.EscapeDataString(title)}&fields=overview&include=boxart");
        return s == null ? null : ParseTheGamesDb(s, title);
    }

    private static GameMetadata FromIgdb(IgdbGameInfo g) => new()
    {
        Title = g.Name, Description = g.Summary, CoverUrl = g.CoverUrl ?? "", Rating = g.Rating,
        ReleaseYear = g.ReleaseYear ?? 0, Genres = g.Genres,
    };

    // ── Resolve + cache + contribute ──────────────────────────────────────────

    private static bool IsPc(string? platform) => string.IsNullOrWhiteSpace(platform) || string.Equals(platform, "PC", StringComparison.OrdinalIgnoreCase);

    private static string CachePath(string title, string? platform) =>
        Path.Combine(UserDataService.DataRoot, "MetadataCache",
            UserDataService.SanitiseFolderName((IsPc(platform) ? "" : platform!.ToLowerInvariant() + "-") + Normalize(title)) + ".json");

    public static GameMetadata? LoadCached(string title, string? platform = "PC")
    {
        try
        {
            string p = CachePath(title, platform);
            return File.Exists(p) ? JsonSerializer.Deserialize<GameMetadata>(File.ReadAllText(p)) : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Resolves metadata for a game that may not come from Steam. Order: cache → local folder → Steam store (free)
    /// → SteamGridDB → TheGamesDB → IGDB (the last three only when keys are set). Missing fields are filled in turn.
    /// Steam is PC-only; ROM platforms use the keyed providers.
    /// </summary>
    public static async Task<GameMetadata> ResolveAsync(string rawTitle, string? installDir, string platform,
        string steamGridDbKey = "", string theGamesDbKey = "", string igdbClientId = "", string igdbClientSecret = "", bool forceRefresh = false)
    {
        string title = CleanTitle(rawTitle);
        if (title == "") title = rawTitle;
        if (!forceRefresh && LoadCached(title, platform) is { IsEmpty: false } cached) return cached;

        var meta = ReadLocalMetadata(title, installDir);
        if (meta.SteamAppId > 0) meta.Sources = "Local";

        async Task Run(string name, Func<Task<GameMetadata?>> fetch)
        {
            try { if (await fetch() is { } r) meta.FillFrom(r, name); }
            catch (Exception ex) { DevLogService.Log($"[Metadata] {name} failed for '{title}': {ex.Message}"); }
        }

        // Steam's store only knows PC games; consoles/ROMs rely on SteamGridDB, TheGamesDB and IGDB.
        if (IsPc(platform)) await Run("Steam", () => SteamStoreAsync(title, meta.SteamAppId));
        if (!string.IsNullOrWhiteSpace(steamGridDbKey)) await Run("SteamGridDB", () => SteamGridDbAsync(title, steamGridDbKey));
        if (!string.IsNullOrWhiteSpace(theGamesDbKey)) await Run("TheGamesDB", () => TheGamesDbAsync(title, theGamesDbKey));
        var igdb = new IgdbService(igdbClientId, igdbClientSecret);
        if (igdb.IsConfigured)
            await Run("IGDB", async () =>
            {
                var hits = await igdb.SearchAsync(title);
                int bi = BestIndex(title, hits.Select(h => h.Name).ToList());
                return bi < 0 ? null : FromIgdb(hits[bi]);
            });

        if (meta.Title == "") meta.Title = title;
        if (!meta.IsEmpty)
        {
            try
            {
                string p = CachePath(title, platform);
                Directory.CreateDirectory(Path.GetDirectoryName(p)!);
                File.WriteAllText(p, JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex) { DevLogService.Log($"[Metadata] cache write failed: {ex.Message}"); }
            Contribute(meta, platform);
        }
        return meta;
    }

    /// <summary>Queues the resolved game for the Game OS games database (Steam AppId when known, else a title entry).</summary>
    public static void Contribute(GameMetadata m, string platform)
    {
        if (m.SteamAppId > 0) DatabaseContributionQueue.EnqueueSteamGame(m.SteamAppId, m.Title);
        else DatabaseContributionQueue.EnqueueRom(string.IsNullOrWhiteSpace(platform) ? "PC" : platform, m.Title, null,
            m.Description == "" ? null : m.Description, null);
    }
}
