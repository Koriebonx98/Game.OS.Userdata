using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace GameLauncher.Services;

/// <summary>A game discovered by a library provider (Playnite-style).</summary>
public sealed record ProviderGame(string Provider, string Id, string Title, string InstallPath, string LaunchUri);

/// <summary>A store/launcher whose installed games can be listed.</summary>
public interface IGameLibraryProvider
{
    string Name { get; }
    IReadOnlyList<ProviderGame> Scan();
}

/// <summary>Library providers (installed games per store) and the IGDB metadata provider.</summary>
public static class GameProviderService
{
    public static IReadOnlyList<IGameLibraryProvider> Providers { get; } = new IGameLibraryProvider[]
    {
        new EpicProvider(), new GogProvider(), new UbisoftProvider(), new EaProvider(),
    };

    /// <summary>Scans every provider; one failing provider never blocks the others.</summary>
    public static List<ProviderGame> ScanAll()
    {
        var all = new List<ProviderGame>();
        foreach (var p in Providers)
        {
            try { all.AddRange(p.Scan()); }
            catch (Exception ex) { DevLogService.Log($"[Providers] {p.Name} scan failed: {ex.Message}"); }
        }
        return all;
    }

    /// <summary>Parses one Epic Games Launcher manifest (.item) JSON. Returns null when it is not an installed game.</summary>
    public static ProviderGame? ParseEpicManifest(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        string Str(string n) => r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        string name = Str("DisplayName"), app = Str("AppName"), dir = Str("InstallLocation");
        if (name == "" || app == "" || dir == "") return null;
        if (r.TryGetProperty("bIsIncompleteInstall", out var inc) && inc.ValueKind == JsonValueKind.True) return null;
        string ns = Str("CatalogNamespace"), item = Str("CatalogItemId");
        return new ProviderGame("Epic", app, name, dir,
            $"com.epicgames.launcher://apps/{Uri.EscapeDataString($"{ns}:{item}:{app}")}?action=launch&silent=true");
    }

    private sealed class EpicProvider : IGameLibraryProvider
    {
        public string Name => "Epic";
        public IReadOnlyList<ProviderGame> Scan()
        {
            var list = new List<ProviderGame>();
            if (!OperatingSystem.IsWindows()) return list;
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Epic", "EpicGamesLauncher", "Data", "Manifests");
            if (!Directory.Exists(dir)) return list;
            foreach (var f in Directory.EnumerateFiles(dir, "*.item"))
            {
                try { if (ParseEpicManifest(File.ReadAllText(f)) is { } g) list.Add(g); }
                catch (Exception ex) { DevLogService.Log($"[Providers] Epic manifest {f}: {ex.Message}"); }
            }
            return list;
        }
    }

    private sealed class GogProvider : IGameLibraryProvider
    {
        public string Name => "GOG";
        public IReadOnlyList<ProviderGame> Scan()
        {
            var list = new List<ProviderGame>();
            if (!OperatingSystem.IsWindows()) return list;
            using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\GOG.com\Games");
            if (root == null) return list;
            foreach (var id in root.GetSubKeyNames())
            {
                using var k = root.OpenSubKey(id);
                string title = k?.GetValue("gameName") as string ?? "", path = k?.GetValue("path") as string ?? "";
                if (title == "" || path == "") continue;
                list.Add(new ProviderGame("GOG", id, title, path, $"goggalaxy://openGameView/{id}"));
            }
            return list;
        }
    }

    private sealed class UbisoftProvider : IGameLibraryProvider
    {
        public string Name => "Ubisoft Connect";
        public IReadOnlyList<ProviderGame> Scan()
        {
            var list = new List<ProviderGame>();
            if (!OperatingSystem.IsWindows()) return list;
            using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs");
            if (root == null) return list;
            foreach (var id in root.GetSubKeyNames())
            {
                using var k = root.OpenSubKey(id);
                string dir = (k?.GetValue("InstallDir") as string ?? "").TrimEnd('/', '\\');
                if (dir == "" || !Directory.Exists(dir)) continue;
                list.Add(new ProviderGame("Ubisoft Connect", id, new DirectoryInfo(dir).Name, dir, $"uplay://launch/{id}/0"));
            }
            return list;
        }
    }

    private sealed class EaProvider : IGameLibraryProvider
    {
        public string Name => "EA app";
        public IReadOnlyList<ProviderGame> Scan()
        {
            var list = new List<ProviderGame>();
            if (!OperatingSystem.IsWindows()) return list;
            // EA app writes an InstallerData.xml-less layout; installed titles register their folder here.
            using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\EA Games");
            if (root == null) return list;
            foreach (var title in root.GetSubKeyNames())
            {
                using var k = root.OpenSubKey(title);
                string dir = (k?.GetValue("Install Dir") as string ?? "").TrimEnd('/', '\\');
                if (dir == "" || !Directory.Exists(dir)) continue;
                list.Add(new ProviderGame("EA app", title, title, dir, ""));
            }
            return list;
        }
    }
}

/// <summary>Result of an IGDB lookup.</summary>
public sealed record IgdbGameInfo(long Id, string Name, string Summary, string? CoverUrl, double Rating, int? ReleaseYear, List<string> Genres);

/// <summary>
/// IGDB metadata provider. Needs a free Twitch application (client id + secret) — see https://api-docs.igdb.com/#account-creation.
/// </summary>
public sealed class IgdbService
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };
    private readonly string _clientId, _clientSecret;
    private string? _token;
    private DateTime _tokenExpiry = DateTime.MinValue;

    public IgdbService(string clientId, string clientSecret) { _clientId = clientId; _clientSecret = clientSecret; }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(_clientId) && !string.IsNullOrWhiteSpace(_clientSecret);

    private async Task<string?> GetTokenAsync()
    {
        if (_token != null && DateTime.UtcNow < _tokenExpiry) return _token;
        var url = $"https://id.twitch.tv/oauth2/token?client_id={Uri.EscapeDataString(_clientId)}" +
                  $"&client_secret={Uri.EscapeDataString(_clientSecret)}&grant_type=client_credentials";
        using var resp = await Http.PostAsync(url, null);
        if (!resp.IsSuccessStatusCode) return null;
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        _token = doc.RootElement.GetProperty("access_token").GetString();
        _tokenExpiry = DateTime.UtcNow.AddSeconds(doc.RootElement.GetProperty("expires_in").GetInt32() - 60);
        return _token;
    }

    public async Task<List<IgdbGameInfo>> SearchAsync(string title, int limit = 5)
    {
        var result = new List<IgdbGameInfo>();
        if (!IsConfigured || string.IsNullOrWhiteSpace(title)) return result;
        try
        {
            string? token = await GetTokenAsync();
            if (token == null) return result;
            string safe = title.Replace("\\", " ").Replace("\"", " ");
            using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.igdb.com/v4/games")
            {
                Content = new StringContent(
                    $"search \"{safe}\"; fields name,summary,total_rating,first_release_date,cover.image_id,genres.name; limit {Math.Clamp(limit, 1, 20)};",
                    Encoding.UTF8, "text/plain")
            };
            req.Headers.Add("Client-ID", _clientId);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await Http.SendAsync(req);
            if (!resp.IsSuccessStatusCode) return result;
            result = ParseGames(await resp.Content.ReadAsStringAsync());
        }
        catch (Exception ex) { DevLogService.Log($"[IGDB] search failed: {ex.Message}"); }
        return result;
    }

    public static List<IgdbGameInfo> ParseGames(string json)
    {
        var list = new List<IgdbGameInfo>();
        using var doc = JsonDocument.Parse(json);
        foreach (var g in doc.RootElement.EnumerateArray())
        {
            string cover = g.TryGetProperty("cover", out var c) && c.TryGetProperty("image_id", out var im)
                ? $"https://images.igdb.com/igdb/image/upload/t_cover_big/{im.GetString()}.jpg" : "";
            double rating = g.TryGetProperty("total_rating", out var r) && r.ValueKind == JsonValueKind.Number ? r.GetDouble() / 20.0 : 0;
            int? year = g.TryGetProperty("first_release_date", out var d) && d.ValueKind == JsonValueKind.Number
                ? DateTimeOffset.FromUnixTimeSeconds(d.GetInt64()).Year : null;
            var genres = g.TryGetProperty("genres", out var gs)
                ? gs.EnumerateArray().Select(x => x.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "").Where(x => x != "").ToList()
                : new List<string>();
            list.Add(new IgdbGameInfo(
                g.GetProperty("id").GetInt64(),
                g.TryGetProperty("name", out var nm) ? nm.GetString() ?? "" : "",
                g.TryGetProperty("summary", out var sm) ? sm.GetString() ?? "" : "",
                cover == "" ? null : cover, rating, year, genres));
        }
        return list;
    }
}
