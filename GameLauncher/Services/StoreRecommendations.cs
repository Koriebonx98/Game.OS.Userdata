using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using GameLauncher.Models;

namespace GameLauncher.Services;

/// <summary>
/// Store recommendations, ported from the website (script.js <c>buildRecommendations</c>):
/// games the user does not own, ranked by overlap with the genres / platforms / series they play.
/// </summary>
internal static class StoreRecommendations
{
    private static string Key(string? platform, string? title) =>
        $"{(platform ?? "").Trim().ToLowerInvariant()}|{(title ?? "").Trim().ToLowerInvariant()}";

    private static IEnumerable<string> Genres(string? genre) =>
        (genre ?? "").Split(new[] { ',', '/', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     .Where(g => !string.Equals(g, "Unknown", StringComparison.OrdinalIgnoreCase))
                     .Select(g => g.ToLowerInvariant());

    /// <summary>Series key: title before ':' / ' - ' minus a trailing number or roman numeral.</summary>
    public static string Series(string? title)
    {
        var t = (title ?? "").ToLowerInvariant();
        t = Regex.Split(t, @"\s*[:\u2013-]\s+")[0];
        t = Regex.Replace(t, @"\s+(\d+|[ivx]{1,5})$", "");
        t = Regex.Replace(t, @"[^a-z0-9 ]", "").Trim();
        return t.Length >= 3 ? t : "";
    }

    /// <summary>Up to <paramref name="count"/> unowned store games, mixed across platforms (best <paramref name="perPlatform"/> of each).</summary>
    public static List<StoreGame> ForUser(IEnumerable<StoreGame> catalog, IEnumerable<(string Platform, string Title, string Genre)> owned,
                                          int count, int perPlatform = 3)
    {
        var ownedList = owned.ToList();
        var excluded = new HashSet<string>(ownedList.Select(o => Key(o.Platform, o.Title)));
        var genreScore = new Dictionary<string, int>();
        var platScore = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var seriesScore = new Dictionary<string, int>();
        foreach (var o in ownedList)
        {
            platScore[o.Platform] = platScore.GetValueOrDefault(o.Platform) + 1;
            var s = Series(o.Title);
            if (s.Length > 0) seriesScore[s] = seriesScore.GetValueOrDefault(s) + 1;
            foreach (var g in Genres(o.Genre)) genreScore[g] = genreScore.GetValueOrDefault(g) + 1;
        }

        var scored = new List<(double Score, StoreGame Game)>();
        var seen = new HashSet<string>();
        foreach (var g in catalog)
        {
            if (string.IsNullOrWhiteSpace(g.Title)) continue;
            var key = Key(g.Platform, g.Title);
            if (excluded.Contains(key) || !seen.Add(key)) continue;
            double s = platScore.GetValueOrDefault(g.Platform) * 0.5 + (string.IsNullOrEmpty(g.CoverUrl) ? 0 : 0.5);
            foreach (var x in Genres(g.Genre)) s += genreScore.GetValueOrDefault(x);
            s += seriesScore.GetValueOrDefault(Series(g.Title)) * 3;
            scored.Add((s, g));
        }

        var ordered = scored.OrderByDescending(x => x.Score).ThenByDescending(x => x.Game.Rating)
                            .ThenBy(x => x.Game.Title, StringComparer.OrdinalIgnoreCase).ToList();

        var buckets = ordered.GroupBy(x => x.Game.Platform, StringComparer.OrdinalIgnoreCase)
                             .OrderBy(b => b.Key, StringComparer.OrdinalIgnoreCase)
                             .Select(b => b.Take(perPlatform).Select(x => x.Game).ToList()).ToList();
        var mixed = new List<StoreGame>();
        for (int i = 0; i < perPlatform; i++)
            foreach (var b in buckets)
                if (i < b.Count) mixed.Add(b[i]);
        return mixed.Take(count).ToList();
    }

    /// <summary>Store games related to one title: same series first, then shared genres, then same platform.</summary>
    public static List<StoreGame> Related(IEnumerable<StoreGame> catalog, string platform, string title, string? genre, int count)
    {
        var all = catalog.ToList();
        var self = all.FirstOrDefault(g => Key(g.Platform, g.Title) == Key(platform, title));
        var genres = new HashSet<string>(Genres(string.IsNullOrWhiteSpace(genre) || genre == "Unknown" ? self?.Genre : genre));
        var series = Series(title);
        var selfKey = Key(platform, title);
        var seen = new HashSet<string> { selfKey };

        return all
            .Where(g => !string.IsNullOrWhiteSpace(g.Title) && seen.Add(Key(g.Platform, g.Title)))
            .Select(g =>
            {
                double s = string.Equals(g.Platform, platform, StringComparison.OrdinalIgnoreCase) ? 0.5 : 0;
                if (series.Length > 0 && Series(g.Title) == series) s += 5;
                s += Genres(g.Genre).Count(genres.Contains);
                return (Score: s, Game: g);
            })
            .Where(x => x.Score >= 1)
            .OrderByDescending(x => x.Score).ThenByDescending(x => x.Game.Rating)
            .ThenBy(x => x.Game.Title, StringComparer.OrdinalIgnoreCase)
            .Take(count)
            .Select(x => x.Game)
            .ToList();
    }
}
