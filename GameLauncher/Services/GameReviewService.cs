using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace GameLauncher.Services;

/// <summary>
/// Loads and saves per-game user reviews from
/// <c>Data/GameCache/{platform}/{title}/reviews.json</c>.
///
/// Reviews are stored locally on disk and, optionally, queued for upload to
/// the Games.Database via <see cref="GitHubDataService"/>.
/// </summary>
public static class GameReviewService
{
    private static readonly JsonSerializerOptions _json = new()
    {
        WriteIndented      = true,
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Returns the path to the reviews.json file for the given platform + title.
    /// </summary>
    public static string GetReviewsPath(string platform, string title)
    {
        string sanitized = SanitizeFolderName(title);
        return Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "Data", "GameCache", platform, sanitized,
            "reviews.json");
    }

    /// <summary>
    /// Loads all cached reviews for the given game.
    /// Returns an empty list when the file does not exist.
    /// </summary>
    public static List<Models.GameReview> LoadReviews(string platform, string title)
    {
        string path = GetReviewsPath(platform, title);
        if (!File.Exists(path)) return new List<Models.GameReview>();
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<List<Models.GameReview>>(json, _json)
                   ?? new List<Models.GameReview>();
        }
        catch { return new List<Models.GameReview>(); }
    }

    /// <summary>
    /// Saves the given collection of reviews to the local cache file,
    /// creating parent directories as needed.
    /// </summary>
    public static void SaveReviews(string platform, string title,
                                   IEnumerable<Models.GameReview> reviews)
    {
        string path = GetReviewsPath(platform, title);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(reviews, _json));
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Adds a new review to the local cache, replacing any existing review by the
    /// same username (one review per user per game).
    /// </summary>
    public static void AddOrUpdateReview(string platform, string title,
                                         Models.GameReview review)
    {
        var reviews = LoadReviews(platform, title);
        reviews.RemoveAll(r =>
            string.Equals(r.Username, review.Username, StringComparison.OrdinalIgnoreCase));
        reviews.Add(review);
        SaveReviews(platform, title, reviews);
    }

    private static string SanitizeFolderName(string name)
    {
        foreach (char c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }
}
