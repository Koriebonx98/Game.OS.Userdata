using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using GameOS.Desktop.Models;

namespace GameOS.Desktop.Services;

public class GameService
{
    private static readonly Dictionary<string, List<string>> SampleGames = new()
    {
        ["PC"] = new() { "Minecraft", "Counter-Strike 2", "Cyberpunk 2077", "Elden Ring", "The Witcher 3" },
        ["PS4"] = new() { "God of War", "The Last of Us Part II", "Spider-Man", "Horizon Zero Dawn" },
        ["PS5"] = new() { "Demon's Souls", "Ratchet & Clank: Rift Apart", "Returnal" },
        ["Switch"] = new() { "The Legend of Zelda: Breath of the Wild", "Super Mario Odyssey", "Animal Crossing: New Horizons" },
        ["Xbox One"] = new() { "Halo 5: Guardians", "Forza Horizon 4", "Gears 5" },
        ["PS3"] = new() { "The Last of Us", "Uncharted 2: Among Thieves", "Red Dead Redemption" },
        ["Xbox 360"] = new() { "Halo 3", "Gears of War", "Red Dead Redemption" }
    };

    public static List<Game> GetAllGames()
    {
        var games = new List<Game>();
        foreach (var (platform, titles) in SampleGames)
        {
            foreach (var title in titles)
            {
                games.Add(new Game { Platform = platform, Title = title, AddedAt = "" });
            }
        }
        return games;
    }

    public static List<string> GetPlatforms() => new() { "All", "PC", "PS3", "PS4", "PS5", "Switch", "Xbox 360", "Xbox One" };

    public static async Task<List<Game>> GetLibraryAsync(string username)
    {
        var path = Path.Combine(DataService.GetUserDataPath(username), "library.json");
        return await DataService.ReadJsonAsync<List<Game>>(path) ?? new List<Game>();
    }

    public static async Task AddGameAsync(string username, Game game)
    {
        var library = await GetLibraryAsync(username);
        if (library.Any(g => g.Platform == game.Platform && g.Title == game.Title)) return;
        game.AddedAt = DateTime.UtcNow.ToString("o");
        library.Add(game);
        var path = Path.Combine(DataService.GetUserDataPath(username), "library.json");
        await DataService.WriteJsonAsync(path, library);
    }

    public static async Task RemoveGameAsync(string username, string platform, string title)
    {
        var library = await GetLibraryAsync(username);
        library.RemoveAll(g => g.Platform == platform && g.Title == title);
        var path = Path.Combine(DataService.GetUserDataPath(username), "library.json");
        await DataService.WriteJsonAsync(path, library);
    }

    public static async Task<List<Game>> GetWishlistAsync(string username)
    {
        var path = Path.Combine(DataService.GetUserDataPath(username), "wishlist.json");
        return await DataService.ReadJsonAsync<List<Game>>(path) ?? new List<Game>();
    }

    public static async Task AddToWishlistAsync(string username, Game game)
    {
        var wishlist = await GetWishlistAsync(username);
        if (wishlist.Any(g => g.Platform == game.Platform && g.Title == game.Title)) return;
        game.AddedAt = DateTime.UtcNow.ToString("o");
        wishlist.Add(game);
        var path = Path.Combine(DataService.GetUserDataPath(username), "wishlist.json");
        await DataService.WriteJsonAsync(path, wishlist);
    }

    public static async Task RemoveFromWishlistAsync(string username, string platform, string title)
    {
        var wishlist = await GetWishlistAsync(username);
        wishlist.RemoveAll(g => g.Platform == platform && g.Title == title);
        var path = Path.Combine(DataService.GetUserDataPath(username), "wishlist.json");
        await DataService.WriteJsonAsync(path, wishlist);
    }
}
