using System.Collections.Generic;
using GameLauncher.Models;

namespace GameLauncher
{
    /// <summary>
    /// Built-in demo data so the launcher can run without a live GitHub connection.
    /// </summary>
    internal static class DemoData
    {
        public static List<Game> Library { get; } = new()
        {
            new Game { Platform = "PC",   Title = "Cyberpunk 2077",    Genre = "RPG",         Rating = 9.1, AddedAt = "2025-01-10T12:00:00Z", Description = "Open-world action RPG set in the future." },
            new Game { Platform = "PC",   Title = "Elden Ring",        Genre = "Action RPG",  Rating = 9.6, AddedAt = "2025-02-14T09:30:00Z", Description = "Epic open-world action RPG by FromSoftware." },
            new Game { Platform = "PC",   Title = "Baldur's Gate 3",   Genre = "RPG",         Rating = 9.8, AddedAt = "2025-03-01T15:00:00Z", Description = "Award-winning DnD RPG by Larian Studios." },
            new Game { Platform = "Xbox", Title = "Halo Infinite",     Genre = "FPS",         Rating = 8.5, AddedAt = "2025-01-20T11:00:00Z", Description = "Master Chief returns in this FPS epic." },
            new Game { Platform = "PS5",  Title = "God of War Ragnarök",Genre = "Action",      Rating = 9.7, AddedAt = "2025-02-05T08:00:00Z", Description = "Kratos and Atreus face Ragnarök." },
        };

        public static List<Achievement> Achievements { get; } = new()
        {
            new Achievement { Platform = "PC",   GameTitle = "Cyberpunk 2077",  Name = "Night City Legend",  Description = "Complete all main missions.",        UnlockedAt = "2025-01-15T14:00:00Z" },
            new Achievement { Platform = "PC",   GameTitle = "Elden Ring",      Name = "Elden Lord",         Description = "Defeat the Elden Beast.",            UnlockedAt = "2025-02-20T18:30:00Z" },
            new Achievement { Platform = "Xbox", GameTitle = "Halo Infinite",   Name = "Master Chief",       Description = "Complete the campaign on Legendary.", UnlockedAt = "2025-01-25T20:00:00Z" },
        };

        public static List<StoreGame> Store { get; } = new()
        {
            // Featured
            new StoreGame { Title = "GTA VI",               Platform = "PC",   Genre = "Open World",  Price = "£69.99",  Rating = 9.5, IsFeatured = true,  ReleaseYear = "2026", Description = "Rockstar's long-awaited return to Vice City." },
            new StoreGame { Title = "Elder Scrolls VI",     Platform = "PC",   Genre = "RPG",         Price = "£59.99",  Rating = 9.3, IsFeatured = true,  ReleaseYear = "2026", Description = "Bethesda's next open-world fantasy epic." },
            new StoreGame { Title = "Call of Duty 2025",    Platform = "PC",   Genre = "FPS",         Price = "£69.99",  Rating = 8.2, IsFeatured = true,  ReleaseYear = "2025", Description = "The latest entry in the CoD franchise." },
            // New releases
            new StoreGame { Title = "Hollow Knight: Silksong", Platform = "PC", Genre = "Metroidvania", Price = "£14.99", Rating = 9.4, IsFeatured = false, ReleaseYear = "2025", Description = "Hornet's long-awaited adventure continues." },
            new StoreGame { Title = "Star Wars Outlaws",    Platform = "PC",   Genre = "Action",      Price = "£54.99",  Rating = 8.0, IsFeatured = false, ReleaseYear = "2025", Description = "The first open-world Star Wars game." },
            new StoreGame { Title = "Dragon Age: Veilguard",Platform = "PC",   Genre = "RPG",         Price = "£49.99",  Rating = 8.6, IsFeatured = false, ReleaseYear = "2025", Description = "BioWare's return to Thedas." },
            new StoreGame { Title = "Metaphor: ReFantazio", Platform = "PC",   Genre = "RPG",         Price = "£54.99",  Rating = 9.3, IsFeatured = false, ReleaseYear = "2025", Description = "Atlus' new epic fantasy RPG." },
            new StoreGame { Title = "Warhammer 40K: Space Marine 2", Platform = "PC", Genre = "Action", Price = "£44.99", Rating = 8.9, IsFeatured = false, ReleaseYear = "2025", Description = "Fight for the Emperor in brutal combat." },
            new StoreGame { Title = "Like a Dragon: Pirate Yakuza", Platform = "PC", Genre = "RPG",    Price = "£49.99", Rating = 8.7, IsFeatured = false, ReleaseYear = "2025", Description = "Majima goes pirate in this action RPG." },
            new StoreGame { Title = "Avowed",               Platform = "PC",   Genre = "RPG",         Price = "£49.99",  Rating = 8.4, IsFeatured = false, ReleaseYear = "2025", Description = "Obsidian Entertainment's next RPG." },
            new StoreGame { Title = "Monster Hunter Wilds", Platform = "PC",   Genre = "Action RPG",  Price = "£54.99",  Rating = 9.2, IsFeatured = false, ReleaseYear = "2025", Description = "Hunt massive monsters in stunning wilds." },
            new StoreGame { Title = "Doom: The Dark Ages",  Platform = "PC",   Genre = "FPS",         Price = "£49.99",  Rating = 9.0, IsFeatured = false, ReleaseYear = "2025", Description = "The Slayer returns in medieval darkness." },
        };
    }
}
