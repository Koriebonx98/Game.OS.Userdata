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
            new Game { Platform = "PC",    Title = "Cyberpunk 2077",     Genre = "RPG",         Rating = 9.1, AddedAt = "2025-01-10T12:00:00Z", Description = "Open-world action RPG set in the future.",            CoverColor = "#1a1a2e", CoverGradient = "#1a1a2e,#16213e" },
            new Game { Platform = "PC",    Title = "Elden Ring",         Genre = "Action RPG",  Rating = 9.6, AddedAt = "2025-02-14T09:30:00Z", Description = "Epic open-world action RPG by FromSoftware.",          CoverColor = "#1c0a00", CoverGradient = "#1c0a00,#6e2400" },
            new Game { Platform = "PC",    Title = "Baldur's Gate 3",    Genre = "RPG",         Rating = 9.8, AddedAt = "2025-03-01T15:00:00Z", Description = "Award-winning DnD RPG by Larian Studios.",             CoverColor = "#0d1b2a", CoverGradient = "#0d1b2a,#1b4332" },
            new Game { Platform = "Xbox",  Title = "Halo Infinite",      Genre = "FPS",         Rating = 8.5, AddedAt = "2025-01-20T11:00:00Z", Description = "Master Chief returns in this epic sci-fi FPS.",        CoverColor = "#003153", CoverGradient = "#003153,#0056a8" },
            new Game { Platform = "PS5",   Title = "God of War Ragnarök", Genre = "Action",     Rating = 9.7, AddedAt = "2025-02-05T08:00:00Z", Description = "Kratos and Atreus face the trials of Ragnarök.",      CoverColor = "#1a0a00", CoverGradient = "#1a0a00,#8b0000" },
            new Game { Platform = "PC",    Title = "Hogwarts Legacy",    Genre = "RPG",         Rating = 8.7, AddedAt = "2025-04-01T10:00:00Z", Description = "Explore Hogwarts in this open-world RPG.",             CoverColor = "#1e0a2a", CoverGradient = "#1e0a2a,#4a0080" },
            new Game { Platform = "Switch", Title = "Zelda: TOTK",       Genre = "Adventure",   Rating = 9.9, AddedAt = "2025-04-15T14:00:00Z", Description = "Link explores the skies of Hyrule.",                  CoverColor = "#0a1628", CoverGradient = "#0a1628,#1a4a6e" },
            new Game { Platform = "PC",    Title = "Starfield",          Genre = "RPG",         Rating = 7.9, AddedAt = "2025-05-10T09:00:00Z", Description = "Bethesda's first new universe in 25 years.",           CoverColor = "#05060f", CoverGradient = "#05060f,#1a1a3e" },
        };

        public static List<Achievement> Achievements { get; } = new()
        {
            new Achievement { Platform = "PC",    GameTitle = "Cyberpunk 2077",  Name = "Night City Legend",   Description = "Complete all main missions.",            UnlockedAt = "2025-01-15T14:00:00Z" },
            new Achievement { Platform = "PC",    GameTitle = "Elden Ring",      Name = "Elden Lord",          Description = "Defeat the Elden Beast.",                UnlockedAt = "2025-02-20T18:30:00Z" },
            new Achievement { Platform = "Xbox",  GameTitle = "Halo Infinite",   Name = "Master Chief",        Description = "Complete the campaign on Legendary.",    UnlockedAt = "2025-01-25T20:00:00Z" },
            new Achievement { Platform = "PC",    GameTitle = "Baldur's Gate 3", Name = "Dark Urge Overcome",  Description = "Resist the Dark Urge throughout.",       UnlockedAt = "2025-03-10T16:00:00Z" },
            new Achievement { Platform = "PS5",   GameTitle = "God of War Ragnarök", Name = "Father and Son", Description = "Complete the main story.",               UnlockedAt = "2025-02-10T21:00:00Z" },
        };

        public static List<StoreGame> Store { get; } = new()
        {
            // Featured
            new StoreGame { Title = "GTA VI",                     Platform = "PC",    Genre = "Open World",   Price = "£69.99", Rating = 9.5, IsFeatured = true,  ReleaseYear = "2026", Description = "Rockstar's long-awaited return to Vice City.",            CoverColor = "#0a1628", CoverGradient = "#0a1628,#1a3a6e" },
            new StoreGame { Title = "The Elder Scrolls VI",       Platform = "PC",    Genre = "RPG",          Price = "£59.99", Rating = 9.3, IsFeatured = true,  ReleaseYear = "2026", Description = "Bethesda's next open-world fantasy epic.",                CoverColor = "#1a0c00", CoverGradient = "#1a0c00,#5c3a00" },
            new StoreGame { Title = "Call of Duty 2025",          Platform = "PC",    Genre = "FPS",          Price = "£69.99", Rating = 8.2, IsFeatured = true,  ReleaseYear = "2025", Description = "The latest entry in the CoD franchise.",                  CoverColor = "#0c0c0c", CoverGradient = "#0c0c0c,#2a2a2a" },
            // New releases
            new StoreGame { Title = "Hollow Knight: Silksong",    Platform = "PC",    Genre = "Metroidvania", Price = "£14.99", Rating = 9.4, IsFeatured = false, ReleaseYear = "2025", Description = "Hornet's long-awaited adventure continues.",              CoverColor = "#120021", CoverGradient = "#120021,#3a0057" },
            new StoreGame { Title = "Star Wars Outlaws",          Platform = "PC",    Genre = "Action",       Price = "£54.99", Rating = 8.0, IsFeatured = false, ReleaseYear = "2025", Description = "The first open-world Star Wars game.",                    CoverColor = "#05060f", CoverGradient = "#05060f,#0a1628" },
            new StoreGame { Title = "Metaphor: ReFantazio",       Platform = "PC",    Genre = "RPG",          Price = "£54.99", Rating = 9.3, IsFeatured = false, ReleaseYear = "2025", Description = "Atlus' new epic fantasy RPG.",                            CoverColor = "#1a0028", CoverGradient = "#1a0028,#5a0090" },
            new StoreGame { Title = "Monster Hunter Wilds",       Platform = "PC",    Genre = "Action RPG",   Price = "£54.99", Rating = 9.2, IsFeatured = false, ReleaseYear = "2025", Description = "Hunt massive monsters in stunning wilds.",                CoverColor = "#1c0a00", CoverGradient = "#1c0a00,#6b2800" },
            new StoreGame { Title = "Warhammer 40K: Space Marine 2", Platform = "PC", Genre = "Action",      Price = "£44.99", Rating = 8.9, IsFeatured = false, ReleaseYear = "2025", Description = "Fight for the Emperor in brutal close combat.",           CoverColor = "#0a0c0a", CoverGradient = "#0a0c0a,#1a2e1a" },
            new StoreGame { Title = "Dragon Age: Veilguard",      Platform = "PC",    Genre = "RPG",          Price = "£49.99", Rating = 8.6, IsFeatured = false, ReleaseYear = "2025", Description = "BioWare's return to Thedas.",                             CoverColor = "#1a0028", CoverGradient = "#1a0028,#4a0057" },
            new StoreGame { Title = "Avowed",                     Platform = "PC",    Genre = "RPG",          Price = "£49.99", Rating = 8.4, IsFeatured = false, ReleaseYear = "2025", Description = "Obsidian Entertainment's first-person RPG.",              CoverColor = "#0a1420", CoverGradient = "#0a1420,#1a3040" },
            new StoreGame { Title = "Doom: The Dark Ages",        Platform = "PC",    Genre = "FPS",          Price = "£49.99", Rating = 9.0, IsFeatured = false, ReleaseYear = "2025", Description = "The Slayer returns in medieval darkness.",                CoverColor = "#1a0000", CoverGradient = "#1a0000,#5a0000" },
            new StoreGame { Title = "Like a Dragon: Pirate Yakuza", Platform = "PC", Genre = "RPG",          Price = "£49.99", Rating = 8.7, IsFeatured = false, ReleaseYear = "2025", Description = "Majima goes pirate in this action RPG.",                  CoverColor = "#001a28", CoverGradient = "#001a28,#003a5a" },
        };
    }
}
