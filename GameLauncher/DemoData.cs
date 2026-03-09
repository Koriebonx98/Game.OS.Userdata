using System.Collections.Generic;
using GameLauncher.Models;

namespace GameLauncher
{
    /// <summary>
    /// Static store catalog and game metadata used for display enrichment.
    /// The store catalog has no backend API endpoint, so it is defined here.
    /// The <see cref="LibraryMetadata"/> list provides UI-only metadata (genre,
    /// description, rating, cover) used to enrich games returned by the API.
    /// </summary>
    internal static class DemoData
    {
        /// <summary>
        /// Metadata lookup for known games.  Used to enrich API-returned library
        /// entries with cover colours, genres, descriptions, and ratings that the
        /// backend does not currently store.
        /// </summary>
        public static List<Game> Library { get; } = new()
        {
            new Game { Platform = "Switch", Title = "Mario Kart 8 Deluxe",  Genre = "Racing",      Rating = 9.7, AddedAt = "2025-06-01T10:00:00Z", Description = "Hit the road with the definitive version of Mario Kart 8! Race as your favourite Nintendo characters on 96 total courses, including all DLC Booster Course Pass tracks.",
                CoverColor = "#c00000", CoverGradient = "#c00000,#ff6b00",
                CoverUrl    = "https://assets.nintendo.com/image/upload/ar_16:9,b_auto:border,c_lpad/b_white/f_auto/q_auto/dpr_auto/c_scale,w_300/ncom/software/switch/70010000000153/b9248571a2c8cfc3ea62a6f9cf0e4219f2b9e7e5b87a38af51286aa5f18f7b0",
                Screenshots = new() {
                    "https://assets.nintendo.com/image/upload/f_auto/q_auto/ncom/software/switch/70010000000153/image/screenshot01",
                    "https://assets.nintendo.com/image/upload/f_auto/q_auto/ncom/software/switch/70010000000153/image/screenshot02",
                } },
            new Game { Platform = "PC",    Title = "Cyberpunk 2077",     Genre = "RPG",         Rating = 9.1, AddedAt = "2025-01-10T12:00:00Z", Description = "An open-world action RPG set in the dark future of Night City — a megalopolis obsessed with power, glamour and body modification.",            CoverColor = "#1a1a2e", CoverGradient = "#1a1a2e,#16213e",
                CoverUrl    = "https://media.rawg.io/media/games/26d/26d4437715bee60138dab4a7c8c59c92.jpg",
                Screenshots = new() {
                    "https://media.rawg.io/media/screenshots/a7c/a7c43871a54bed6573a6a429a1e7a8c9.jpg",
                    "https://media.rawg.io/media/screenshots/3e1/3e13e1780b4d343d30edd2e561e7cef0.jpg",
                    "https://media.rawg.io/media/screenshots/1e3/1e3aab17c0ccbaad6ca8e5ba6bb15ced.jpg",
                } },
            new Game { Platform = "PC",    Title = "Elden Ring",         Genre = "Action RPG",  Rating = 9.6, AddedAt = "2025-02-14T09:30:00Z", Description = "A sprawling fantasy action RPG from FromSoftware and George R.R. Martin. Journey through the Lands Between and become the Elden Lord.",          CoverColor = "#1c0a00", CoverGradient = "#1c0a00,#6e2400",
                CoverUrl    = "https://media.rawg.io/media/games/b45/b45575f34285f2c4479c9a5f719d972e.jpg",
                Screenshots = new() {
                    "https://media.rawg.io/media/screenshots/3b8/3b8c388a3cf0a3e28db9b3b9ddaad4b4.jpg",
                    "https://media.rawg.io/media/screenshots/fd8/fd8c19f8a09e4de50a4bcdc8e7be58ef.jpg",
                } },
            new Game { Platform = "PC",    Title = "Baldur's Gate 3",    Genre = "RPG",         Rating = 9.8, AddedAt = "2025-03-01T15:00:00Z", Description = "Gather your party and return to the Forgotten Realms in this award-winning DnD RPG by Larian Studios.",             CoverColor = "#0d1b2a", CoverGradient = "#0d1b2a,#1b4332",
                CoverUrl    = "https://media.rawg.io/media/games/618/618c2031a07bbff6b4f611f10b6bcdbc.jpg",
                Screenshots = new() {
                    "https://media.rawg.io/media/screenshots/66e/66e3bdfc14d00047a0a8bd5e0b4c1a95.jpg",
                    "https://media.rawg.io/media/screenshots/0e4/0e4543e2ea80f7ec3e56fac7a1fee02e.jpg",
                } },
            new Game { Platform = "Xbox",  Title = "Halo Infinite",      Genre = "FPS",         Rating = 8.5, AddedAt = "2025-01-20T11:00:00Z", Description = "Master Chief returns in this epic sci-fi FPS. Forge your own path across a mysterious Forerunner ringworld.",        CoverColor = "#003153", CoverGradient = "#003153,#0056a8",
                CoverUrl    = "https://media.rawg.io/media/games/3ea/3ea3c9bbd940b6cb7f2139e42d3d443f.jpg",
                Screenshots = new() {
                    "https://media.rawg.io/media/screenshots/2bc/2bcb1a3ea1e91f6e069ea09f2d9b2ba7.jpg",
                    "https://media.rawg.io/media/screenshots/e6b/e6b89c7e6be26499bc5c0e35540b60de.jpg",
                } },
            new Game { Platform = "PS5",   Title = "God of War Ragnarök", Genre = "Action",     Rating = 9.7, AddedAt = "2025-02-05T08:00:00Z", Description = "Kratos and Atreus must journey to each of the Nine Realms in search of answers as Asgardian forces prepare for the prophesied battle.",      CoverColor = "#1a0a00", CoverGradient = "#1a0a00,#8b0000",
                CoverUrl    = "https://media.rawg.io/media/games/fc1/fc1307a2774506b5bd65d7e8424664a7.jpg",
                Screenshots = new() {
                    "https://media.rawg.io/media/screenshots/26b/26b58ce3e99e14e06f94b5bc9e37bded.jpg",
                    "https://media.rawg.io/media/screenshots/4a7/4a754e4f9e4b4c50855ebc3e5e9b5edb.jpg",
                } },
            new Game { Platform = "PC",    Title = "Hogwarts Legacy",    Genre = "RPG",         Rating = 8.7, AddedAt = "2025-04-01T10:00:00Z", Description = "Explore an open-world Hogwarts in this immersive action RPG. Uncover a hidden truth about the wizarding world.",             CoverColor = "#1e0a2a", CoverGradient = "#1e0a2a,#4a0080",
                CoverUrl    = "https://media.rawg.io/media/games/5ec/5ecac5cb026ec26a56efcc546364e348.jpg" },
            new Game { Platform = "Switch", Title = "Zelda: TOTK",       Genre = "Adventure",   Rating = 9.9, AddedAt = "2025-04-15T14:00:00Z", Description = "Link discovers a mysterious power that lets him explore the skies and depths of Hyrule, encountering a secret in the clouds.",
                CoverColor = "#0a1628", CoverGradient = "#0a1628,#1a4a6e",
                CoverUrl    = "https://assets.nintendo.com/image/upload/ar_16:9,b_auto:border,c_lpad/b_white/f_auto/q_auto/dpr_auto/c_scale,w_300/ncom/software/switch/70010000063714/791ffa4ce68e0a0f99e5e8c6c58c0c0d7c29a32cd9a7a83c51d5e8f97c6a29a" },
            new Game { Platform = "PC",    Title = "Starfield",          Genre = "RPG",         Rating = 7.9, AddedAt = "2025-05-10T09:00:00Z", Description = "Bethesda Game Studios' first new universe in 25 years. Create any character and explore the vast reaches of the galaxy.",           CoverColor = "#05060f", CoverGradient = "#05060f,#1a1a3e",
                CoverUrl    = "https://media.rawg.io/media/games/fd9/fd91fdea4f93fe71c2ff8c965c4eca74.jpg" },
        };

        public static List<StoreGame> Store { get; } = new()
        {
            // Featured
            new StoreGame { Title = "Mario Kart 8 Deluxe",           Platform = "Switch", Genre = "Racing",       Price = "£49.99", Rating = 9.7, IsFeatured = true,  ReleaseYear = "2017", Description = "Hit the road with the definitive version of Mario Kart 8! Race on 96 total courses with friends online or locally.",
                CoverUrl = "https://assets.nintendo.com/image/upload/ar_16:9,b_auto:border,c_lpad/b_white/f_auto/q_auto/dpr_auto/c_scale,w_300/ncom/software/switch/70010000000153/b9248571a2c8cfc3ea62a6f9cf0e4219f2b9e7e5b87a38af51286aa5f18f7b0",
                CoverColor = "#c00000", CoverGradient = "#c00000,#ff6b00" },
            new StoreGame { Title = "GTA VI",                         Platform = "PC",     Genre = "Open World",   Price = "£69.99", Rating = 9.5, IsFeatured = true,  ReleaseYear = "2026", Description = "Rockstar's long-awaited return to Vice City with Lucia leading an epic crime saga.",
                CoverUrl = "https://media.rawg.io/media/games/2ad/2ad87a4a69b1104f02435c14c5196095.jpg",
                CoverColor = "#0a1628", CoverGradient = "#0a1628,#1a3a6e" },
            new StoreGame { Title = "The Elder Scrolls VI",           Platform = "PC",     Genre = "RPG",          Price = "£59.99", Rating = 9.3, IsFeatured = true,  ReleaseYear = "2026", Description = "Bethesda's next open-world fantasy epic set across Tamriel's uncharted lands.",
                CoverColor = "#1a0c00", CoverGradient = "#1a0c00,#5c3a00" },
            new StoreGame { Title = "Call of Duty 2025",              Platform = "PC",     Genre = "FPS",          Price = "£69.99", Rating = 8.2, IsFeatured = true,  ReleaseYear = "2025", Description = "The latest entry in the blockbuster CoD franchise with next-gen multiplayer.",
                CoverColor = "#0c0c0c", CoverGradient = "#0c0c0c,#2a2a2a" },
            // New releases
            new StoreGame { Title = "Hollow Knight: Silksong",        Platform = "PC",     Genre = "Metroidvania", Price = "£14.99", Rating = 9.4, IsFeatured = false, ReleaseYear = "2025", Description = "Hornet's long-awaited adventure continues in a vast kingdom teeming with bugs.",
                CoverUrl = "https://media.rawg.io/media/games/4a0/4a0a1316102366260e6f38fd2a9cfdce.jpg",
                CoverColor = "#120021", CoverGradient = "#120021,#3a0057" },
            new StoreGame { Title = "Star Wars Outlaws",               Platform = "PC",     Genre = "Action",       Price = "£54.99", Rating = 8.0, IsFeatured = false, ReleaseYear = "2025", Description = "The first open-world Star Wars game. Kay Vess fights to earn freedom across the galaxy.",
                CoverUrl = "https://media.rawg.io/media/games/d82/d82fcb52ab66cb18bc6dc7900a8f9c22.jpg",
                CoverColor = "#05060f", CoverGradient = "#05060f,#0a1628" },
            new StoreGame { Title = "Metaphor: ReFantazio",            Platform = "PC",     Genre = "RPG",          Price = "£54.99", Rating = 9.3, IsFeatured = false, ReleaseYear = "2025", Description = "Atlus' new epic fantasy RPG where humanity's survival rests on a magical election.",
                CoverColor = "#1a0028", CoverGradient = "#1a0028,#5a0090",
                CoverUrl = "https://media.rawg.io/media/games/5c0/5c0ba33e9cfc3e7e5ce0c6b3c8b7bcc6.jpg" },
            new StoreGame { Title = "Monster Hunter Wilds",            Platform = "PC",     Genre = "Action RPG",   Price = "£54.99", Rating = 9.2, IsFeatured = false, ReleaseYear = "2025", Description = "Hunt massive monsters in breathtaking living ecosystems that shift with the seasons.",
                CoverUrl = "https://media.rawg.io/media/games/618/618c2031a07bbff6b4f611f10b6bcdbc.jpg",
                CoverColor = "#1c0a00", CoverGradient = "#1c0a00,#6b2800" },
            new StoreGame { Title = "Warhammer 40K: Space Marine 2",  Platform = "PC",     Genre = "Action",       Price = "£44.99", Rating = 8.9, IsFeatured = false, ReleaseYear = "2025", Description = "Fight for the Emperor as an Ultramarine Space Marine in brutal third-person combat.",
                CoverUrl = "https://media.rawg.io/media/games/b4b/b4b43c4c5f17ea9de5c9d27e0c0c0a30.jpg",
                CoverColor = "#0a0c0a", CoverGradient = "#0a0c0a,#1a2e1a" },
            new StoreGame { Title = "Dragon Age: Veilguard",          Platform = "PC",     Genre = "RPG",          Price = "£49.99", Rating = 8.6, IsFeatured = false, ReleaseYear = "2025", Description = "BioWare returns to Thedas. Lead a party of heroes to stop the ancient elven gods.",
                CoverUrl = "https://media.rawg.io/media/games/b45/b45575f34285f2c4479c9a5f719d972e.jpg",
                CoverColor = "#1a0028", CoverGradient = "#1a0028,#4a0057" },
            new StoreGame { Title = "Avowed",                         Platform = "PC",     Genre = "RPG",          Price = "£49.99", Rating = 8.4, IsFeatured = false, ReleaseYear = "2025", Description = "Obsidian Entertainment's first-person RPG set in the Living Lands of Eora.",
                CoverUrl = "https://media.rawg.io/media/games/3ea/3ea3c9bbd940b6cb7f2139e42d3d443f.jpg",
                CoverColor = "#0a1420", CoverGradient = "#0a1420,#1a3040" },
            new StoreGame { Title = "Doom: The Dark Ages",            Platform = "PC",     Genre = "FPS",          Price = "£49.99", Rating = 9.0, IsFeatured = false, ReleaseYear = "2025", Description = "The Doom Slayer returns in a prequel set in the brutal medieval realm of the Dark Ages.",
                CoverUrl = "https://media.rawg.io/media/games/fc1/fc1307a2774506b5bd65d7e8424664a7.jpg",
                CoverColor = "#1a0000", CoverGradient = "#1a0000,#5a0000" },
            new StoreGame { Title = "Like a Dragon: Pirate Yakuza",  Platform = "PC",     Genre = "RPG",          Price = "£49.99", Rating = 8.7, IsFeatured = false, ReleaseYear = "2025", Description = "Majima has lost his memory and become a pirate captain in this wild action RPG.",
                CoverUrl = "https://media.rawg.io/media/games/fd9/fd91fdea4f93fe71c2ff8c965c4eca74.jpg",
                CoverColor = "#001a28", CoverGradient = "#001a28,#003a5a" },
        };
    }
}
