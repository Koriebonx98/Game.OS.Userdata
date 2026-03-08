using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Spectre.Console;
using GameLauncher.Models;

namespace GameLauncher.UI
{
    internal static class StoreScreen
    {
        public static async Task ShowAsync(
            UserProfile profile,
            List<Game> library,
            List<StoreGame> store,
            bool demoMode,
            GameOsClient client)
        {
            while (true)
            {
                AnsiConsole.Clear();
                AnsiConsole.MarkupLine("[bold cyan]Game.OS Launcher[/]  [grey]›  Games Store[/]");
                AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

                // ── Featured banner ───────────────────────────────────────────
                DrawFeaturedBanner(store);

                // ── Browse options ────────────────────────────────────────────
                var action = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[bold]Store Menu[/]")
                        .AddChoices(
                            "🔥  Browse All Games",
                            "🔍  Search by Title",
                            "🏷   Browse by Genre",
                            "⬅  Back to Dashboard"));

                if (action.StartsWith("⬅")) return;

                if (action.StartsWith("🔥"))
                    await BrowseAllAsync(store, library, profile, demoMode, client);
                else if (action.StartsWith("🔍"))
                    await SearchAsync(store, library, profile, demoMode, client);
                else if (action.StartsWith("🏷"))
                    await BrowseByGenreAsync(store, library, profile, demoMode, client);
            }
        }

        // ── Featured banner ───────────────────────────────────────────────────
        private static void DrawFeaturedBanner(List<StoreGame> store)
        {
            var featured = store.Where(g => g.IsFeatured).ToList();
            if (featured.Count == 0) return;

            AnsiConsole.MarkupLine("[bold yellow]⭐  FEATURED & NEW RELEASES[/]");

            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderStyle(Style.Parse("yellow"))
                .Expand();

            table.AddColumn(new TableColumn("[bold]Title[/]"));
            table.AddColumn(new TableColumn("[bold]Platform[/]").Centered().Width(10));
            table.AddColumn(new TableColumn("[bold]Genre[/]").Width(14));
            table.AddColumn(new TableColumn("[bold]Rating[/]").Centered().Width(10));
            table.AddColumn(new TableColumn("[bold]Price[/]").RightAligned().Width(10));

            foreach (var g in featured)
            {
                table.AddRow(
                    $"[bold white]{Markup.Escape(g.Title)}[/]  [yellow]NEW[/]",
                    DashboardScreen.PlatformBadge(g.Platform),
                    $"[grey]{Markup.Escape(g.Genre)}[/]",
                    $"[yellow]★ {g.Rating:F1}[/]",
                    $"[green]{Markup.Escape(g.Price)}[/]"
                );
            }

            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();
        }

        // ── Browse all ────────────────────────────────────────────────────────
        private static async Task BrowseAllAsync(
            List<StoreGame> store, List<Game> library,
            UserProfile profile, bool demoMode, GameOsClient client)
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine("[bold cyan]Game.OS Launcher[/]  [grey]›  Store  ›  All Games[/]");
            AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

            DrawFullCatalogue(store, library);

            AnsiConsole.MarkupLine("\n[grey]───────────────────────────────────────────────────────────────────────────[/]");

            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .AddChoices("➕  Add game to library", "⬅  Back"));

            if (choice.StartsWith("➕"))
                await AddGameFlowAsync(store, library, profile, demoMode, client);
        }

        // ── Search ────────────────────────────────────────────────────────────
        private static async Task SearchAsync(
            List<StoreGame> store, List<Game> library,
            UserProfile profile, bool demoMode, GameOsClient client)
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine("[bold cyan]Game.OS Launcher[/]  [grey]›  Store  ›  Search[/]");
            AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

            string query = AnsiConsole.Ask<string>("[grey]Search games:[/] ");
            var results  = store
                .Where(g => g.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
                         || g.Genre.Contains(query, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (results.Count == 0)
            {
                AnsiConsole.MarkupLine($"\n[yellow]No results for \"{Markup.Escape(query)}\".[/]\n");
            }
            else
            {
                AnsiConsole.MarkupLine($"\n[bold]{results.Count} result(s) for \"{Markup.Escape(query)}\"[/]\n");
                DrawFullCatalogue(results, library);

                AnsiConsole.MarkupLine("\n[grey]───────────────────────────────────────────────────────────────────────────[/]");
                var choice = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .AddChoices("➕  Add game to library", "⬅  Back"));

                if (choice.StartsWith("➕"))
                    await AddGameFlowAsync(results, library, profile, demoMode, client);

                return;
            }

            AnsiConsole.MarkupLine("[grey]Press any key to return…[/]");
            Console.ReadKey(true);
        }

        // ── Browse by genre ───────────────────────────────────────────────────
        private static async Task BrowseByGenreAsync(
            List<StoreGame> store, List<Game> library,
            UserProfile profile, bool demoMode, GameOsClient client)
        {
            AnsiConsole.Clear();
            var genres = store.Select(g => g.Genre).Distinct().OrderBy(g => g).ToList();
            genres.Insert(0, "← Back");

            var selectedGenre = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[grey]Select a genre:[/]")
                    .AddChoices(genres));

            if (selectedGenre == "← Back") return;

            var filtered = store.Where(g => g.Genre == selectedGenre).ToList();

            AnsiConsole.Clear();
            AnsiConsole.MarkupLine($"[bold cyan]Game.OS Launcher[/]  [grey]›  Store  ›  {Markup.Escape(selectedGenre)}[/]");
            AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

            DrawFullCatalogue(filtered, library);

            AnsiConsole.MarkupLine("\n[grey]───────────────────────────────────────────────────────────────────────────[/]");
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .AddChoices("➕  Add game to library", "⬅  Back"));

            if (choice.StartsWith("➕"))
                await AddGameFlowAsync(filtered, library, profile, demoMode, client);
        }

        // ── Add game flow ─────────────────────────────────────────────────────
        private static async Task AddGameFlowAsync(
            List<StoreGame> catalogue, List<Game> library,
            UserProfile profile, bool demoMode, GameOsClient client)
        {
            var available = catalogue
                .Where(s => !library.Any(l =>
                    string.Equals(l.Title, s.Title, StringComparison.OrdinalIgnoreCase)))
                .Select(g => g.Title)
                .Concat(new[] { "← Cancel" })
                .ToArray();

            var selected = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[grey]Select a game to add:[/]")
                    .AddChoices(available));

            if (selected == "← Cancel") return;

            var storeGame = catalogue.First(g => g.Title == selected);

            if (demoMode)
            {
                // Demo mode: add locally without GitHub API
                library.Add(new Game
                {
                    Platform    = storeGame.Platform,
                    Title       = storeGame.Title,
                    Genre       = storeGame.Genre,
                    Rating      = storeGame.Rating,
                    Description = storeGame.Description,
                    AddedAt     = DateTimeOffset.UtcNow.ToString("o")
                });
                AnsiConsole.MarkupLine($"\n[green]✓ '{Markup.Escape(storeGame.Title)}' added to your library![/]");
                await Task.Delay(1000);
                return;
            }

            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("[cyan]Adding game…[/]", async ctx =>
                {
                    try
                    {
                        await client.AddGameAsync(
                            profile.Username, storeGame.Platform, storeGame.Title);

                        library.Add(new Game
                        {
                            Platform    = storeGame.Platform,
                            Title       = storeGame.Title,
                            Genre       = storeGame.Genre,
                            Rating      = storeGame.Rating,
                            Description = storeGame.Description,
                            AddedAt     = DateTimeOffset.UtcNow.ToString("o")
                        });
                        AnsiConsole.MarkupLine(
                            $"\n[green]✓ '{Markup.Escape(storeGame.Title)}' added to your library![/]");
                    }
                    catch (GameOsException ex)
                    {
                        AnsiConsole.MarkupLine($"\n[red]✗ {Markup.Escape(ex.Message)}[/]");
                    }
                });

            await Task.Delay(1000);
        }

        // ── Table renderer ─────────────────────────────────────────────────────
        private static void DrawFullCatalogue(List<StoreGame> games, List<Game> library)
        {
            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderStyle(Style.Parse("grey"))
                .Expand();

            table.AddColumn(new TableColumn("[bold]Title[/]"));
            table.AddColumn(new TableColumn("[bold]Platform[/]").Centered().Width(10));
            table.AddColumn(new TableColumn("[bold]Genre[/]").Width(14));
            table.AddColumn(new TableColumn("[bold]Year[/]").Centered().Width(8));
            table.AddColumn(new TableColumn("[bold]Rating[/]").Centered().Width(10));
            table.AddColumn(new TableColumn("[bold]Price[/]").RightAligned().Width(10));
            table.AddColumn(new TableColumn("[bold]Owned[/]").Centered().Width(8));

            foreach (var g in games.OrderByDescending(g => g.Rating))
            {
                bool owned = library.Any(l =>
                    string.Equals(l.Title, g.Title, StringComparison.OrdinalIgnoreCase));

                table.AddRow(
                    $"[bold white]{Markup.Escape(g.Title)}[/]",
                    DashboardScreen.PlatformBadge(g.Platform),
                    $"[grey]{Markup.Escape(g.Genre)}[/]",
                    $"[grey]{g.ReleaseYear}[/]",
                    $"[yellow]★ {g.Rating:F1}[/]",
                    owned ? "[grey dim]—[/]" : $"[green]{Markup.Escape(g.Price)}[/]",
                    owned ? "[green]✓[/]" : "[grey]—[/]"
                );
            }

            AnsiConsole.Write(table);
        }
    }
}
