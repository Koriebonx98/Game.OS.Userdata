using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Spectre.Console;
using GameLauncher.Models;

namespace GameLauncher.UI
{
    internal static class LibraryScreen
    {
        public static async Task ShowAsync(
            UserProfile profile,
            List<Game> library,
            bool demoMode)
        {
            while (true)
            {
                AnsiConsole.Clear();
                AnsiConsole.MarkupLine("[bold cyan]Game.OS Launcher[/]  [grey]›  My Library[/]");
                AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

                if (library.Count == 0)
                {
                    AnsiConsole.MarkupLine("[grey]  Your library is empty. Visit the Games Store to add games![/]\n");
                    AnsiConsole.MarkupLine("[grey]  Press any key to return…[/]");
                    Console.ReadKey(true);
                    return;
                }

                // ── Filter bar ────────────────────────────────────────────────
                var platformFilter = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[grey]Filter by platform:[/]")
                        .AddChoices(new[] { "All" }
                            .Concat(library.Select(g => g.Platform).Distinct().OrderBy(p => p))
                            .ToArray()));

                var filtered = platformFilter == "All"
                    ? library
                    : library.Where(g => g.Platform == platformFilter).ToList();

                AnsiConsole.Clear();
                AnsiConsole.MarkupLine("[bold cyan]Game.OS Launcher[/]  [grey]›  My Library[/]");
                AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");
                AnsiConsole.MarkupLine($"[bold]🎮  MY LIBRARY[/]  [grey]({filtered.Count} games{(platformFilter != "All" ? $" · {platformFilter}" : "")})[/]\n");

                DrawLibraryTable(filtered);

                AnsiConsole.MarkupLine("\n[grey]───────────────────────────────────────────────────────────────────────────[/]");

                var action = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .AddChoices(
                            "🔍  View game details",
                            "⬅  Back to Dashboard"));

                if (action.StartsWith("⬅")) return;

                if (action.StartsWith("🔍"))
                    await ShowGameDetailsAsync(filtered, profile, demoMode);
            }
        }

        private static void DrawLibraryTable(List<Game> games)
        {
            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderStyle(Style.Parse("grey"))
                .Expand();

            table.AddColumn(new TableColumn("[bold]#[/]").Centered().Width(4));
            table.AddColumn(new TableColumn("[bold]Title[/]"));
            table.AddColumn(new TableColumn("[bold]Platform[/]").Centered().Width(12));
            table.AddColumn(new TableColumn("[bold]Genre[/]").Width(16));
            table.AddColumn(new TableColumn("[bold]Rating[/]").Centered().Width(10));
            table.AddColumn(new TableColumn("[bold]Added[/]").Width(16));

            int i = 1;
            foreach (var g in games.OrderByDescending(g => g.AddedAt))
            {
                string rating = g.Rating.HasValue
                    ? RatingBar(g.Rating.Value)
                    : "[grey]—[/]";

                string added = DateTimeOffset.TryParse(g.AddedAt, out var dt)
                    ? dt.ToString("dd MMM yyyy")
                    : g.AddedAt;

                table.AddRow(
                    $"[grey]{i++}[/]",
                    $"[bold white]{Markup.Escape(g.Title)}[/]",
                    DashboardScreen.PlatformBadge(g.Platform),
                    $"[grey]{Markup.Escape(g.Genre ?? "—")}[/]",
                    rating,
                    $"[grey]{added}[/]"
                );
            }

            AnsiConsole.Write(table);
        }

        private static async Task ShowGameDetailsAsync(
            List<Game> games, UserProfile profile, bool demoMode)
        {
            var titles = games.Select(g => g.Title).Concat(new[] { "← Back" }).ToArray();

            var selected = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[grey]Select a game:[/]")
                    .AddChoices(titles));

            if (selected == "← Back") return;

            var game = games.FirstOrDefault(g => g.Title == selected);
            if (game == null) return;

            AnsiConsole.Clear();
            AnsiConsole.MarkupLine("[bold cyan]Game.OS Launcher[/]  [grey]›  Library  ›  Game Details[/]");
            AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

            var panel = new Panel(
                new Rows(
                    new Markup($"[bold yellow]{Markup.Escape(game.Title)}[/]"),
                    new Markup($"[grey]Platform:[/]  {DashboardScreen.PlatformBadge(game.Platform)}"),
                    new Markup($"[grey]Genre:[/]     [white]{Markup.Escape(game.Genre ?? "—")}[/]"),
                    new Markup(game.Rating.HasValue
                        ? $"[grey]Rating:[/]    [yellow]★ {game.Rating:F1} / 10[/]  {RatingBar(game.Rating.Value)}"
                        : "[grey]Rating:    —[/]"),
                    new Markup($"\n[grey]{Markup.Escape(game.Description ?? "No description available.")}[/]"),
                    new Markup($"\n[grey dim]Added: {game.AddedAt}[/]")
                )
            )
            {
                Header  = new PanelHeader("[bold]Game Details[/]"),
                Border  = BoxBorder.Rounded,
                Padding = new Padding(2, 1)
            };

            AnsiConsole.Write(panel);

            AnsiConsole.MarkupLine("\n[grey]Press any key to return…[/]");
            Console.ReadKey(true);
        }

        private static string RatingBar(double rating)
        {
            int filled = (int)Math.Round(rating / 2.0);
            string stars = new string('★', filled) + new string('☆', 5 - filled);
            string color = rating >= 9.0 ? "green" : rating >= 7.0 ? "yellow" : "red";
            return $"[{color}]{stars}[/] [grey]{rating:F1}[/]";
        }
    }
}
