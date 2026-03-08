using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Spectre.Console;
using GameLauncher.Models;

namespace GameLauncher.UI
{
    internal static class DashboardScreen
    {
        public static async Task<string> ShowAsync(
            UserProfile profile,
            List<Game> library,
            List<Achievement> achievements,
            bool demoMode)
        {
            AnsiConsole.Clear();

            // ── Header bar ────────────────────────────────────────────────────
            var headerTable = new Table().NoBorder().Expand();
            headerTable.AddColumn(new TableColumn("[bold cyan]Game.OS Launcher[/]").LeftAligned());
            headerTable.AddColumn(new TableColumn($"[bold grey]👤 {Markup.Escape(profile.Username)}[/]  [grey]{(demoMode ? "[yellow]DEMO MODE[/]" : "LIVE")}[/]").RightAligned());
            AnsiConsole.Write(headerTable);
            AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]");

            // ── Stats row ─────────────────────────────────────────────────────
            DrawStatsRow(library, achievements);
            AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

            // ── Recent games ──────────────────────────────────────────────────
            DrawRecentGames(library);

            // ── Recent achievements ───────────────────────────────────────────
            DrawRecentAchievements(achievements);

            AnsiConsole.MarkupLine("\n[grey]───────────────────────────────────────────────────────────────────────────[/]");

            // ── Navigation menu ───────────────────────────────────────────────
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[bold]Main Menu[/]")
                    .AddChoices(
                        "🎮  My Library",
                        "🛒  Games Store",
                        "🏆  Achievements",
                        "👤  Profile",
                        "🚪  Sign Out"));

            return choice.Substring(0, 2).Trim();
        }

        private static void DrawStatsRow(List<Game> library, List<Achievement> achievements)
        {
            var statsGrid = new Grid().Expand();
            statsGrid.AddColumn();
            statsGrid.AddColumn();
            statsGrid.AddColumn();
            statsGrid.AddColumn();

            var platforms = library.GroupBy(g => g.Platform).ToList();
            string platformSummary = platforms.Count == 0
                ? "—"
                : string.Join(", ", platforms.Select(p => $"{p.Key} ({p.Count()})"));

            statsGrid.AddRow(
                new Panel($"[bold cyan]{library.Count}[/]\n[grey]Games[/]").NoBorder(),
                new Panel($"[bold yellow]{achievements.Count}[/]\n[grey]Achievements[/]").NoBorder(),
                new Panel($"[bold green]{platforms.Count}[/]\n[grey]Platforms[/]").NoBorder(),
                new Panel($"[bold magenta]{GetTotalPlaytime(library)}h[/]\n[grey]Playtime[/]").NoBorder()
            );

            AnsiConsole.Write(statsGrid);
        }

        private static void DrawRecentGames(List<Game> library)
        {
            if (library.Count == 0)
            {
                AnsiConsole.MarkupLine("[grey]  No games in library yet. Visit the Games Store to add some![/]\n");
                return;
            }

            AnsiConsole.MarkupLine("[bold]🎮  RECENTLY ADDED[/]");

            var recent = library
                .OrderByDescending(g => g.AddedAt)
                .Take(5)
                .ToList();

            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderStyle(Style.Parse("grey"))
                .Expand();

            table.AddColumn(new TableColumn("[bold]Title[/]").Width(30));
            table.AddColumn(new TableColumn("[bold]Platform[/]").Centered().Width(12));
            table.AddColumn(new TableColumn("[bold]Genre[/]").Width(14));
            table.AddColumn(new TableColumn("[bold]Rating[/]").Centered().Width(10));
            table.AddColumn(new TableColumn("[bold]Added[/]").Width(16));

            foreach (var g in recent)
            {
                string rating = g.Rating.HasValue
                    ? $"[yellow]★ {g.Rating:F1}[/]"
                    : "[grey]—[/]";

                string added = DateTimeOffset.TryParse(g.AddedAt, out var dt)
                    ? dt.ToString("dd MMM yyyy")
                    : g.AddedAt;

                table.AddRow(
                    $"[bold white]{Markup.Escape(g.Title)}[/]",
                    PlatformBadge(g.Platform),
                    $"[grey]{Markup.Escape(g.Genre ?? "—")}[/]",
                    rating,
                    $"[grey]{added}[/]"
                );
            }

            AnsiConsole.Write(table);
        }

        private static void DrawRecentAchievements(List<Achievement> achievements)
        {
            if (achievements.Count == 0) return;

            AnsiConsole.MarkupLine("[bold]🏆  RECENT ACHIEVEMENTS[/]");

            var recent = achievements
                .OrderByDescending(a => a.UnlockedAt)
                .Take(3)
                .ToList();

            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderStyle(Style.Parse("grey"))
                .Expand();

            table.AddColumn(new TableColumn("[bold]Achievement[/]"));
            table.AddColumn(new TableColumn("[bold]Game[/]").Width(24));
            table.AddColumn(new TableColumn("[bold]Platform[/]").Centered().Width(12));
            table.AddColumn(new TableColumn("[bold]Unlocked[/]").Width(16));

            foreach (var a in recent)
            {
                string unlocked = DateTimeOffset.TryParse(a.UnlockedAt, out var dt)
                    ? dt.ToString("dd MMM yyyy")
                    : a.UnlockedAt;

                table.AddRow(
                    $"[yellow]🏆 {Markup.Escape(a.Name)}[/]",
                    $"[grey]{Markup.Escape(a.GameTitle)}[/]",
                    PlatformBadge(a.Platform),
                    $"[grey]{unlocked}[/]"
                );
            }

            AnsiConsole.Write(table);
        }

        // ── Helpers ───────────────────────────────────────────────────────────
        internal static string PlatformBadge(string platform) => platform.ToUpper() switch
        {
            "PC"   => "[blue]🖥  PC[/]",
            "XBOX" => "[green]🟢 Xbox[/]",
            "PS5"  => "[blue]🔵 PS5[/]",
            "PS4"  => "[blue]🔵 PS4[/]",
            "SWITCH" => "[red]🔴 Switch[/]",
            _      => $"[grey]{Markup.Escape(platform)}[/]"
        };

        private static int GetTotalPlaytime(List<Game> library)
        {
            // Approximate playtime from demo data (not stored in basic profile)
            return library.Count * 12;
        }
    }
}
