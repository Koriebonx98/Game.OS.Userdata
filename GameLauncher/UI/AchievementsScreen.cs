using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Spectre.Console;
using GameLauncher.Models;

namespace GameLauncher.UI
{
    internal static class AchievementsScreen
    {
        public static Task ShowAsync(
            UserProfile profile,
            List<Achievement> achievements)
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine("[bold cyan]Game.OS Launcher[/]  [grey]›  Achievements[/]");
            AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

            if (achievements.Count == 0)
            {
                AnsiConsole.MarkupLine("[grey]  No achievements unlocked yet. Keep playing![/]\n");
                AnsiConsole.MarkupLine("[grey]  Press any key to return…[/]");
                Console.ReadKey(true);
                return Task.CompletedTask;
            }

            AnsiConsole.MarkupLine($"[bold]🏆  ACHIEVEMENTS[/]  [grey]({achievements.Count} unlocked)[/]\n");

            var byGame = achievements
                .GroupBy(a => a.GameTitle)
                .OrderBy(g => g.Key)
                .ToList();

            foreach (var group in byGame)
            {
                AnsiConsole.MarkupLine($"[bold yellow]{Markup.Escape(group.Key)}[/]  " +
                                       $"[grey]({group.Count()} achievement{(group.Count() == 1 ? "" : "s")})[/]");

                var table = new Table()
                    .Border(TableBorder.Simple)
                    .BorderStyle(Style.Parse("grey"))
                    .Expand();

                table.AddColumn(new TableColumn("[bold]Achievement[/]"));
                table.AddColumn(new TableColumn("[bold]Description[/]"));
                table.AddColumn(new TableColumn("[bold]Platform[/]").Centered().Width(12));
                table.AddColumn(new TableColumn("[bold]Unlocked[/]").Width(16));

                foreach (var a in group.OrderByDescending(a => a.UnlockedAt))
                {
                    string unlocked = DateTimeOffset.TryParse(a.UnlockedAt, out var dt)
                        ? dt.ToString("dd MMM yyyy")
                        : a.UnlockedAt;

                    table.AddRow(
                        $"[yellow]🏆 {Markup.Escape(a.Name)}[/]",
                        $"[grey]{Markup.Escape(a.Description)}[/]",
                        DashboardScreen.PlatformBadge(a.Platform),
                        $"[grey]{unlocked}[/]"
                    );
                }

                AnsiConsole.Write(table);
                AnsiConsole.WriteLine();
            }

            AnsiConsole.MarkupLine("[grey]Press any key to return…[/]");
            Console.ReadKey(true);
            return Task.CompletedTask;
        }
    }
}
