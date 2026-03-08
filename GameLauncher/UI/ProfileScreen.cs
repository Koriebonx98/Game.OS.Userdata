using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Spectre.Console;
using GameLauncher.Models;

namespace GameLauncher.UI
{
    internal static class ProfileScreen
    {
        public static Task ShowAsync(
            UserProfile profile,
            List<Game> library,
            List<Achievement> achievements,
            bool demoMode)
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine("[bold cyan]Game.OS Launcher[/]  [grey]›  Profile[/]");
            AnsiConsole.MarkupLine("[grey]───────────────────────────────────────────────────────────────────────────[/]\n");

            // ── Avatar banner ─────────────────────────────────────────────────
            string initial = profile.Username.Length > 0
                ? profile.Username[0].ToString().ToUpper()
                : "?";

            AnsiConsole.Write(
                new Panel(
                    new Rows(
                        new Markup($"[bold cyan]  {initial}  [/]"),
                        new Markup($"[bold white]{Markup.Escape(profile.Username)}[/]"),
                        new Markup($"[grey]{Markup.Escape(profile.Email)}[/]")
                    )
                )
                {
                    Header  = new PanelHeader("[bold]👤 Player Profile[/]"),
                    Border  = BoxBorder.Rounded,
                    Padding = new Padding(3, 1)
                });

            AnsiConsole.WriteLine();

            // ── Stats ─────────────────────────────────────────────────────────
            var statsTable = new Table()
                .Border(TableBorder.Rounded)
                .BorderStyle(Style.Parse("grey"))
                .Expand();

            statsTable.AddColumn(new TableColumn("[bold]Stat[/]").Width(24));
            statsTable.AddColumn(new TableColumn("[bold]Value[/]"));

            statsTable.AddRow("[grey]Username[/]",    $"[white]{Markup.Escape(profile.Username)}[/]");
            statsTable.AddRow("[grey]Email[/]",       $"[white]{Markup.Escape(profile.Email)}[/]");
            statsTable.AddRow("[grey]Member Since[/]",
                DateTimeOffset.TryParse(profile.CreatedAt, out var dt)
                    ? $"[white]{dt:dd MMM yyyy}[/]"
                    : $"[white]{Markup.Escape(profile.CreatedAt)}[/]");
            statsTable.AddRow("[grey]Games in Library[/]", $"[cyan]{library.Count}[/]");
            statsTable.AddRow("[grey]Achievements[/]",      $"[yellow]{achievements.Count}[/]");
            statsTable.AddRow("[grey]Mode[/]",              demoMode ? "[yellow]Demo[/]" : "[green]Live[/]");

            AnsiConsole.Write(statsTable);

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[grey]Press any key to return…[/]");
            Console.ReadKey(true);
            return Task.CompletedTask;
        }
    }
}
