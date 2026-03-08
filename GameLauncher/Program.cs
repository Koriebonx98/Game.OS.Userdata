using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Spectre.Console;
using GameLauncher;
using GameLauncher.Models;
using GameLauncher.UI;

// ── Entry point ───────────────────────────────────────────────────────────────
Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.Title = "Game.OS Launcher";

// Detect whether to start in demo mode automatically
// (no GAMEOS_PAT env var → demo mode; env var present → live mode available)
bool hasPat = !string.IsNullOrWhiteSpace(
    Environment.GetEnvironmentVariable("GAMEOS_PAT"));

using var client = new GameOsClient(demoMode: !hasPat);

// ── Login / Register ──────────────────────────────────────────────────────────
var (profile, demoMode) = await LoginScreen.ShowAsync(client);
if (profile == null)
{
    AnsiConsole.MarkupLine("[grey]Goodbye![/]");
    return;
}

// ── Load data ─────────────────────────────────────────────────────────────────
List<Game>        library      = new();
List<Achievement> achievements = new();

await AnsiConsole.Status()
    .Spinner(Spinner.Known.Dots)
    .StartAsync("[cyan]Loading your data…[/]", async ctx =>
    {
        if (demoMode)
        {
            library      = new List<Game>(DemoData.Library);
            achievements = new List<Achievement>(DemoData.Achievements);
        }
        else
        {
            try
            {
                var (g, _) = await client.GetGamesAsync(profile.Username);
                var (a, _) = await client.GetAchievementsAsync(profile.Username);
                library      = g ?? new List<Game>();
                achievements = a ?? new List<Achievement>();
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine(
                    $"[yellow]⚠ Could not load data: {Markup.Escape(ex.Message)}[/]");
                library      = new List<Game>();
                achievements = new List<Achievement>();
            }
        }
    });

// ── Main navigation loop ──────────────────────────────────────────────────────
while (true)
{
    string nav = await DashboardScreen.ShowAsync(profile, library, achievements, demoMode);

    switch (nav)
    {
        case "🎮":
            await LibraryScreen.ShowAsync(profile, library, demoMode);
            break;

        case "🛒":
            await StoreScreen.ShowAsync(
                profile, library, DemoData.Store, demoMode, client);
            break;

        case "🏆":
            await AchievementsScreen.ShowAsync(profile, achievements);
            break;

        case "👤":
            await ProfileScreen.ShowAsync(profile, library, achievements, demoMode);
            break;

        case "🚪":
            client.Logout();
            AnsiConsole.Clear();
            LoginScreen.DrawLogo();
            AnsiConsole.MarkupLine($"[grey]Goodbye, {Markup.Escape(profile.Username)}! See you next time.[/]\n");
            await Task.Delay(800);
            return;
    }
}
