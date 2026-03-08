using System;
using System.Threading.Tasks;
using Spectre.Console;
using GameLauncher.Models;

namespace GameLauncher.UI
{
    internal static class LoginScreen
    {
        public static async Task<(UserProfile? profile, bool demoMode)> ShowAsync(GameOsClient client)
        {
            while (true)
            {
                AnsiConsole.Clear();
                DrawLogo();

                var choice = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[bold grey]Welcome to [cyan]Game.OS Launcher[/][/]")
                        .AddChoices(
                            "🎮  Sign In",
                            "📝  Create Account",
                            "🚀  Demo Mode  [grey](no GitHub account needed)[/]",
                            "❌  Exit"));

                if (choice.StartsWith("❌"))
                    return (null, false);

                if (choice.StartsWith("🚀"))
                {
                    client.DemoMode = true;
                    // Auto-login as "Demo" user
                    try
                    {
                        var demoProfile = await client.LoginAsync("Demo", "demo123");
                        AnsiConsole.MarkupLine("\n[green]✓ Demo mode activated! Logging in as Demo...[/]");
                        await Task.Delay(1200);
                        return (demoProfile, true);
                    }
                    catch
                    {
                        // Fallback: create an in-memory profile
                        var fallback = new UserProfile
                        {
                            Username  = "Demo",
                            Email     = "demo@gameos.local",
                            CreatedAt = DateTimeOffset.UtcNow.ToString("o")
                        };
                        return (fallback, true);
                    }
                }

                if (choice.StartsWith("🎮"))
                {
                    var profile = await SignInAsync(client);
                    if (profile != null) return (profile, client.DemoMode);
                }
                else if (choice.StartsWith("📝"))
                {
                    var profile = await RegisterAsync(client);
                    if (profile != null) return (profile, client.DemoMode);
                }
            }
        }

        // ── Sign-in form ──────────────────────────────────────────────────────
        private static async Task<UserProfile?> SignInAsync(GameOsClient client)
        {
            AnsiConsole.Clear();
            DrawLogo();
            AnsiConsole.MarkupLine("[bold cyan]SIGN IN[/]\n");

            string usernameOrEmail = AnsiConsole.Ask<string>("[grey]Username or email:[/] ");
            string password        = AnsiConsole.Prompt(
                new TextPrompt<string>("[grey]Password:[/] ")
                    .PromptStyle("grey")
                    .Secret());

            UserProfile? profile = null;
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("[cyan]Signing in…[/]", async ctx =>
                {
                    try
                    {
                        profile = await client.LoginAsync(usernameOrEmail, password);
                    }
                    catch (GameOsException ex)
                    {
                        AnsiConsole.MarkupLine($"\n[red]✗ {Markup.Escape(ex.Message)}[/]");
                    }
                    catch (Exception ex)
                    {
                        AnsiConsole.MarkupLine($"\n[red]✗ Connection error: {Markup.Escape(ex.Message)}[/]");
                        AnsiConsole.MarkupLine("[yellow]Tip: Use 'Demo Mode' to run without a GitHub account.[/]");
                    }
                });

            if (profile != null)
            {
                AnsiConsole.MarkupLine($"\n[green]✓ Welcome back, {Markup.Escape(profile.Username)}![/]");
                await Task.Delay(1000);
            }
            else
            {
                AnsiConsole.MarkupLine("\n[grey]Press any key to return to the menu…[/]");
                Console.ReadKey(true);
            }

            return profile;
        }

        // ── Register form ─────────────────────────────────────────────────────
        private static async Task<UserProfile?> RegisterAsync(GameOsClient client)
        {
            AnsiConsole.Clear();
            DrawLogo();
            AnsiConsole.MarkupLine("[bold cyan]CREATE ACCOUNT[/]\n");

            string username = AnsiConsole.Prompt(
                new TextPrompt<string>("[grey]Username (letters & numbers only):[/] ")
                    .Validate(u =>
                        System.Text.RegularExpressions.Regex.IsMatch(u, @"^[A-Za-z0-9_]{3,24}$")
                            ? ValidationResult.Success()
                            : ValidationResult.Error("[red]Username must be 3–24 alphanumeric characters[/]")));

            string email = AnsiConsole.Prompt(
                new TextPrompt<string>("[grey]Email address:[/] ")
                    .Validate(e =>
                        e.Contains('@') && e.Contains('.')
                            ? ValidationResult.Success()
                            : ValidationResult.Error("[red]Please enter a valid email address[/]")));

            string password = AnsiConsole.Prompt(
                new TextPrompt<string>("[grey]Password (min 8 characters):[/] ")
                    .PromptStyle("grey")
                    .Secret()
                    .Validate(p =>
                        p.Length >= 8
                            ? ValidationResult.Success()
                            : ValidationResult.Error("[red]Password must be at least 8 characters[/]")));

            AnsiConsole.Prompt(
                new TextPrompt<string>("[grey]Confirm password:[/] ")
                    .PromptStyle("grey")
                    .Secret()
                    .Validate(p =>
                        p == password
                            ? ValidationResult.Success()
                            : ValidationResult.Error("[red]Passwords do not match[/]")));

            UserProfile? profile = null;
            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .StartAsync("[cyan]Creating account…[/]", async ctx =>
                {
                    try
                    {
                        profile = await client.RegisterAsync(username, email, password);
                    }
                    catch (GameOsException ex)
                    {
                        AnsiConsole.MarkupLine($"\n[red]✗ {Markup.Escape(ex.Message)}[/]");
                    }
                    catch (Exception ex)
                    {
                        AnsiConsole.MarkupLine($"\n[red]✗ {Markup.Escape(ex.Message)}[/]");
                    }
                });

            if (profile != null)
            {
                AnsiConsole.MarkupLine($"\n[green]✓ Account created! Welcome, {Markup.Escape(profile.Username)}![/]");
                await Task.Delay(1200);
            }
            else
            {
                AnsiConsole.MarkupLine("\n[grey]Press any key to return…[/]");
                Console.ReadKey(true);
            }

            return profile;
        }

        // ── ASCII logo ────────────────────────────────────────────────────────
        internal static void DrawLogo()
        {
            AnsiConsole.Write(
                new FigletText("Game.OS")
                    .Centered()
                    .Color(Color.CornflowerBlue));
            AnsiConsole.MarkupLine("[grey]  ─────────────────────────────────────────────[/]");
            AnsiConsole.MarkupLine("[grey]         Your games. Your world. Your OS.       [/]");
            AnsiConsole.MarkupLine("[grey]  ─────────────────────────────────────────────[/]\n");
        }
    }
}
