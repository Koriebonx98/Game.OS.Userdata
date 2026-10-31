using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace GameLauncher.ViewModels;

/// <summary>One row of the controller-navigable action list shown by the Hub / Wii / Switch / Steam quick menus.</summary>
public partial class QuickMenuHubActionVm : ObservableObject
{
    public string Title { get; init; } = "";
    public string Subtitle { get; init; } = "";
    public string Glyph { get; init; } = "";
    /// <summary>Null for read-only rows (e.g. achievements); the cursor skips them.</summary>
    public Action? Run { get; init; }
    public bool IsActionable => Run != null;
    public ICommand ActivateCommand => new RelayCommand(() => Run?.Invoke());
    public bool HasSubtitle => !string.IsNullOrEmpty(Subtitle);
    [ObservableProperty] private bool _isCursor;
}

public partial class QuickMenuViewModel
{
    public ObservableCollection<QuickMenuHubActionVm> HubActions { get; } = new();
    [ObservableProperty] private int _hubActionIndex = -1;

    public bool UsesSwitchGuideLayout => IsSwitchTheme;
    public bool UsesSteamGuideLayout => IsSteamBpmTheme;
    public bool HasHubActions => HubActions.Count > 0;

    private bool _rebuildingHubActions;

    /// <summary>Rebuilds the action list for the active page (or the fixed Wii bubble row).</summary>
    public void RebuildHubActions()
    {
        if (_rebuildingHubActions) return;
        _rebuildingHubActions = true;
        try
        {
            HubActions.Clear();
            foreach (var a in BuildHubActions()) HubActions.Add(a);
            HubActionIndex = Array.FindIndex(HubActions.ToArray(), a => a.IsActionable);
            SyncHubCursor();
            OnPropertyChanged(nameof(HasHubActions));
        }
        finally { _rebuildingHubActions = false; }
    }

    partial void OnHubActionIndexChanged(int value) => SyncHubCursor();

    private void SyncHubCursor()
    {
        for (int i = 0; i < HubActions.Count; i++) HubActions[i].IsCursor = i == HubActionIndex;
    }

    private static QuickMenuHubActionVm Act(string glyph, string title, Action run, string sub = "") =>
        new() { Glyph = glyph, Title = title, Subtitle = sub, Run = run };

    private System.Collections.Generic.IEnumerable<QuickMenuHubActionVm> BuildHubActions()
    {
        if (IsWiiTheme)
        {
            yield return Act("🏠", "Home", () => GoToGameOsHomeCommand.Execute(null));
            yield return Act("🎮", "Recent", () => OpenLibraryPageCommand.Execute(null));
            yield return Act("👥", "Friends", () => OpenFriendsPageCommand.Execute(null));
            yield return Act("📬", "Inbox", () => OpenInboxPageCommand.Execute(null));
            yield return Act("🌐", "Browser", () => OpenBrowserCommand.Execute(null));
            if (IsPlayingGame) yield return Act("⏹", "Exit Game", () => ExitGameCommand.Execute(null));
            yield return Act("✕", "Close", () => DismissCommand.Execute(null));
            yield break;
        }

        switch (ActivePage)
        {
            case "home":
                yield return Act("▶", "Resume", () => DismissCommand.Execute(null));
                if (IsPlayingGame) yield return Act("⏹", "Exit Game", () => ExitGameCommand.Execute(null), CurrentGameTitle);
                if (HasAchievementsProgress) yield return Act("🏆", "Achievements", () => OpenAchievementsCommand.Execute(null), AchievementsLabel);
                yield return Act("⚙", "Settings", () => OpenSettingsPageCommand.Execute(null));
                break;
            case "switcher":
                foreach (var item in SwitcherItems.ToList())
                {
                    var captured = item;
                    yield return Act(captured.IsActive ? "✓" : "🗂", captured.Title,
                        () => OpenPageFromSwitcherCommand.Execute(captured), captured.Subtitle);
                }
                break;
            case "recent":
                foreach (var game in RecentGames.ToList())
                {
                    var captured = game;
                    yield return Act("🎮", captured.EffectiveTitle, () => LaunchRecentGameCommand.Execute(captured), captured.Platform);
                }
                if (RecentGames.Count == 0) yield return new QuickMenuHubActionVm { Glyph = "ℹ", Title = "No recent games found." };
                break;
            case "notifications":
                yield return new QuickMenuHubActionVm { Glyph = "🔔", Title = $"Unread messages: {UnreadMessageCount}", Subtitle = LastMessagePreview };
                yield return Act("📬", "Open Inbox", () => OpenNotificationsPageCommand.Execute(null));
                break;
            case "downloads":
                yield return new QuickMenuHubActionVm { Glyph = "⬇", Title = $"Ready installs / updates: {PendingDownloadCount}" };
                yield return Act("▦", "Open Library", () => OpenDownloadsPageCommand.Execute(null));
                break;
            case "friends":
                foreach (var f in QuickFriends.Take(4))
                {
                    var name = f.Username;
                    yield return Act("👤", $"View {name}", () => ViewFriendCommand.Execute(name), f.StatusLabel);
                    yield return Act("💬", $"Message {name}", () => MessageFriendCommand.Execute(name));
                }
                yield return Act("👥", "Open Friends Page", () => OpenFriendsPageCommand.Execute(null));
                break;
            case "inbox":
                yield return new QuickMenuHubActionVm { Glyph = "📬", Title = $"Unread messages: {UnreadMessageCount}", Subtitle = LastMessagePreview };
                yield return Act("📬", "Open Inbox Page", () => OpenInboxPageCommand.Execute(null));
                break;
            case "media":
                yield return Act("⏮", "Previous", () => MediaPreviousCommand.Execute(null));
                yield return Act("⏯", "Play / Pause", () => MediaPlayPauseCommand.Execute(null), MediaStatusProvider?.Invoke() ?? MediaStatusLabel);
                yield return Act("⏭", "Next", () => MediaNextCommand.Execute(null));
                yield return Act("⏪", "Skip Back", () => MediaSeekBackCommand.Execute(null));
                yield return Act("⏩", "Skip Forward", () => MediaSeekForwardCommand.Execute(null));
                yield return Act("⛶", "Full Screen Player", () => MediaFullScreenCommand.Execute(null));
                yield return Act("🎵", "Open Music", () => OpenMusicPageCommand.Execute(null));
                break;
            case "guides":
                yield return Act("🏠", "Home", () => GoToGameOsHomeCommand.Execute(null), "Dashboard");
                if (!IsPlayingGame)
                {
                    yield return new QuickMenuHubActionVm { Glyph = "ℹ", Title = "No game running.", Subtitle = "Start a game to see its saved walkthroughs." };
                    yield return Act("🌐", "Open Browser", () => OpenBrowserCommand.Execute(null));
                    break;
                }
                string gp = string.IsNullOrWhiteSpace(CurrentGamePlatform) ? "PC" : CurrentGamePlatform;
                string gt = CurrentGameTitle;
                var links = Services.GameLinksService.ForGame(gp, gt);
                var sections = new (string Title, Func<Services.GameLink, bool> Match)[]
                {
                    ("Walk Throughs", l => l.IsGuideLike),
                    ("Mods", l => l.Kind == Services.GameLink.KindMod),
                    ("Downloads", l => l.Kind == Services.GameLink.KindDownload),
                    ("Other", l => !l.IsGuideLike && l.Kind != Services.GameLink.KindMod && l.Kind != Services.GameLink.KindDownload),
                };
                foreach (var (sectionTitle, match) in sections)
                {
                    var inSection = links.Where(match).ToList();
                    if (inSection.Count == 0) continue;
                    yield return new QuickMenuHubActionVm { Glyph = "▾", Title = sectionTitle.ToUpperInvariant() };
                    foreach (var l in inSection)
                    {
                        var capturedLink = l;
                        yield return Act(capturedLink.Icon, capturedLink.Name, () => { OnOpenUrl?.Invoke(gp, gt, capturedLink.Url); OnRequestLauncherForeground?.Invoke(); OnDismiss?.Invoke(); }, capturedLink.Kind);
                    }
                }
                if (links.Count == 0)
                    yield return new QuickMenuHubActionVm { Glyph = "ℹ", Title = $"No saved links for {gt}.", Subtitle = "Open the browser from the game page to save walkthroughs." };
                yield return Act("🔍", "Search walkthrough", () => { OnOpenUrl?.Invoke(gp, gt, "https://duckduckgo.com/?q=" + Uri.EscapeDataString($"{gt} {gp} walkthrough")); OnRequestLauncherForeground?.Invoke(); OnDismiss?.Invoke(); });
                break;
            case "browser":
                yield return Act("🌐", "Open Browser", () => OpenBrowserCommand.Execute(null), "Open the built-in web browser.");
                break;
            case "power":
                yield return Act("↩", "Sign Out", () => PowerSignOutCommand.Execute(null));
                yield return Act("🔁", "Switch Account", () => PowerSwitchAccountCommand.Execute(null));
                yield return Act("⏻", "Exit App", () => PowerExitApplicationCommand.Execute(null));
                break;
            case "achievements":
                foreach (var a in Achievements.Take(8))
                    yield return new QuickMenuHubActionVm { Glyph = a.StatusIcon, Title = a.Name, Subtitle = a.Description };
                yield return Act("↩", "Back", () => SelectHomeCommand.Execute(null));
                break;
        }
    }

    /// <summary>Up / Down cursor inside the current page's action list (all four D-pad directions in the Wii bubble row).</summary>
    public void MoveHubItem(int delta)
    {
        if (IsXb360Theme || HubActions.Count == 0) return;
        int i = HubActionIndex;
        do
        {
            i += delta;
            if (i < 0 || i >= HubActions.Count) return;
        } while (!HubActions[i].IsActionable);
        HubActionIndex = i;
    }

    /// <summary>Runs the highlighted action. Returns false when there is none (caller falls back to page selection).</summary>
    private bool ActivateHubAction()
    {
        if (HubActionIndex < 0 || HubActionIndex >= HubActions.Count) return false;
        var run = HubActions[HubActionIndex].Run;
        if (run == null) return false;
        run();
        return true;
    }
}
