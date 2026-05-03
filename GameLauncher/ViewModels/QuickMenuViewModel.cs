using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using GameLauncher.Models;
using GameLauncher.Services;

namespace GameLauncher.ViewModels;

/// <summary>
/// View-model for the Quick Menu overlay (triggered by Left Shift + Left Ctrl).
/// Displays current session info, friends list, inbox preview, achievements, and
/// an "Exit Game" button that kills the tracked game process.
/// </summary>
public partial class QuickMenuViewModel : ViewModelBase
{
    // ── Current game info ──────────────────────────────────────────────────
    [ObservableProperty] private string _currentGameTitle    = "";
    [ObservableProperty] private string _currentSessionLabel = "Not playing";
    [ObservableProperty] private bool   _isPlayingGame;

    // ── Friends list ──────────────────────────────────────────────────────
    public ObservableCollection<FriendPresenceVm> OnlineFriends { get; } = new();
    [ObservableProperty] private bool _hasOnlineFriends;

    // ── Inbox preview ─────────────────────────────────────────────────────
    [ObservableProperty] private int    _unreadMessageCount;
    [ObservableProperty] private string _lastMessagePreview = "";
    [ObservableProperty] private bool   _hasUnreadMessages;

    // ── Achievements for current game ─────────────────────────────────────
    [ObservableProperty] private int    _achievementsUnlocked;
    [ObservableProperty] private int    _achievementsTotal;
    [ObservableProperty] private string _achievementsLabel = "";
    [ObservableProperty] private bool   _hasAchievementsProgress;

    // ── Exit game command callback ─────────────────────────────────────────
    /// <summary>Invoked when the user clicks "Exit Game" in the Quick Menu.</summary>
    public System.Action? OnExitGame { get; set; }

    /// <summary>Invoked when the Quick Menu should be dismissed.</summary>
    public System.Action? OnDismiss { get; set; }

    [RelayCommand]
    private void ExitGame()
    {
        OnExitGame?.Invoke();
        OnDismiss?.Invoke();
    }

    [RelayCommand]
    private void Dismiss() => OnDismiss?.Invoke();

    /// <summary>
    /// Refreshes the Quick Menu with the current session data.
    /// </summary>
    /// <param name="currentGameTitle">Title of the currently running game, or null if not playing.</param>
    /// <param name="sessionStartedAt">When the current session began (UTC), used to compute elapsed time.</param>
    /// <param name="friends">Current friend list with presence info.</param>
    /// <param name="unreadCount">Number of unread direct messages.</param>
    /// <param name="lastMessage">Preview text of the most recent unread message.</param>
    /// <param name="unlockedAchievements">Count of unlocked achievements for the current game.</param>
    /// <param name="totalAchievements">Total achievements available for the current game.</param>
    public void Refresh(
        string? currentGameTitle,
        System.DateTime? sessionStartedAt,
        System.Collections.Generic.IReadOnlyList<FriendPresenceVm> friends,
        int unreadCount,
        string? lastMessage,
        int unlockedAchievements,
        int totalAchievements)
    {
        IsPlayingGame      = !string.IsNullOrEmpty(currentGameTitle);
        CurrentGameTitle   = currentGameTitle ?? "";

        if (IsPlayingGame && sessionStartedAt.HasValue)
        {
            var elapsed = System.DateTime.UtcNow - sessionStartedAt.Value;
            int mins    = (int)elapsed.TotalMinutes;
            CurrentSessionLabel = mins < 60
                ? $"Playing for {mins}m"
                : $"Playing for {mins / 60}h {mins % 60}m";
        }
        else
        {
            CurrentSessionLabel = "Not playing";
        }

        OnlineFriends.Clear();
        foreach (var f in friends)
            OnlineFriends.Add(f);
        HasOnlineFriends = OnlineFriends.Count > 0;

        UnreadMessageCount = unreadCount;
        LastMessagePreview = lastMessage ?? "";
        HasUnreadMessages  = unreadCount > 0;

        AchievementsUnlocked     = unlockedAchievements;
        AchievementsTotal        = totalAchievements;
        HasAchievementsProgress  = totalAchievements > 0;
        AchievementsLabel        = totalAchievements > 0
            ? $"{unlockedAchievements} / {totalAchievements} unlocked"
            : "";
    }
}

/// <summary>A friend entry shown in the Quick Menu's friends list.</summary>
public class FriendPresenceVm
{
    public string Username    { get; set; } = "";
    public string CurrentGame { get; set; } = "";
    public bool   IsPlaying   => !string.IsNullOrEmpty(CurrentGame);
    public string StatusLabel => IsPlaying ? $"Playing {CurrentGame}" : "Online";
}
