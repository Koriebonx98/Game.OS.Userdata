using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace GameLauncher.ViewModels;

/// <summary>One slot of the Wii Menu channel grid: a game, or an empty slot when <see cref="Card"/> is null.</summary>
public partial class WiiChannelVm : ObservableObject
{
    public LocalGameCardVm? Card { get; init; }
    public bool IsEmpty => Card == null;
    public bool HasCard => Card != null;
    [ObservableProperty] private bool _isFocused;
}

public class WiiPageDotVm : ObservableObject
{
    private bool _isActive;
    public bool IsActive { get => _isActive; set => SetProperty(ref _isActive, value); }
}

/// <summary>
/// Wii Menu dashboard: one page of 4×3 channels (recently played). Pressing Right past the last column
/// slides on to the Library page, which uses the user's chosen Games design (Wii.Games.Lib.axaml for "Wii").
/// </summary>
public partial class DashboardViewModel
{
    public const int WiiColumns = 4;
    public const int WiiRows = 3;
    private const int WiiPageSize = WiiColumns * WiiRows;

    public ObservableCollection<WiiChannelVm> WiiChannels { get; } = new();
    public ObservableCollection<WiiPageDotVm> WiiPageDots { get; } = new()
    {
        new WiiPageDotVm { IsActive = true }, new WiiPageDotVm()
    };

    [ObservableProperty] private int _wiiFocusIndex;

    public string WiiPageTitle => "Recently Played";

    /// <summary>True when the first column is highlighted (Left then opens the nav menu).</summary>
    public bool IsAtWiiLeftEdge => WiiFocusIndex % WiiColumns == 0;

    private void RebuildWiiPages()
    {
        var cards = RecentLocalGames.Take(WiiPageSize).ToList();
        WiiChannels.Clear();
        for (int i = 0; i < WiiPageSize; i++)
            WiiChannels.Add(new WiiChannelVm { Card = i < cards.Count ? cards[i] : null });
        SetWiiFocus(WiiFocusIndex);
    }

    private void SetWiiFocus(int index)
    {
        index = Math.Clamp(index, 0, Math.Max(0, WiiChannels.Count - 1));
        WiiFocusIndex = index;
        for (int i = 0; i < WiiChannels.Count; i++) WiiChannels[i].IsFocused = i == index;
        OnPropertyChanged(nameof(IsAtWiiLeftEdge));
    }

    /// <summary>D-pad: moves the highlight; Right past the last column opens the Library page.</summary>
    /// <returns>False when Left was pressed on the first column (caller opens the nav menu).</returns>
    public bool MoveWiiFocus(int dCol, int dRow)
    {
        if (WiiChannels.Count == 0) return dCol >= 0;
        int col = WiiFocusIndex % WiiColumns, row = WiiFocusIndex / WiiColumns;
        if (dCol < 0 && col == 0) return false;
        if (dCol > 0 && col == WiiColumns - 1) { OnNavigateToLibrary?.Invoke(); return true; }
        SetWiiFocus(Math.Clamp(row + dRow, 0, WiiRows - 1) * WiiColumns + Math.Clamp(col + dCol, 0, WiiColumns - 1));
        return true;
    }

    [RelayCommand]
    private void WiiNextPage() => OnNavigateToLibrary?.Invoke();

    /// <summary>A: open the highlighted channel's info page. Empty slots do nothing.</summary>
    public void OpenWiiFocused()
    {
        if (WiiFocusIndex < WiiChannels.Count && WiiChannels[WiiFocusIndex].Card is { } c)
            OnOpenFocusedCardDetail?.Invoke(c);
    }

    /// <summary>X: launch the highlighted channel's game.</summary>
    public void PlayWiiFocused()
    {
        if (WiiFocusIndex < WiiChannels.Count && WiiChannels[WiiFocusIndex].Card is { } c)
            OnPlayFocusedCard?.Invoke(c);
    }

    [RelayCommand]
    private void OpenWiiChannel(WiiChannelVm? channel)
    {
        if (channel?.Card == null) return;
        SetWiiFocus(WiiChannels.IndexOf(channel));
        OnOpenFocusedCardDetail?.Invoke(channel.Card);
    }
}
