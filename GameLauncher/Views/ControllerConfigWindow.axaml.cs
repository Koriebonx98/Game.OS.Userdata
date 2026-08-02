using System;
using Avalonia.Controls;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class ControllerConfigWindow : Window
{
    public ControllerConfigWindow()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Opens the window to create or manage controller profiles for the given game.
    /// Shows the "Default" profile on open; users can load any saved profile from the sidebar.
    /// </summary>
    public static void OpenFor(
        string platform,
        string gameTitle,
        string author,
        Window owner,
        System.Action<Models.ControllerProfile>? onProfileActivated = null)
    {
        OpenForProfile(platform, gameTitle, author, profileName: null, owner, onProfileActivated);
    }

    /// <summary>
    /// Opens the window pre-loaded with a specific named profile for editing.
    /// Falls back to the Default profile when <paramref name="profileName"/> is null or not found.
    /// </summary>
    public static void OpenForProfile(
        string platform,
        string gameTitle,
        string author,
        string? profileName,
        Window owner,
        System.Action<Models.ControllerProfile>? onProfileActivated = null)
    {
        var vm = new ControllerConfigViewModel();

        if (string.IsNullOrEmpty(profileName))
            vm.Load(platform, gameTitle, author);
        else
            vm.LoadForEdit(platform, gameTitle, author, profileName);

        var window = new ControllerConfigWindow { DataContext = vm };
        vm.OnProfileActivated = profile => onProfileActivated?.Invoke(profile);
        vm.OnClose = () => window.Close();

        // ShowDialog returns Task; fire-and-forget is intentional — the dialog
        // is self-contained and callers receive results via the callbacks above.
        _ = window.ShowDialog(owner);
    }
}
