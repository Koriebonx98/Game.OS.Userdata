using Avalonia.Controls;
using Avalonia.Input;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        KeyDown += OnKeyDown;
    }

    /// <summary>
    /// Handles global keyboard navigation.
    /// Xbox / PlayStation controllers connected via XInput/DirectInput are reported
    /// as standard keyboard keys by Windows:
    ///   Escape / B-button  → close overlays
    ///   PageUp  / LB       → navigate to previous sidebar page
    ///   PageDown / RB      → navigate to next sidebar page
    /// </summary>
    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not MainViewModel vm) return;

        switch (e.Key)
        {
            // Navigate back from a detail or friend-profile overlay
            case Key.Escape:
                if (vm.ShowDetail)
                {
                    vm.DetailVm.CloseCommand.Execute(null);
                    e.Handled = true;
                }
                else if (vm.ShowFriendProfile)
                {
                    vm.CloseFriendProfileCommand.Execute(null);
                    e.Handled = true;
                }
                break;

            // LB / PageUp → previous sidebar section
            case Key.PageUp:
                if (!vm.ShowDetail && !vm.ShowFriendProfile)
                {
                    NavigatePrev(vm);
                    e.Handled = true;
                }
                break;

            // RB / PageDown → next sidebar section
            case Key.PageDown:
                if (!vm.ShowDetail && !vm.ShowFriendProfile)
                {
                    NavigateNext(vm);
                    e.Handled = true;
                }
                break;
        }
    }

    private static readonly string[] _navPages =
        ["dashboard", "library", "store", "friends", "profile", "settings"];

    private static void NavigatePrev(MainViewModel vm)
    {
        int idx = System.Array.IndexOf(_navPages, vm.ActivePage);
        if (idx > 0)
            vm.NavigateCommand.Execute(_navPages[idx - 1]);
    }

    private static void NavigateNext(MainViewModel vm)
    {
        int idx = System.Array.IndexOf(_navPages, vm.ActivePage);
        if (idx >= 0 && idx < _navPages.Length - 1)
            vm.NavigateCommand.Execute(_navPages[idx + 1]);
    }
}
