using System.Linq;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using GameLauncher.ViewModels;

namespace GameLauncher.Views.DashboardLib;

public partial class SteamBpmDashboard : UserControl
{
    private DashboardViewModel? _vm;

    public SteamBpmDashboard()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_vm != null) _vm.SteamFocusChanged -= ScrollFocusedIntoView;
            _vm = DataContext as DashboardViewModel;
            if (_vm != null) _vm.SteamFocusChanged += ScrollFocusedIntoView;
        };
    }

    // Keeps the controller highlight visible when it moves along a row that is wider than the window.
    private void ScrollFocusedIntoView() =>
        Dispatcher.UIThread.Post(() =>
            this.GetVisualDescendants().OfType<Button>()
                .FirstOrDefault(b => b.IsVisible && b.Classes.Contains("steam-focused")
                                     && !b.Classes.Contains("steam-tab-pill"))?.BringIntoView(),
            DispatcherPriority.Background);
}
