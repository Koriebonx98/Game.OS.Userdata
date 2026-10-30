using System.Linq;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using GameLauncher.ViewModels;

namespace GameLauncher.Views.DashboardLib;

public partial class DefaultDashboard : UserControl
{
    private DashboardViewModel? _vm;

    public DefaultDashboard()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_vm != null) _vm.DefaultFocusChanged -= ScrollFocusedIntoView;
            _vm = DataContext as DashboardViewModel;
            if (_vm != null) _vm.DefaultFocusChanged += ScrollFocusedIntoView;
        };
    }

    // Keeps the controller highlight visible when it moves to a row below the fold.
    private void ScrollFocusedIntoView() =>
        Dispatcher.UIThread.Post(() =>
            this.GetVisualDescendants().OfType<Button>()
                .FirstOrDefault(b => b.IsVisible && b.Classes.Contains("focused"))?.BringIntoView(),
            DispatcherPriority.Background);
}
