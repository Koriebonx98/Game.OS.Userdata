using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using GameLauncher.ViewModels;

namespace GameLauncher.Views.DashboardLib;

public partial class Ps5Dashboard : UserControl
{
    public Ps5Dashboard()
    {
        InitializeComponent();
        // PointerEntered does not bubble, so watch pointer movement and resolve the card under the mouse.
        AddHandler(PointerMovedEvent, OnPointerMoved, RoutingStrategies.Bubble, handledEventsToo: true);
        DataContextChanged += (_, _) =>
        {
            if (_vm != null) _vm.Ps5ShelfFocusChanged -= ScrollShelfFocusIntoView;
            _vm = DataContext as DashboardViewModel;
            if (_vm != null) _vm.Ps5ShelfFocusChanged += ScrollShelfFocusIntoView;
        };
    }

    private DashboardViewModel? _vm;

    // The shelf is wider than the window: keep the highlighted card on screen as the D-pad moves along it.
    private void ScrollShelfFocusIntoView() =>
        Dispatcher.UIThread.Post(() =>
            this.GetVisualDescendants().OfType<Button>()
                .FirstOrDefault(b => b.IsVisible && b.Classes.Contains("focused")
                                     && b.DataContext is DashboardViewModel.ShelfCardVm)?.BringIntoView(),
            DispatcherPriority.Background);

    private void OnPointerMoved(object? sender, PointerEventArgs e)
    {
        if (DataContext is not DashboardViewModel vm) return;
        var button = (e.Source as Visual)?.FindAncestorOfType<Button>(includeSelf: true);
        if (button == null) return;

        if (button.Tag is "store") vm.HoverCard(-1);
        else if (button.Tag is "all") vm.HoverCard(vm.Ps5RecentGames.Count);
        else if (button.DataContext is LocalGameCardVm card)
        {
            int idx = vm.Ps5RecentGames.IndexOf(card);
            if (idx >= 0) vm.HoverCard(idx);
        }
    }
}
