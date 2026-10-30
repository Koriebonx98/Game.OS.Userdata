using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
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
    }

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
