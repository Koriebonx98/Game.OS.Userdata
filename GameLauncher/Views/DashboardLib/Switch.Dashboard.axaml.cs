using Avalonia.Controls;
using Avalonia.Input;
using GameLauncher.ViewModels;

namespace GameLauncher.Views.DashboardLib;

public partial class SwitchDashboard : UserControl
{
    public SwitchDashboard()
    {
        InitializeComponent();
    }

    private void OnTileEnter(object? sender, PointerEventArgs e)
    {
        if (DataContext is DashboardViewModel vm && (sender as Control)?.DataContext is LocalGameCardVm card)
            vm.SwitchHoverCard = card;
    }

    private void OnTileExit(object? sender, PointerEventArgs e)
    {
        if (DataContext is DashboardViewModel vm) vm.SwitchHoverCard = null;
    }
}
