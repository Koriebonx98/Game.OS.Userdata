using Avalonia.Controls;
using Avalonia.Input;
using GameLauncher.ViewModels;

namespace GameLauncher.Views.DashboardLib;

public partial class SwitchDashboard : UserControl
{
    public SwitchDashboard()
    {
        InitializeComponent();
        // The cover's natural size must never grow the layout (it would push the tile list out of view).
        SizeChanged += (_, e) =>
        {
            if (this.FindControl<Control>("BgCover") is { } bg)
            {
                bg.MaxWidth = e.NewSize.Width;
                bg.MaxHeight = e.NewSize.Height;
            }
        };
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
