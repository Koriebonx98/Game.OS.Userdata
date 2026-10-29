using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System.Linq;

namespace GameLauncher.Views.StoreLib;

public partial class StoreOverlays : UserControl
{
    public StoreOverlays()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is System.ComponentModel.INotifyPropertyChanged n)
                n.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == "FilterMenuIndex")
                        Dispatcher.UIThread.Post(ScrollFilterIntoView, DispatcherPriority.Background);
                };
        };
    }

    /// <summary>Keeps the highlighted filter row visible so the list scrolls with the selection.</summary>
    private void ScrollFilterIntoView()
    {
        var list = this.FindControl<ItemsControl>("FilterList");
        if (list == null) return;
        foreach (var row in list.GetVisualDescendants().OfType<Border>())
            if (row.Classes.Contains("hl")) { row.BringIntoView(); return; }
    }

    private void OnFilterRowTapped(object? sender, Avalonia.Input.TappedEventArgs e)
    {
        if (DataContext is not GameLauncher.ViewModels.StoreViewModel vm ||
            (sender as Control)?.DataContext is not GameLauncher.ViewModels.StoreViewModel.FilterMenuItem item) return;
        int i = vm.FilterMenuItems.IndexOf(item);
        if (i < 0) return;
        vm.MoveFilterMenu(i - vm.FilterMenuIndex);
        vm.ApplyFilterMenuSelection();
    }

    private void OnKeyTapped(object? sender, Avalonia.Input.TappedEventArgs e)
    {
        if (DataContext is not GameLauncher.ViewModels.StoreViewModel vm ||
            (sender as Control)?.DataContext is not GameLauncher.ViewModels.StoreViewModel.KeyboardKeyVm key) return;
        for (int r = 0; r < vm.KeyboardRowItems.Count; r++)
        {
            int c = vm.KeyboardRowItems[r].Keys.IndexOf(key);
            if (c < 0) continue;
            vm.MoveKeyboard(r - vm.KeyboardRow, 0);
            vm.MoveKeyboard(0, c - vm.KeyboardCol);
            vm.PressKeyboardKey();
            return;
        }
    }

    private void OnCloseOverlay(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is not GameLauncher.ViewModels.StoreViewModel vm) return;
        vm.CloseFilterMenu();
        vm.CloseKeyboard();
    }
}
