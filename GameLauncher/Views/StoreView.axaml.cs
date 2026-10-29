using System.Linq;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class StoreView : UserControl
{
    private StoreViewModel? _vm;

    public StoreView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, System.EventArgs e)
    {
        _vm = DataContext as StoreViewModel;
        if (_vm == null) return;
        _vm.FocusSearchRequested = () => _vm.OpenKeyboard();
        _vm.ColumnsProvider = GetColumns;
        _vm.ScrollFocusedIntoView = () => Dispatcher.UIThread.Post(BringFocusedIntoView, DispatcherPriority.Background);
    }

    private void OnFiltersClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e) => _vm?.OpenFilterMenu();
    private void OnKeyboardClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e) => _vm?.OpenKeyboard();

    private Control? ActiveRoot() => this.FindControl<Control>(
        _vm is { IsSonyStore: true }     ? "Ps5StoreView" :
        _vm is { IsXboxStore: true }     ? "XboxStoreView" :
        _vm is { IsNintendoStore: true } ? "NintendoStoreView" :
                                           "DefaultStoreView");

    /// <summary>The visible card grid (the WrapPanel of the active tab).</summary>
    private WrapPanel? CardPanel() => ActiveRoot()?.GetVisualDescendants()
        .OfType<WrapPanel>().FirstOrDefault(p => p.IsEffectivelyVisible && p.Children.Count > 0);

    private int GetColumns()
    {
        var panel = CardPanel();
        if (panel == null || panel.Children.Count == 0) return 1;
        var first = panel.Children[0];
        double slot = first.Bounds.Width + first.Margin.Left + first.Margin.Right;
        return slot <= 0 ? 1 : System.Math.Max(1, (int)(panel.Bounds.Width / slot));
    }

    private void BringFocusedIntoView()
    {
        var panel = CardPanel();
        if (panel == null) return;
        foreach (var child in panel.Children)
        {
            if (child.DataContext is Models.IStoreFocusable { IsFocused: true } ||
                child.GetVisualDescendants().OfType<Control>().Any(c => c.Classes.Contains("focused")))
            {
                child.BringIntoView();
                return;
            }
        }
    }
}
