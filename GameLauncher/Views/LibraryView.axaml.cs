using System.Linq;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;

namespace GameLauncher.Views;

public partial class LibraryView : UserControl
{
    private ViewModels.LibraryViewModel? _vm;

    public LibraryView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, System.EventArgs e)
    {
        if (_vm != null) _vm.PropertyChanged -= OnVmPropertyChanged;
        _vm = DataContext as ViewModels.LibraryViewModel;
        if (_vm == null) return;
        _vm.FocusSearchRequested = FocusSearchBox;
        _vm.ColumnsProvider = GetColumns;
        _vm.PropertyChanged += OnVmPropertyChanged;
    }

    private void OnVmPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ViewModels.LibraryViewModel.FocusedGameIndex))
            Dispatcher.UIThread.Post(BringFocusedIntoView, DispatcherPriority.Background);
    }

    private Control? ActiveLib() => _vm is { IsPs5GamesLib: true }
        ? this.FindControl<GamesLib.Ps5GamesLib>("Ps5Lib")
        : this.FindControl<GamesLib.DefaultGamesLib>("DefaultLib");

    private WrapPanel? CardPanel() =>
        ActiveLib()?.GetVisualDescendants().OfType<WrapPanel>().FirstOrDefault();

    /// <summary>Cards per row, measured from the live card panel so Up/Down match the screen.</summary>
    private int GetColumns()
    {
        var panel = CardPanel();
        if (panel == null || panel.Children.Count == 0) return 1;
        var first = panel.Children[0];
        double slot = first.Bounds.Width + first.Margin.Left + first.Margin.Right;
        if (slot <= 0) return 1;
        return System.Math.Max(1, (int)(panel.Bounds.Width / slot));
    }

    private void BringFocusedIntoView()
    {
        var panel = CardPanel();
        int i = _vm?.FocusedGameIndex ?? -1;
        if (panel != null && i >= 0 && i < panel.Children.Count)
            panel.Children[i].BringIntoView();
    }

    private void FocusSearchBox()
    {
        if (DataContext is ViewModels.LibraryViewModel { IsPs5GamesLib: true })
            this.FindControl<GamesLib.Ps5GamesLib>("Ps5Lib")?.FocusSearchBox();
        else
            this.FindControl<GamesLib.DefaultGamesLib>("DefaultLib")?.FocusSearchBox();
    }
}
