using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.VisualTree;
using GameLauncher.Models;
using GameLauncher.ViewModels;
using System.Linq;

namespace GameLauncher.Views;

public partial class StoreView : UserControl
{
    public StoreView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        SizeChanged += (_, _) => UpdateStoreGridColumns();
    }

    private void OnDataContextChanged(object? sender, System.EventArgs e)
    {
        if (DataContext is StoreViewModel vm)
        {
            vm.FocusSearchRequested = FocusSearchBox;
            vm.FocusStoreGameRequested = FocusStoreGame;
            UpdateStoreGridColumns();
        }
    }

    private void UpdateStoreGridColumns()
    {
        if (DataContext is StoreViewModel vm)
            vm.UpdateStoreGridColumnCount(Bounds.Width);
    }

    private void OnStorePointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (DataContext is StoreViewModel vm)
            vm.ClearStoreGameFocus();
    }

    private void FocusStoreGame(StoreGame game)
    {
        var button = this.GetVisualDescendants()
            .OfType<Button>()
            .FirstOrDefault(candidate => ReferenceEquals(candidate.DataContext, game));
        if (button != null)
        {
            button.Focus();
            button.BringIntoView();
        }
    }

    private void FocusSearchBox()
    {
        // Focus whichever search box is currently visible
        var gamesBox = this.FindControl<TextBox>("StoreSearchBox");
        var appsBox  = this.FindControl<TextBox>("AppStoreSearchBox");
        if (gamesBox?.IsVisible == true)
            gamesBox.Focus();
        else
            appsBox?.Focus();
    }
}
