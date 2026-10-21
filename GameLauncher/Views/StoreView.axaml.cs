using Avalonia.Controls;
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
    }

    private void OnDataContextChanged(object? sender, System.EventArgs e)
    {
        if (DataContext is StoreViewModel vm)
        {
            vm.FocusSearchRequested = FocusSearchBox;
            vm.FocusStoreGameRequested = FocusStoreGame;
        }
    }

    private void FocusStoreGame(StoreGame game)
    {
        var button = this.GetVisualDescendants()
            .OfType<Button>()
            .FirstOrDefault(candidate => ReferenceEquals(candidate.DataContext, game));
        button?.Focus();
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
