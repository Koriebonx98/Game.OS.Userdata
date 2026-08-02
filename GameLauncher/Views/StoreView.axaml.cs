using Avalonia.Controls;
using GameLauncher.ViewModels;

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
            vm.FocusSearchRequested = FocusSearchBox;
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
