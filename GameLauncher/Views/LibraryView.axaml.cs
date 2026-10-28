using Avalonia.Controls;

namespace GameLauncher.Views;

public partial class LibraryView : UserControl
{
    public LibraryView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, System.EventArgs e)
    {
        if (DataContext is ViewModels.LibraryViewModel vm)
            vm.FocusSearchRequested = FocusSearchBox;
    }

    private void FocusSearchBox()
    {
        if (DataContext is ViewModels.LibraryViewModel { IsPs5GamesLib: true })
            this.FindControl<GamesLib.Ps5GamesLib>("Ps5Lib")?.FocusSearchBox();
        else
            this.FindControl<GamesLib.DefaultGamesLib>("DefaultLib")?.FocusSearchBox();
    }
}
