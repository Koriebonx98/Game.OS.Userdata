using Avalonia.Controls;

namespace GameLauncher.Views.GamesLib;

public partial class SteamGamesLib : UserControl
{
    public SteamGamesLib()
    {
        InitializeComponent();
    }

    public void FocusSearchBox() => this.FindControl<TextBox>("LibrarySearchBox")?.Focus();
}
