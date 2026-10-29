using Avalonia.Controls;

namespace GameLauncher.Views.GamesLib;

public partial class WiiGamesLib : UserControl
{
    public WiiGamesLib()
    {
        InitializeComponent();
    }

    public void FocusSearchBox() => this.FindControl<TextBox>("LibrarySearchBox")?.Focus();
}
