using Avalonia.Controls;

namespace GameLauncher.Views.GamesLib;

public partial class DefaultGamesLib : UserControl
{
    public DefaultGamesLib()
    {
        InitializeComponent();
    }

    public void FocusSearchBox() => this.FindControl<TextBox>("LibrarySearchBox")?.Focus();
}
