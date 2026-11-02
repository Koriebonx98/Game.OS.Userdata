using Avalonia.Controls;

namespace GameLauncher.Views.GamesLib;

public partial class XbOneGamesLib : UserControl
{
    public XbOneGamesLib()
    {
        InitializeComponent();
    }

    public void FocusSearchBox() => this.FindControl<TextBox>("LibrarySearchBox")?.Focus();
}
