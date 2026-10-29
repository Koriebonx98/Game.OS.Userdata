using Avalonia.Controls;

namespace GameLauncher.Views.GamesLib;

public partial class SwitchGamesLib : UserControl
{
    public SwitchGamesLib()
    {
        InitializeComponent();
    }

    public void FocusSearchBox() => this.FindControl<TextBox>("LibrarySearchBox")?.Focus();
}
