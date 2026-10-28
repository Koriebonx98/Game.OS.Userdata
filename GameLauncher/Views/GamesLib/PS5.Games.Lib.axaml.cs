using Avalonia.Controls;

namespace GameLauncher.Views.GamesLib;

public partial class Ps5GamesLib : UserControl
{
    public Ps5GamesLib()
    {
        InitializeComponent();
    }

    public void FocusSearchBox() => this.FindControl<TextBox>("LibrarySearchBox")?.Focus();
}
