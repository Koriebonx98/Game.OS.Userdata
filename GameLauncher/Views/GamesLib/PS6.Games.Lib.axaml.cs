using Avalonia.Controls;

namespace GameLauncher.Views.GamesLib;

public partial class Ps6GamesLib : UserControl
{
    public Ps6GamesLib()
    {
        InitializeComponent();
    }

    public void FocusSearchBox() => this.FindControl<TextBox>("LibrarySearchBox")?.Focus();
}
