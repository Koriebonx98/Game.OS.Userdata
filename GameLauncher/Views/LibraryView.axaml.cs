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
        var box = this.FindControl<TextBox>("LibrarySearchBox");
        box?.Focus();
    }
}
