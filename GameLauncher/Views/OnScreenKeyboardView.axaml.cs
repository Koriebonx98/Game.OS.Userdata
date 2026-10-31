using Avalonia.Controls;
using Avalonia.Input;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class OnScreenKeyboardView : UserControl
{
    public OnScreenKeyboardView() => InitializeComponent();

    private void OnKeyTapped(object? sender, TappedEventArgs e)
    {
        if (DataContext is OnScreenKeyboardViewModel kb && (sender as Control)?.DataContext is OsKeyVm key)
            kb.PressTapped(key);
    }
}
