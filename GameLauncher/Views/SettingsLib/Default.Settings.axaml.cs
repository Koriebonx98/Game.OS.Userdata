using Avalonia.Controls;

namespace GameLauncher.Views.SettingsLib;

public partial class DefaultSettings : UserControl
{
    public DefaultSettings()
    {
        InitializeComponent();
    }

    private async void OnCopyStreamAddressClicked(object? sender, Avalonia.Interactivity.RoutedEventArgs e) =>
        await CopyStreamValueAsync(vm => vm.StreamAddress);

    private async void OnCopyStreamPinClicked(object? sender, Avalonia.Interactivity.RoutedEventArgs e) =>
        await CopyStreamValueAsync(vm => vm.StreamPin);

    private async System.Threading.Tasks.Task CopyStreamValueAsync(System.Func<GameLauncher.ViewModels.SettingsViewModel, string> getValue)
    {
        if (DataContext is not GameLauncher.ViewModels.SettingsViewModel vm ||
            TopLevel.GetTopLevel(this)?.Clipboard is not { } clipboard)
            return;

        try
        {
            await clipboard.SetTextAsync(getValue(vm));
            vm.StreamCopyStatus = "Copied to clipboard.";
        }
        catch
        {
            vm.StreamCopyStatus = "Could not access the clipboard.";
        }
    }
}
