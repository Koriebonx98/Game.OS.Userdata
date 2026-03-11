using Avalonia.Controls;
using Avalonia.Platform.Storage;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, System.EventArgs e)
    {
        if (DataContext is SettingsViewModel vm)
            vm.BrowseRequested = OnBrowseRequested;
    }

    private async void OnBrowseRequested(EmulatorRowVm row)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null) return;

        var files = await topLevel.StorageProvider.OpenFilePickerAsync(
            new FilePickerOpenOptions
            {
                Title = $"Select emulator for {row.Platform}",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("Executable")
                    {
                        Patterns = new[] { "*.exe", "*.bat", "*.sh", "*.AppImage" },
                    },
                    FilePickerFileTypes.All,
                },
            });

        if (files.Count > 0)
            row.EmulatorPath = files[0].Path.LocalPath;
    }
}
