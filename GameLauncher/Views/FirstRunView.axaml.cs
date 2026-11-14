using System;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class FirstRunView : UserControl
{
    public FirstRunView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is FirstRunViewModel vm) vm.BrowseFolderRequested = OnBrowseFolder;
        };
    }

    private async void OnBrowseFolder(Action<string> apply)
    {
        var top = TopLevel.GetTopLevel(this);
        if (top == null) return;
        var folders = await top.StorageProvider.OpenFolderPickerAsync(
            new FolderPickerOpenOptions { Title = "Select your emulators folder", AllowMultiple = false });
        if (folders.Count > 0) apply(folders[0].Path.LocalPath);
    }
}
