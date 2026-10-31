using System.ComponentModel;
using Avalonia.Controls;
using Avalonia.Threading;
using GameLauncher.ViewModels;

namespace GameLauncher.Views.QuickMenuLib;

public partial class Xb360QuickMenu : UserControl
{
    private QuickMenuViewModel? _vm;

    public Xb360QuickMenu()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_vm != null) _vm.PropertyChanged -= OnVmPropertyChanged;
            _vm = DataContext as QuickMenuViewModel;
            if (_vm != null) _vm.PropertyChanged += OnVmPropertyChanged;
        };
    }

    // Keep the controller cursor visible inside the scrolling lists.
    private void OnVmPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_vm == null) return;
        if (e.PropertyName == nameof(QuickMenuViewModel.Xb360AchievementIndex))
            ScrollIntoView("AchievementsList", _vm.Xb360AchievementIndex);
        else if (e.PropertyName == nameof(QuickMenuViewModel.Xb360SelectedFriendIndex))
            ScrollIntoView("FriendsList", _vm.Xb360SelectedFriendIndex);
    }

    private void ScrollIntoView(string name, int index) =>
        Dispatcher.UIThread.Post(() =>
        {
            if (this.FindControl<ItemsControl>(name) is { } list)
                list.ContainerFromIndex(index)?.BringIntoView();
        });
}
