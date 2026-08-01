using Avalonia.Controls;
using GameLauncher.ViewModels;

namespace GameLauncher.Views;

public partial class ControllerConfigWindow : Window
{
    public ControllerConfigWindow()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Opens the window with the given game's controller configuration.
    /// Wires the save / close callbacks and shows the window modally relative
    /// to <paramref name="owner"/>.
    /// </summary>
    public static void OpenFor(
        string platform,
        string gameTitle,
        string author,
        Window owner,
        System.Action<Models.ControllerProfile>? onProfileActivated = null)
    {
        var vm = new ControllerConfigViewModel();
        vm.Load(platform, gameTitle, author);

        var window = new ControllerConfigWindow { DataContext = vm };
        vm.OnProfileActivated = profile =>
        {
            onProfileActivated?.Invoke(profile);
        };
        vm.OnClose = () => window.Close();

        window.ShowDialog(owner);
    }
}
