namespace GameOS.Desktop.ViewModels;

public static class NavigationService
{
    private static System.Action<ViewModelBase>? _navigate;

    public static void Initialize(System.Action<ViewModelBase> navigate) => _navigate = navigate;

    public static void NavigateTo(ViewModelBase vm) => _navigate?.Invoke(vm);
}
