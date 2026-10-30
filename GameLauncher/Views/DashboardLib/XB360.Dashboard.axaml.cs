using System;
using System.ComponentModel;
using Avalonia.Controls;
using GameLauncher.ViewModels;

namespace GameLauncher.Views.DashboardLib;

public partial class Xb360Dashboard : UserControl
{
    private DashboardOptionsVm? _options;

    public Xb360Dashboard()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (_options != null) _options.PropertyChanged -= OnOptionsChanged;
            _options = (DataContext as DashboardViewModel)?.Options;
            if (_options != null) _options.PropertyChanged += OnOptionsChanged;
            EnsureKinetic();
        };
    }

    private void OnOptionsChanged(object? sender, PropertyChangedEventArgs e) => EnsureKinetic();

    // Kinetic is only built when "XB360 Kinetic" is the active dashboard, so a failure there can't take down other designs.
    private void EnsureKinetic()
    {
        if (this.FindControl<ContentControl>("KineticHost") is not { } host) return;
        if (_options?.IsXb360Kinetic != true || host.Content != null) return;
        try { host.Content = new Xb360KineticDashboard(); }
        catch (Exception ex) { Console.Error.WriteLine($"XB360 Kinetic dashboard failed to load: {ex}"); }
    }
}
